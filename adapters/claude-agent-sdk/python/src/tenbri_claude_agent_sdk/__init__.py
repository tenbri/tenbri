"""Tenbri for the Claude Agent SDK: every tool call the agent makes is a signed decision.

Before a tool runs, its intent is durable in the stream; after, its outcome follows (``ok``,
``error``, ``refused``, or ``unknown`` when interrupted). A tool approved through the SDK's
``can_use_tool`` is recorded as an ``approval`` entry, which the outcome names.

    from claude_agent_sdk import ClaudeAgentOptions, query
    from tenbri import AsyncTenbri
    from tenbri_claude_agent_sdk import TenbriHooks

    log = await AsyncTenbri.open("./audit/support", create=True)
    options = TenbriHooks(log, "agent:support").instrument(ClaudeAgentOptions(...))
    async for message in query(prompt="...", options=options):
        ...
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any, Union, cast

from claude_agent_sdk import (
    ClaudeAgentOptions,
    HookContext,
    HookMatcher,
    PermissionResult,
    PermissionResultDeny,
    ToolPermissionContext,
)
from tenbri import AsyncTenbri, Entry, InvalidRequestError, Principal, Status

try:
    from opentelemetry import trace as _otel
except ImportError:  # OpenTelemetry is optional: without it, entries carry no trace.
    _otel = None  # type: ignore[assignment]

__all__ = ["TenbriHooks", "default_describe", "entry_hash"]

_log = logging.getLogger(__name__)

Describe = Callable[[str, dict[str, Any]], Union[Mapping[str, Any], None]]
"""``(tool_name, tool_input)`` to the fields of the intent: ``target``, ``inputs``, ``rule``,
``subject``, or ``action`` to rename the action. ``None`` records the tool with no extra fields."""

Approver = Union[
    Principal, Callable[[str, dict[str, Any], ToolPermissionContext], Union[Principal, None]]
]
CanUseTool = Callable[[str, dict[str, Any], ToolPermissionContext], Awaitable[PermissionResult]]

_TARGETS = ("file_path", "notebook_path", "path", "url")


def default_describe(tool: str, tool_input: dict[str, Any]) -> Mapping[str, Any] | None:
    """The target of the built-in file and web tools (``file_path``, ``path``, ``url``...);
    nothing else. Commands, prompts and contents stay out of the log."""
    for k in _TARGETS:
        v = tool_input.get(k)
        if isinstance(v, str) and v:
            return {"target": v}
    return None


def _canonical(value: Any) -> bytes:
    # RFC 8785 for what an entry holds (objects, strings, integers): sorted keys, no whitespace,
    # UTF-8, the same escapes. Entry keys are ASCII, so code point order is UTF-16 order.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entry_hash(entry: Mapping[str, Any]) -> str:
    """The entry hash of an entry as stored (what ``approval.entry`` names): SHA-256 of ``0x00``
    and its canonical bytes."""
    return "sha256:" + hashlib.sha256(b"\x00" + _canonical(entry)).hexdigest()


def _trace() -> dict[str, str] | None:
    if _otel is None:
        return None
    c = _otel.get_current_span().get_span_context()
    if not c.is_valid:
        return None
    return {"trace_id": format(c.trace_id, "032x"), "span_id": format(c.span_id, "016x")}


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


class TenbriHooks:
    """Records the tool calls of a Claude Agent SDK session in a Tenbri stream.

    ``principal`` is the agent (``"agent:support"``). ``tools`` selects the tools to record: names,
    or a predicate of the name; all by default. ``describe`` maps a tool call to the intent's
    fields (:data:`Describe`); the default records the target of file and web tools. When the
    stream was opened with a ``digest_key``, each intent also pins the tool input by its keyed
    digest (``claude:tool_input@<tool_use_id>``); the input itself is never stored.

    ``approver`` is who approves through ``can_use_tool``: a principal (``"person:alice"``), or a
    function of ``(tool_name, tool_input, context)`` returning one, or ``None`` when no person
    approved (your own policy decided). Each approval is an ``approval`` entry.

    Fail closed by default: if the intent is not durable within ``timeout`` seconds, the tool is
    denied. With ``fail_open=True`` the tool runs anyway, unrecorded, and a warning is logged.
    """

    def __init__(
        self,
        log: AsyncTenbri,
        principal: Principal,
        *,
        tools: Iterable[str] | Callable[[str], bool] | None = None,
        describe: Describe = default_describe,
        approver: Approver | None = None,
        fail_open: bool = False,
        timeout: float = 2.0,
    ) -> None:
        self._log = log
        self._principal = principal
        if tools is None or callable(tools):
            self._selected: Callable[[str], bool] = tools or (lambda _: True)
        else:
            names = frozenset(tools)
            self._selected = names.__contains__
        self._describe = describe
        self._approver = approver
        self._fail_open = fail_open
        self._timeout = timeout
        self._open: dict[str, Entry] = {}
        self._approvals: dict[str, dict[str, Any]] = {}

    def instrument(self, options: ClaudeAgentOptions) -> ClaudeAgentOptions:
        """``options`` with Tenbri's hooks added to its own, and its ``can_use_tool`` (if any)
        wrapped to record approvals and refusals."""
        hooks: dict[Any, list[HookMatcher]] = {k: list(v) for k, v in (options.hooks or {}).items()}
        for event, fn in (
            ("PreToolUse", self._pre),
            ("PostToolUse", self._post),
            ("PostToolUseFailure", self._failure),
            ("PermissionDenied", self._denied),
        ):
            hooks.setdefault(event, []).append(HookMatcher(hooks=[fn]))
        can_use_tool = options.can_use_tool and self.can_use_tool(options.can_use_tool)
        return dataclasses.replace(options, hooks=hooks, can_use_tool=can_use_tool)

    def can_use_tool(self, fn: CanUseTool) -> CanUseTool:
        """Wraps a ``can_use_tool`` callback: a denial is the call's ``refused`` outcome, an
        allowance by an ``approver`` an ``approval`` entry."""

        async def wrapped(
            tool: str, tool_input: dict[str, Any], ctx: ToolPermissionContext
        ) -> PermissionResult:
            result = await fn(tool, tool_input, ctx)
            tid = ctx.tool_use_id
            intent = self._open.get(tid or "")
            if tid is None or intent is None:
                return result
            if isinstance(result, PermissionResultDeny):
                await self._close(tid, "refused")
                return result
            by = self._approver(tool, tool_input, ctx) if callable(self._approver) else self._approver
            if by is None:
                return result
            try:
                draft = {"kind": "approval", "principal": by, "action": intent["action"]}
                entry = await asyncio.wait_for(self._log.append(_traced(draft)), self._timeout)
            except Exception as e:
                if self._fail_open:
                    _log.warning("tenbri: approval of %s not recorded: %s", tid, e)
                    return result
                await self._close(tid, "refused")
                return PermissionResultDeny(message=f"Tenbri could not record the approval: {e}")
            self._approvals[tid] = {"by": entry["principal"], "entry": entry_hash(entry)}
            return result

        return wrapped

    def _draft(self, tool: str, tool_input: dict[str, Any], tid: str) -> dict[str, Any]:
        fields = dict(self._describe(tool, tool_input) or {})
        action = {"type": fields.pop("action", tool)}
        if (target := fields.pop("target", None)) is not None:
            action["target"] = target
        inputs = list(fields.pop("inputs", []))
        try:
            digest = self._log.digest(_canonical(tool_input))
            inputs.append({"ref": "claude:tool_input", "version": tid, "digest": digest})
        except InvalidRequestError:
            pass  # no digest_key at open: nothing to pin with
        draft = {**fields, "action": action, "principal": self._principal}
        if inputs:
            draft["inputs"] = inputs
        return _traced(draft)

    async def _pre(self, data: Any, tool_use_id: str | None, _: HookContext) -> Any:
        tool: str = data["tool_name"]
        tid: str = data.get("tool_use_id") or tool_use_id or ""
        if not self._selected(tool):
            return {}
        try:
            draft = self._draft(tool, data["tool_input"], tid)
            self._open[tid] = await asyncio.wait_for(self._log.intent(draft), self._timeout)
        except Exception as e:
            if self._fail_open:
                _log.warning("tenbri: %s runs unrecorded (fail-open): %s", tool, e)
                return {}
            return _deny(f"Tenbri could not record the intent, so {tool} is blocked: {e}")
        return {}

    async def _post(self, data: Any, tool_use_id: str | None, _: HookContext) -> Any:
        await self._close(data.get("tool_use_id") or tool_use_id, "ok")
        return {}

    async def _failure(self, data: Any, tool_use_id: str | None, _: HookContext) -> Any:
        # Interrupted: whether the action ran is not known.
        status: Status = "unknown" if data.get("is_interrupt") else "error"
        await self._close(data.get("tool_use_id") or tool_use_id, status)
        return {}

    async def _denied(self, data: Any, tool_use_id: str | None, _: HookContext) -> Any:
        await self._close(data.get("tool_use_id") or tool_use_id, "refused")
        return {}

    async def _close(self, tid: str | None, status: Status) -> None:
        intent = self._open.pop(tid or "", None)
        if intent is None:
            return
        fields = _traced({})
        if (approval := self._approvals.pop(cast(str, tid), None)) is not None:
            fields["approval"] = approval
        try:
            await self._log.outcome(intent, status, **fields)
        except Exception:
            # The action already ran; the open intent is reconciled as unknown later.
            _log.exception("tenbri: the %s outcome of %s was not recorded", status, tid)


def _traced(draft: dict[str, Any]) -> dict[str, Any]:
    if (t := _trace()) is not None:
        draft["trace"] = t
    return draft
