"""Tenbri for the OpenAI Agents SDK: every tool call and handoff recorded as a decision.

    import tenbri

    tenbri.init()
    tenbri.instrument_openai_agents()
    # every Runner.run, run_sync and run_streamed from here on is recorded, and so is every
    # RunState.approve and reject

:func:`instrument` is that, with its options. :class:`TenbriRecorder` is the lower level: the run
hooks of one run, on a stream you opened:

    async with TenbriRecorder(log) as recorder:
        result = await Runner.run(agent, "refund ch_123", hooks=recorder,
                                  run_config=recorder.run_config())

The SDK awaits its run hooks, so the intent is durable before the tool runs and a failed write
stops the run before the tool does (fail closed). What is recorded:

- a tool call: an intent by the agent (``action.type`` is the tool's name) right before the tool
  runs, then its outcome, ``ok`` or ``error``;
- a tool call that never ran because a tool input guardrail rejected it or a person rejected it:
  an intent and an outcome ``refused``;
- a handoff: an intent and an outcome ``ok``, action ``handoff``, target ``agent:<name>``;
- a person's approval (:meth:`TenbriRecorder.approve`): an ``approval`` entry, which the tool's
  intent then names in its ``approval`` member.

Tool arguments and results are never written; :meth:`TenbriRecorder.read` and ``inputs=`` pin what
a decision relied on by keyed digest.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import re
from collections.abc import Awaitable, Callable, Collection, Iterable, Mapping
from types import TracebackType
from typing import Any, TypeVar

from agents import Agent, Handoff, RunConfig, RunContextWrapper, RunHooks, Tool, handoff
from agents.lifecycle import RunHooksBase
from agents.exceptions import ToolInputGuardrailTripwireTriggered
from agents.items import ModelResponse, ToolApprovalItem, TResponseInputItem
from agents.run_config import ToolErrorFormatterArgs
from agents.run_state import RunState
from agents.tool import default_tool_error_function
from agents.tool_context import ToolContext
from agents.tracing import get_current_span, get_current_trace
from tenbri import AsyncTenbri, Entry, Principal, Status, TenbriError
from tenbri import _auto as auto

__all__ = ["TenbriRecorder", "instrument", "uninstrument"]

log = logging.getLogger("tenbri.openai_agents")

T = TypeVar("T")

# What the SDK tells the model when a tool raised (and no failure_error_function is set) or timed out.
_DEFAULT_ERROR = default_tool_error_function(RunContextWrapper(None), Exception())
_TIMED_OUT = re.compile(r"Tool '.*' timed out after [0-9.e+-]+ seconds\.")


@dataclasses.dataclass
class _Call:
    agent: Agent[Any]
    name: str
    arguments: str | None


class TenbriRecorder(RunHooks[Any]):
    """Run hooks that record an agent's tool calls and handoffs in a Tenbri stream.

    One recorder per run, or per conversation when a run resumes after approvals: it keeps the
    calls in flight. Pass it as ``hooks=``; pass :meth:`run_config` as ``run_config=`` so a tool
    that raised is recorded as ``error`` (else only the SDK's default error message tells); use it
    as ``async with`` so a run that raises closes its open intents.

    ``tools`` selects the tools recorded (names, or a predicate; default all). ``action`` maps a
    tool name to the action type; ``target`` maps the tool name and parsed arguments to the
    action's target; ``inputs`` maps them to the inputs to pin, each ``{"ref", "version",
    "content"}`` (digested with the stream's ``digest_key``) or ``{"ref", "version", "digest"}``.
    ``subject`` is the pseudonymous handle of the person the run is about. ``describe`` maps the
    tool name and parsed arguments to any of ``action``, ``target``, ``rule`` and ``subject`` at
    once, over the others. ``fail_open`` lets actions run when the stream cannot be written
    (logged, not recorded); the default blocks them.
    """

    def __init__(
        self,
        log: AsyncTenbri,
        *,
        tools: Collection[str] | Callable[[str], bool] | None = None,
        action: Callable[[str], str] | None = None,
        target: Callable[[str, dict[str, Any]], str | None] | None = None,
        inputs: Callable[[str, dict[str, Any]], Iterable[Mapping[str, Any]]] | None = None,
        subject: str | None = None,
        describe: Callable[[str, dict[str, Any]], Mapping[str, Any]] | None = None,
        fail_open: bool = False,
    ) -> None:
        self.log = log
        self._describe = describe
        self._tools = tools
        self._action = action
        self._target = target
        self._inputs = inputs
        self._subject = subject
        self._fail_open = fail_open
        self._reads: list[dict[str, str]] = []
        self._seen: dict[str, _Call] = {}  # asked for by the model, not started yet
        self._open: dict[str, Entry] = {}  # intents waiting for their outcome
        self._failed: set[str] = set()
        self._approvals: dict[str, dict[str, Any]] = {}

    # What the caller adds.

    def read(
        self, ref: str, version: str, content: bytes | str | None = None, *, digest: str | None = None
    ) -> None:
        """Pins ``ref`` at ``version`` to the next decision, by the keyed digest of ``content``
        (or ``digest`` as given)."""
        if content is None and digest is None:
            raise ValueError("read() needs content or digest")
        self._reads.append(self._input({"ref": ref, "version": version, "content": content, "digest": digest}))

    async def approve(
        self, state: RunState[Any], item: ToolApprovalItem, by: Principal, *, always: bool = False
    ) -> None:
        """Approves ``item`` on ``state`` as ``by`` (``"person:alice"``): the approval is recorded
        first, and the tool's intent names it."""
        call = self._call(item)
        if call is not None and item.call_id:
            draft = {"kind": "approval", "principal": by, "action": self._act(call), "subject": self._subject}
            entry = await self._write(self.log.append(self._trace(draft)))
            if entry is not None:
                self._approvals[item.call_id] = {"by": entry["principal"], "entry": _hash(entry)}
        state.approve(item, always_approve=always)

    async def reject(
        self,
        state: RunState[Any],
        item: ToolApprovalItem,
        by: Principal,
        *,
        message: str | None = None,
    ) -> None:
        """Rejects ``item`` on ``state`` as ``by``: recorded as a refused decision whose outcome
        names ``by``."""
        call = self._call(item)
        if call is not None and item.call_id:
            self._seen.pop(item.call_id, None)
            await self._refuse(call, by)
        if message is None:
            state.reject(item)
        else:
            state.reject(item, rejection_message=message)

    def run_config(self, base: RunConfig | None = None) -> RunConfig:
        """``base`` (or a new RunConfig) with a ``tool_error_formatter`` that tells the recorder
        which tool calls raised; ``base``'s own formatter still decides the message."""
        base = base or RunConfig()
        theirs = base.tool_error_formatter

        def formatter(args: ToolErrorFormatterArgs[Any]) -> str | Awaitable[str | None] | None:
            # str(): openai-agents 0.23 has no tool_exception kind, and no way to tell then.
            if str(args.kind) == "tool_exception":
                self._failed.add(args.call_id)
            return theirs(args) if theirs else None

        return dataclasses.replace(base, tool_error_formatter=formatter)

    async def __aenter__(self) -> TenbriRecorder:
        return self

    async def __aexit__(
        self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        if isinstance(e, ToolInputGuardrailTripwireTriggered):
            await self._refuse_unstarted()
        # Raised, so the run is over: an intent still open did not finish.
        status: Status = "error" if isinstance(e, Exception) else "unknown"
        for key in list(self._open):
            await self._close(key, status)

    # The SDK's hooks.

    async def on_llm_end(
        self, context: RunContextWrapper[Any], agent: Agent[Any], response: ModelResponse
    ) -> None:
        handoffs = {h.tool_name if isinstance(h, Handoff) else handoff(h).tool_name for h in agent.handoffs}
        for item in response.output:
            if getattr(item, "type", None) != "function_call":
                continue
            name, call_id = getattr(item, "name", ""), getattr(item, "call_id", "")
            if name not in handoffs and self._selected(name):
                self._seen[call_id] = _Call(agent, name, getattr(item, "arguments", None))

    async def on_llm_start(
        self,
        context: RunContextWrapper[Any],
        agent: Agent[Any],
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        await self._refuse_unstarted()

    async def on_agent_end(self, context: RunContextWrapper[Any], agent: Agent[Any], output: Any) -> None:
        await self._refuse_unstarted()

    async def on_tool_start(self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool) -> None:
        if not self._selected(tool.name):
            return
        key, arguments = _key(context, tool)
        self._seen.pop(key, None)
        draft = self._draft(_Call(agent, tool.name, arguments), key)
        intent = await self._write(self.log.intent(draft))
        if intent is not None:
            self._open[key] = intent

    async def on_tool_end(
        self, context: RunContextWrapper[Any], agent: Agent[Any], tool: Tool, result: object
    ) -> None:
        key, _ = _key(context, tool)
        failed = key in self._failed or result == _DEFAULT_ERROR
        failed = failed or (isinstance(result, str) and _TIMED_OUT.fullmatch(result) is not None)
        self._failed.discard(key)
        await self._close(key, "error" if failed else "ok")

    async def on_handoff(
        self, context: RunContextWrapper[Any], from_agent: Agent[Any], to_agent: Agent[Any]
    ) -> None:
        draft = self._trace(
            {
                "principal": _agent(from_agent),
                "action": {"type": "handoff", "target": f"agent:{to_agent.name}"},
                "subject": self._subject,
            }
        )
        intent = await self._write(self.log.intent(draft))
        if intent is not None:
            await self._write(self.log.outcome(intent, "ok"))

    # The rest.

    def _selected(self, name: str) -> bool:
        if self._tools is None:
            return True
        return self._tools(name) if callable(self._tools) else name in self._tools

    def _call(self, item: ToolApprovalItem) -> _Call | None:
        name = item.name
        if name is None or not self._selected(name) or not isinstance(item.agent, Agent):
            return None
        return _Call(item.agent, name, item.arguments)

    def _fields(self, call: _Call) -> Mapping[str, Any]:
        return self._describe(call.name, _parse(call.arguments)) if self._describe else {}

    def _act(self, call: _Call) -> dict[str, str]:
        fields = self._fields(call)
        action = {"type": fields.get("action") or (self._action(call.name) if self._action else call.name)}
        target = fields.get("target")
        if target is None and self._target:
            target = self._target(call.name, _parse(call.arguments))
        if target:
            action["target"] = target
        return action

    def _draft(self, call: _Call, call_id: str) -> dict[str, Any]:
        """The intent of ``call``, with the reads since the last decision and the mapped inputs."""
        mapped = self._inputs(call.name, _parse(call.arguments)) if self._inputs else ()
        inputs, self._reads = self._reads + [self._input(i) for i in mapped], []
        fields = self._fields(call)
        draft = {
            "principal": _agent(call.agent),
            "action": self._act(call),
            "inputs": inputs or None,
            "rule": fields.get("rule"),
            "subject": fields.get("subject") or self._subject,
            "approval": self._approvals.pop(call_id, None),
        }
        return self._trace(draft)

    def _input(self, i: Mapping[str, Any]) -> dict[str, str]:
        digest = i.get("digest") or self.log.digest(i["content"])
        return {"ref": i["ref"], "version": i["version"], "digest": digest}

    def _trace(self, draft: dict[str, Any]) -> dict[str, Any]:
        """``draft`` with the SDK's current trace and span, when the SDK is tracing."""
        trace, span = get_current_trace(), get_current_span()
        trace_id = trace.trace_id.removeprefix("trace_") if trace else ""
        # ponytail: the SDK's span ids have 24 hex digits, the format's 16; the first 16 still find
        # the span in a trace. An OpenTelemetry span, when there is one, would fit exactly.
        span_id = span.span_id.removeprefix("span_")[:16] if span else ""
        if _hex(trace_id, 32) and _hex(span_id, 16):
            draft["trace"] = {"trace_id": trace_id, "span_id": span_id}
        return {k: v for k, v in draft.items() if v is not None}

    async def _refuse(self, call: _Call, by: Principal | None = None) -> None:
        intent = await self._write(self.log.intent(self._draft(call, "")))
        if intent is not None:
            await self._write(self.log.outcome(intent, "refused", principal=by))

    async def _refuse_unstarted(self) -> None:
        """The calls the model asked for that never started: a guardrail or a person refused them."""
        seen, self._seen = self._seen, {}
        for call in seen.values():
            await self._refuse(call)

    async def _close(self, key: str, status: Status) -> None:
        intent = self._open.pop(key, None)
        if intent is not None:
            await self._write(self.log.outcome(intent, status))

    async def _write(self, append: Awaitable[T]) -> T | None:
        try:
            return await append
        except TenbriError as e:
            if not self._fail_open:
                raise
            log.warning("tenbri: not recorded, the action goes ahead (fail_open): %s", e)
            return None


def _key(context: RunContextWrapper[Any], tool: Tool) -> tuple[str, str | None]:
    """A tool call's id and arguments; tools that are not function tools have neither."""
    if isinstance(context, ToolContext):
        return context.tool_call_id, context.tool_arguments
    # ponytail: one call at a time per non-function tool (computer, shell); their hooks carry no id.
    return f"tool:{id(tool)}", None


def _agent(agent: Agent[Any]) -> dict[str, str]:
    return {"kind": "agent", "id": agent.name}


def _parse(arguments: str | None) -> dict[str, Any]:
    try:
        args = json.loads(arguments or "{}")
    except ValueError:
        return {}
    return args if isinstance(args, dict) else {}


def _hex(s: str, n: int) -> bool:
    return len(s) == n and all(c in "0123456789abcdef" for c in s) and s != "0" * n


def _hash(entry: Entry) -> str:
    """The entry hash (format v1, 6.2): SHA-256 of 0x00 and the stored line."""
    # ponytail: the bindings return the entry parsed, not its stored line, so the line is rebuilt.
    # Sorted keys and no spaces are RFC 8785 for what entries hold (ASCII keys, strings, integers).
    # An entry_hash from the bindings would remove this.
    line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(b"\x00" + line.encode()).hexdigest()


class _Both(RunHooksBase[Any, Any]):
    """Run hooks that call the recorder's, then the caller's."""

    def __init__(self, *hooks: RunHooksBase[Any, Any]) -> None:
        self.hooks = hooks


def _fan_out(name: str) -> Callable[..., Awaitable[None]]:
    async def hook(self: _Both, *args: Any, **kwargs: Any) -> None:
        for h in self.hooks:
            await getattr(h, name)(*args, **kwargs)

    return hook


for _name in [n for n in dir(RunHooksBase) if n.startswith("on_")]:
    setattr(_Both, _name, _fan_out(_name))

_originals: dict[str, Any] = {}
# Tool call id -> the approval entry that granted it, from RunState.approve, for the run resuming.
_approved: dict[str, dict[str, Any]] = {}


def instrument(
    *,
    actions: auto.Actions | None = None,
    approver: Principal | Callable[[ToolApprovalItem], Principal | None] | None = None,
    tools: Collection[str] | Callable[[str], bool] | None = None,
    subject: str | None = None,
    fail_open: bool | None = None,
) -> None:
    """Records every run from now on, ``Runner.run``, ``run_sync`` and ``run_streamed``, on the
    stream ``tenbri.init()`` opened (``tenbri.instrument_openai_agents()`` calls this), and every
    ``RunState.approve`` and ``reject``.

    Each tool call is by ``agent:<the agent's name>``, the action of the tool's name or of the
    action schema in tenbri.toml of that name: the schema's ``target`` (``stripe:{charge}``) is
    filled from the call's arguments and its ``policy`` is the rule. ``actions`` overrides that
    per tool name: ``{"issue_refund": {"target": "stripe:{charge}", "policy":
    "policy:refund@14"}}``.

    ``approver`` is who answers an interruption (a principal, or a function of the
    ``ToolApprovalItem``); default ``init(approver=...)`` or ``TENBRI_APPROVER``. ``tools``,
    ``subject`` and ``fail_open`` are :class:`TenbriRecorder`'s; ``fail_open`` defaults to
    ``init()``'s."""
    from agents.run import AgentRunner

    uninstrument()

    def recorder() -> TenbriRecorder:
        d = auto.default()
        r = TenbriRecorder(
            d.aio,
            tools=tools,
            describe=lambda tool, args: auto.describe(tool, args, actions),
            subject=subject,
            fail_open=d.fail_open if fail_open is None else fail_open,
        )
        r._approvals = _approved
        return r

    def hooked(r: TenbriRecorder, kwargs: dict[str, Any]) -> dict[str, Any]:
        theirs = kwargs.get("hooks")
        return {**kwargs, "hooks": _Both(r, theirs) if theirs else r, "run_config": r.run_config(kwargs.get("run_config"))}

    run = _originals["run"] = AgentRunner.run
    run_streamed = _originals["run_streamed"] = AgentRunner.run_streamed
    approve = _originals["approve"] = RunState.approve
    reject = _originals["reject"] = RunState.reject

    async def instrumented_run(self: Any, starting_agent: Any, input: Any, **kwargs: Any) -> Any:
        async with recorder() as r:
            return await run(self, starting_agent, input, **hooked(r, kwargs))

    def instrumented_run_streamed(self: Any, starting_agent: Any, input: Any, **kwargs: Any) -> Any:
        # ponytail: an intent a streamed run leaves open when it raises is reconciled as unknown by
        # the stream's next writer, rather than closed here.
        return run_streamed(self, starting_agent, input, **hooked(recorder(), kwargs))

    def answer(item: ToolApprovalItem, approved: bool) -> None:
        """Records a person's answer before the SDK takes it: an approval, or a refused decision."""
        d, r = auto.default(), recorder()
        call = r._call(item)
        if call is None or not item.call_id:
            return
        by = auto.approver(approver, item)
        try:
            if not approved:
                d.outcome(d.intent(r._draft(call, "")), "refused", principal=by)
            elif by is None:
                log.warning("tenbri: %s approved, by nobody known: set TENBRI_APPROVER", item.call_id)
            else:
                draft = {"kind": "approval", "principal": by, "action": r._act(call), "subject": subject}
                entry = d.append(r._trace(draft))
                _approved[item.call_id] = {"by": entry["principal"], "entry": _hash(entry)}
        except TenbriError as e:
            if not r._fail_open:
                raise
            log.warning("tenbri: not recorded, the answer goes ahead (fail_open): %s", e)

    def instrumented_approve(self: RunState[Any], item: ToolApprovalItem, *args: Any, **kwargs: Any) -> None:
        answer(item, True)
        approve(self, item, *args, **kwargs)

    def instrumented_reject(self: RunState[Any], item: ToolApprovalItem, *args: Any, **kwargs: Any) -> None:
        answer(item, False)
        reject(self, item, *args, **kwargs)

    AgentRunner.run = instrumented_run  # type: ignore[method-assign]
    AgentRunner.run_streamed = instrumented_run_streamed  # type: ignore[method-assign]
    RunState.approve = instrumented_approve  # type: ignore[method-assign,assignment]
    RunState.reject = instrumented_reject  # type: ignore[method-assign,assignment]


def uninstrument() -> None:
    """Stops recording runs started and answers given from now on."""
    from agents.run import AgentRunner

    if "run" in _originals:
        AgentRunner.run = _originals.pop("run")  # type: ignore[method-assign]
        AgentRunner.run_streamed = _originals.pop("run_streamed")  # type: ignore[method-assign]
        RunState.approve = _originals.pop("approve")  # type: ignore[method-assign]
        RunState.reject = _originals.pop("reject")  # type: ignore[method-assign]
