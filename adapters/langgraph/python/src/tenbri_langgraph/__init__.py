"""Tenbri for LangGraph and LangChain: every tool call recorded as a decision.

A LangChain callback handler with ``raise_error=True``: before a tool runs, its intent is durable
in the stream, or the tool does not run; after it, the outcome follows (``ok``, ``error``, or
``refused`` when your tool raises :class:`tenbri.Refused`). LangGraph interrupts that a person
answers are recorded with :meth:`TenbriCallbackHandler.resume`: an approved call's intent names the
approval entry that granted it.

    from tenbri import Tenbri
    from tenbri_langgraph import TenbriCallbackHandler

    log = Tenbri.open("./audit/support", create=True)
    tenbri = TenbriCallbackHandler(log, principal="agent:support")
    agent.invoke(inputs, {"callbacks": [tenbri], "configurable": {"thread_id": "t1"}})
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler
from langgraph.errors import GraphBubbleUp
from langgraph.types import Command
from tenbri import Entry, InvalidRequestError, Principal, Refused, Status, Tenbri, TenbriError

__all__ = ["TenbriCallbackHandler"]

log_ = logging.getLogger("tenbri_langgraph")

Input = Mapping[str, str] | tuple[str, str, bytes | str]
"""An input to pin: ``{ref, version, digest}`` as format v1 has it, or ``(ref, version, content)``,
digested with the stream's ``digest_key``."""


def _canon(v: Any) -> bytes:
    # RFC 8785 for what entries hold (strings, integers, objects, arrays, ASCII keys).
    return json.dumps(
        v, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode()


def _hash(e: Entry) -> str:
    """The entry hash (format v1, 6.2). ponytail: recomputed here; the bindings don't return it."""
    return "sha256:" + hashlib.sha256(b"\x00" + _canon(e)).hexdigest()


def _status(e: BaseException) -> Status:
    if isinstance(e, Refused):
        return "refused"
    # A LangGraph interrupt inside the tool pauses it: it runs again from the start on resume, as
    # a new decision, and whatever it did before the interrupt is not known.
    if isinstance(e, GraphBubbleUp) or not isinstance(e, Exception):
        return "unknown"
    return "error"


def _trace() -> dict[str, str] | None:
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    c = trace.get_current_span().get_span_context()
    if not c.is_valid:
        return None
    return {"trace_id": format(c.trace_id, "032x"), "span_id": format(c.span_id, "016x")}


class TenbriCallbackHandler(BaseCallbackHandler):
    """Records each tool call as a decision in ``log``: intent before, outcome after.

    - ``principal``: who acts; default the agent's name (``create_agent(name=...)``), else
      ``agent:langgraph``.
    - ``tools``: which tools to record, by name or as a predicate; default all.
    - ``target``: ``(tool, args) -> str | None``, the reference the call acts on.
    - ``inputs``: ``(tool, args) -> inputs`` to pin to the decision. When the stream was opened
      with a ``digest_key``, the call's arguments are pinned too, as a keyed digest: what the tool
      ran with can be confirmed later without the log holding it. Arguments and results are never
      stored.
    - ``fail_open``: when the intent can't be written, run the tool anyway (logged as a warning)
      instead of failing the call. Off by default: no record, no action.
    """

    raise_error = True

    def __init__(
        self,
        log: Tenbri,
        *,
        principal: Principal | None = None,
        tools: Iterable[str] | Callable[[str], bool] | None = None,
        target: Callable[[str, dict[str, Any]], str | None] | None = None,
        inputs: Callable[[str, dict[str, Any]], Iterable[Input]] | None = None,
        fail_open: bool = False,
    ) -> None:
        self.log = log
        self.principal = principal
        self._tools = tools if tools is None or callable(tools) else frozenset(tools)
        self._target = target
        self._inputs = inputs
        self.fail_open = fail_open
        self._open: dict[UUID, Entry] = {}
        # Tool call id -> the approval entry that granted it, from resume().
        self._approved: dict[str, Entry] = {}

    def _selected(self, tool: str) -> bool:
        t = self._tools
        return t is None or (t(tool) if callable(t) else tool in t)

    def _who(self, metadata: Mapping[str, Any] | None) -> Principal:
        if self.principal is not None:
            return self.principal
        name = (metadata or {}).get("lc_agent_name")
        return f"agent:{name}" if name else "agent:langgraph"

    def _pins(self, tool: str, args: dict[str, Any], call: str | None) -> list[Mapping[str, str]]:
        pins: list[Mapping[str, str]] = []
        for i in self._inputs(tool, args) if self._inputs else ():
            if isinstance(i, tuple):
                ref, version, content = i
                i = {"ref": ref, "version": version, "digest": self.log.digest(content)}
            pins.append(i)
        if call:
            try:
                d = self.log.digest(_canon(args))
            except InvalidRequestError:  # no digest_key
                pass
            else:
                pins.append({"ref": f"langchain:tool_call/{call}", "version": "args", "digest": d})
        return pins

    def _draft(
        self,
        tool: str,
        args: dict[str, Any],
        principal: Principal,
        ext: dict[str, str],
        call: str | None,
    ) -> Entry:
        action = {"type": tool}
        target = self._target(tool, args) if self._target else None
        if target is not None:
            action["target"] = target
        d: Entry = {
            "action": action,
            "principal": principal,
            "ext": {"langchain": {k: v for k, v in ext.items() if v}},
        }
        if pins := self._pins(tool, args, call):
            d["inputs"] = pins
        if trace := _trace():
            d["trace"] = trace
        return d

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        tool = (serialized or {}).get("name") or kwargs.get("name") or "tool"
        if not self._selected(tool):
            return
        args = inputs if inputs is not None else {"input": input_str}
        call: str | None = kwargs.get("tool_call_id")
        ext = {
            "run_id": str(run_id),
            "tool_call_id": call or "",
            "thread_id": str((metadata or {}).get("thread_id") or ""),
        }
        draft = self._draft(tool, args, self._who(metadata), ext, call)
        if call and (a := self._approved.pop(call, None)):
            draft["approval"] = {"by": a["principal"], "entry": _hash(a)}
        try:
            self._open[run_id] = self.log.intent(draft)
        except TenbriError as e:
            if not self.fail_open:
                raise
            log_.warning("tenbri: %s ran unrecorded (fail-open): %s", tool, e)

    def _close(self, run_id: UUID, status: Status) -> None:
        intent = self._open.pop(run_id, None)
        if intent is None:
            return
        try:
            self.log.outcome(intent, status)
        except TenbriError as e:
            # The tool has run: failing it now would only invite a retry. The intent stays open,
            # and the stream's next writer reconciles it as unknown.
            log_.warning("tenbri: outcome of %s not recorded: %s", intent["id"], e)

    def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
        # A ToolMessage with status "error" is an error the tool handled (handle_tool_error).
        self._close(run_id, "error" if getattr(output, "status", None) == "error" else "ok")

    def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
        self._close(run_id, _status(error))

    def approve(
        self,
        tool: str,
        args: Mapping[str, Any] | None = None,
        *,
        by: Principal,
        tool_call_id: str | None = None,
        thread_id: str | None = None,
        checkpoint_id: str | None = None,
    ) -> Entry:
        """Records that ``by`` approved a call of ``tool``: an ``approval`` entry. When that call
        runs (by ``tool_call_id``), its intent names the approval. For interrupts of your own;
        :meth:`resume` calls it for LangChain's ``HumanInTheLoopMiddleware``."""
        ext = {
            "tool_call_id": tool_call_id or "",
            "thread_id": thread_id or "",
            "checkpoint_id": checkpoint_id or "",
        }
        draft = self._draft(tool, dict(args or {}), by, ext, tool_call_id)
        draft["kind"] = "approval"
        entry = self.log.append(draft)
        if tool_call_id:
            self._approved[tool_call_id] = entry
        return entry

    def resume(self, graph: Any, config: Any, resume: Any, *, by: Principal) -> Command[Any]:
        """Records a person's answer to the graph's pending ``HumanInTheLoopMiddleware``
        interrupts, then returns ``Command(resume=resume)`` to invoke the graph with.

        ``approve`` and ``edit`` write an approval entry, named by the call's intent when it
        runs; ``reject`` writes the call's intent and a ``refused`` outcome, since it never runs;
        ``respond`` (the person answers instead of the tool) writes a note. ``resume`` is what you
        would pass to ``Command(resume=...)``: a ``{"decisions": [...]}`` or a single decision,
        or a mapping of interrupt ids to those. Other interrupts are left to :meth:`approve`."""
        snap = graph.get_state(config)
        pending = {i.id: i.value for i in snap.interrupts}
        if isinstance(resume, Mapping) and resume and set(resume) <= set(pending):
            answers = dict(resume)
        elif len(pending) == 1:
            answers = {next(iter(pending)): resume}
        else:
            raise ValueError("several interrupts are pending: key the answers by interrupt id")
        conf = snap.config.get("configurable", {})
        where = {"thread_id": conf.get("thread_id"), "checkpoint_id": conf.get("checkpoint_id")}
        agent = self._who(getattr(graph, "config", None) and graph.config.get("metadata"))
        for iid, answer in answers.items():
            value = pending[iid]
            if not isinstance(value, Mapping):
                continue
            if value.get("type") == "tool_approval":  # per_call mode
                calls = [(value["tool_call_id"], value["name"], value["args"], answer)]
            elif "action_requests" in value:  # batched mode
                ids = _call_ids(snap.values, value["action_requests"])
                calls = [
                    (cid, r["name"], r["args"], d)
                    for cid, r, d in zip(ids, value["action_requests"], answer["decisions"])
                ]
            else:
                continue
            for cid, tool, args, decision in calls:
                self._record(decision, tool, args, by=by, agent=agent, call=cid, **where)
        return Command(resume=resume)

    def _record(
        self,
        decision: Mapping[str, Any],
        tool: str,
        args: dict[str, Any],
        *,
        by: Principal,
        agent: Principal,
        call: str | None,
        thread_id: str | None,
        checkpoint_id: str | None,
    ) -> None:
        kind = decision.get("type")
        if kind in ("approve", "edit"):
            if kind == "edit":
                args = decision["edited_action"].get("args", args)
            self.approve(
                tool, args, by=by, tool_call_id=call, thread_id=thread_id,
                checkpoint_id=checkpoint_id,
            )  # fmt: skip
            return
        ext = {
            "tool_call_id": call or "",
            "thread_id": thread_id or "",
            "checkpoint_id": checkpoint_id or "",
            "decision": str(kind),
            "reviewer": by if isinstance(by, str) else f"{by['kind']}:{by['id']}",
        }
        if kind == "reject":
            intent = self.log.intent(self._draft(tool, args, agent, ext, call))
            self.log.outcome(intent, "refused")
        elif kind == "respond":
            self.log.append({**self._draft(tool, args, by, ext, call), "kind": "note"})


def _call_ids(values: Any, requests: list[Mapping[str, Any]]) -> list[str | None]:
    """The tool call ids of a batched HITL request, from the last AI message: its action requests
    are its gated calls, in order, with the same name and arguments."""
    messages = (values or {}).get("messages") or []
    calls: list[Mapping[str, Any]] = next(
        (m.tool_calls for m in reversed(messages) if getattr(m, "tool_calls", None)), []
    )
    left = list(calls)
    out: list[str | None] = []
    for r in requests:
        m = next((c for c in left if c["name"] == r["name"] and c["args"] == r["args"]), None)
        if m is not None:
            left.remove(m)
        out.append(m["id"] if m else None)
    return out
