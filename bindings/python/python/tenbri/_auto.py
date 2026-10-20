"""The process-wide default stream and what is built on it: ``init()``, ``agent()``, the
``@decision`` decorator and the one-line framework instrumentation, the way tracing SDKs work.

Explicit arguments win over environment variables:

- ``TENBRI_STREAM``: the stream, a directory or ``s3://bucket/prefix`` (``r2://`` too);
- ``TENBRI_KEYS``: the keys directory, apart from the stream (default ``~/.config/tenbri/keys``);
- ``TENBRI_AGENT``: who acts when nothing narrower says (``agent:support``);
- ``TENBRI_APPROVER``: who answers the frameworks' approval prompts (``person:alice``);
- ``TENBRI_SCHEMA``: the action schemas (default ``./tenbri.toml`` when there is one).
"""

from __future__ import annotations

import atexit
import contextlib
import functools
import importlib
import inspect
import json
import logging
import os
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextvars import ContextVar
from types import ModuleType
from typing import Any, TypeVar

from . import (
    AsyncTenbri,
    Entry,
    InvalidRequestError,
    Principal,
    Status,
    Tenbri,
    TenbriError,
    _native,
    _principal,
    _status,
)

_log = logging.getLogger("tenbri")

F = TypeVar("F", bound=Callable[..., Any])

Pin = Mapping[str, Any] | tuple[str, str, bytes | str]
"""An input to pin: ``(ref, version, content)``, digested with the stream's digest key, or
``{"ref", "version", "digest"}`` as format v1 has it."""

Actions = Mapping[str, Mapping[str, Any]]
"""Per tool name (or its last ``__`` part, which is then the action type): ``action`` (the type), ``target`` and ``subject`` (templates of the tool's
arguments, ``"stripe:{charge}"``, or functions of them) and ``policy`` (``"policy:refund@14"``)."""


class Default(Tenbri):
    """The stream :func:`init` opened: a :class:`Tenbri` (``.aio`` is the same stream as an
    :class:`AsyncTenbri`), with the principal, approver, action schemas and failure mode the
    rest of the process uses. ``with tenbri.init(...):`` closes it at the end of the block."""

    aio: AsyncTenbri
    agent: Principal | None
    approver: Principal | None
    actions: dict[str, dict[str, Any]]
    fail_open: bool

    def close(self) -> None:
        """Flushes and closes the stream; it stops being the default."""
        global _current
        if _current is self:
            _current = None
        super().close()

    def __enter__(self) -> Default:
        return self


_current: Default | None = None
_agent: ContextVar[dict[str, str] | None] = ContextVar("tenbri_agent", default=None)


def _env(value: Any, name: str) -> Any:
    return value if value is not None else os.environ.get(name) or None


def init(
    stream: str | os.PathLike[str] | None = None,
    *,
    keys: str | os.PathLike[str] | None = None,
    agent: Principal | None = None,
    approver: Principal | None = None,
    schema: str | os.PathLike[str] | None = None,
    key: str | None = None,
    digest_key: bytes | None = None,
    fail_open: bool = False,
) -> Default:
    """Opens the process's default stream, creating it and its keys if there is none, and closes
    it (flushing) at exit. Each argument defaults to its ``TENBRI_*`` variable (see the module).

    ``agent`` is the principal of decisions nothing narrower names; ``approver`` who answers the
    frameworks' approval prompts. Input digests are keyed by the local key store unless
    ``digest_key`` is given. ``fail_open`` lets actions run, unrecorded and with a warning, when
    their intent cannot be written; by default they are blocked. Calling it again replaces the
    default."""
    global _current
    location = _env(stream, "TENBRI_STREAM")
    if location is None:
        raise InvalidRequestError(
            "no stream: pass tenbri.init(stream) or set TENBRI_STREAM to a directory or "
            "s3://bucket/prefix"
        )
    path = _env(schema, "TENBRI_SCHEMA")
    if path is None and os.path.exists("tenbri.toml"):
        path = "tenbri.toml"
    actions = json.loads(_native.schemas(os.fspath(path)))["actions"] if path else {}
    keys = _env(keys, "TENBRI_KEYS")
    if _current is not None:
        _current.close()  # first: it may hold the same stream's writer
    s = _native.Stream.open(os.fspath(location), None if keys is None else os.fspath(keys), key, True)
    d = Default(s, digest_key)
    d.aio = AsyncTenbri(s, digest_key)
    d.agent = _env(agent, "TENBRI_AGENT")
    d.approver = _env(approver, "TENBRI_APPROVER")
    d.actions = actions
    d.fail_open = fail_open
    _current = d
    return d


@atexit.register
def _close_at_exit() -> None:
    if _current is not None:
        _current.close()


def default() -> Default:
    """The stream :func:`init` opened; raises :class:`InvalidRequestError` before."""
    if _current is None:
        raise InvalidRequestError("Tenbri is not initialized: call tenbri.init() first")
    return _current


@contextlib.contextmanager
def agent(principal: Principal) -> Iterator[None]:
    """``with tenbri.agent("agent:support"):`` decisions in the block, and in the tasks and
    threads it starts with its context, are by ``principal``."""
    token = _agent.set(_principal(principal))
    try:
        yield
    finally:
        _agent.reset(token)


def who(explicit: Principal | None = None) -> dict[str, str]:
    """Who acts: ``explicit``, else the innermost :func:`agent`, else ``init(agent=...)`` or
    ``TENBRI_AGENT``."""
    p = explicit if explicit is not None else _agent.get()
    if p is None:
        p = default().agent
    if p is None:
        raise InvalidRequestError(
            "no principal: pass agent= to tenbri.init(), set TENBRI_AGENT, or use "
            'with tenbri.agent("agent:...")'
        )
    return _principal(p)


_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


def fill(template: str, args: Mapping[str, Any]) -> str:
    """``template`` with each ``{name}`` (or ``{name.key}``) replaced by that argument."""

    def one(m: re.Match[str]) -> str:
        v: Any = args
        for k in m.group(1).split("."):
            v = v[k] if isinstance(v, Mapping) else getattr(v, k)
        return str(v)

    try:
        return _PLACEHOLDER.sub(one, template)
    except (KeyError, AttributeError, TypeError) as e:
        raise InvalidRequestError(f"{template!r}: no argument {e}") from None


def rule(policy: str) -> dict[str, str]:
    """``"policy:refund@14"`` as the rule that allowed the action."""
    ref, sep, version = policy.rpartition("@")
    if not (sep and ref and version):
        raise InvalidRequestError(f"policy {policy!r}: expected ref@version")
    return {"ref": ref, "version": version, "result": "allow"}


def _match(tool: str, specs: Mapping[str, Any]) -> tuple[str, Mapping[str, Any]] | None:
    """The spec for ``tool``: the one of its name, or of its last ``__`` part
    (``mcp__billing__issue_refund`` is ``issue_refund``)."""
    for name in (tool, tool.rpartition("__")[2]):
        if name in specs:
            return name, specs[name]
    return None


def describe(
    tool: str, args: Mapping[str, Any], actions: Actions | None = None
) -> dict[str, Any]:
    """The intent fields of a tool call: ``action`` (the type), ``target``, ``rule`` and
    ``subject``, from ``actions`` over the default stream's action schemas (tenbri.toml), each
    matched by the tool's name or its last ``__`` part, which is then the action type. A schema
    whose ``target`` names arguments (``stripe:{charge}``) is filled from the call, and its
    ``policy`` is the rule. Empty when neither says anything about the tool."""
    spec: dict[str, Any] = {}
    if (found := _match(tool, _current.actions if _current else {})) is not None:
        name, s = found
        spec["action"] = name
        if "{" in (t := s.get("target") or "*") and "*" not in t:
            spec["target"] = t
        if s.get("policy"):
            spec["policy"] = s["policy"]
    if (found := _match(tool, actions or {})) is not None:
        spec["action"] = found[0]
        spec.update(found[1])
    out: dict[str, Any] = {}
    if spec.get("action", tool) != tool:
        out["action"] = spec["action"]
    for k in ("target", "subject"):
        v = spec.get(k)
        if v is not None:
            out[k] = v(args) if callable(v) else fill(v, args)
    if spec.get("policy"):
        out["rule"] = rule(spec["policy"])
    return out


def _pins(log: Tenbri | AsyncTenbri, pins: Iterable[Pin], subject: str | None) -> list[dict[str, str]]:
    out = []
    for p in pins:
        if isinstance(p, tuple):
            ref, version, content = p
            p = {"ref": ref, "version": version, "digest": log.digest(content, subject=subject)}
        elif "digest" not in p:
            p = {**p, "digest": log.digest(p["content"], subject=subject)}
            del p["content"]
        out.append(dict(p))
    return out


def trace() -> dict[str, str] | None:
    """The active OpenTelemetry span, when OpenTelemetry is installed and tracing."""
    try:
        # Optional, and untyped here: mypy checks this package with or without it installed.
        otel: Any = importlib.import_module("opentelemetry.trace")
    except ImportError:
        return None
    c = otel.get_current_span().get_span_context()
    if not c.is_valid:
        return None
    return {"trace_id": format(c.trace_id, "032x"), "span_id": format(c.span_id, "016x")}


def _warn_open(what: str, e: Exception) -> None:
    _log.warning("tenbri: %s runs unrecorded (fail-open): %s", what, e)


def decision(
    action: str,
    target: str | Callable[..., str] | None = None,
    *,
    policy: str | None = None,
    inputs: Iterable[Pin] | Callable[..., Iterable[Pin]] | None = None,
    subject: str | Callable[..., str] | None = None,
    principal: Principal | None = None,
    fail_open: bool | None = None,
    **fields: Any,
) -> Callable[[F], F]:
    """Records each call of the decorated function, sync or async, as a decision on the default
    stream: the intent is durable before the function runs, the outcome follows: ``ok``,
    ``refused`` when it raises :class:`tenbri.Refused`, ``error`` for any other exception (which
    propagates), ``unknown`` when cancelled.

    ``target`` and ``subject`` are templates of the function's arguments (``"stripe:{charge}"``,
    ``"{order.id}"``) or functions of them. ``policy`` (``"policy:refund@14"``) is the rule that
    allowed it. ``inputs`` pins what the decision relied on: ``(ref, version, content)`` tuples,
    or a function of the arguments returning them. ``principal`` defaults to :func:`who`.

    If the intent cannot be written the function does not run (fail closed), unless
    ``fail_open`` (default: ``init(fail_open=...)``) lets it run unrecorded, with a warning."""

    def wrap(fn: F) -> F:
        sig = inspect.signature(fn)

        def draft(log: Tenbri | AsyncTenbri, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Entry:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            a = bound.arguments

            def value(v: Any) -> Any:
                return v(*args, **kwargs) if callable(v) else None if v is None else fill(v, a)

            d: Entry = {**fields, "action": {"type": action}, "principal": who(principal)}
            if (t := value(target)) is not None:
                d["action"]["target"] = t
            if (s := value(subject)) is not None:
                d["subject"] = s
            if policy is not None:
                d["rule"] = rule(policy)
            pins = inputs(*args, **kwargs) if callable(inputs) else inputs or ()
            if pinned := _pins(log, pins, d.get("subject")):
                d["inputs"] = pinned
            if (tr := trace()) is not None:
                d.setdefault("trace", tr)
            return d

        def failing_open(e: TenbriError) -> bool:
            open_ = fail_open if fail_open is not None else bool(_current and _current.fail_open)
            if not open_:
                return False
            _warn_open(fn.__qualname__, e)
            return True

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def run_async(*args: Any, **kwargs: Any) -> Any:
                try:
                    log = default().aio
                    intent = await log.intent(draft(log, args, kwargs))
                except TenbriError as e:
                    if not failing_open(e):
                        raise
                    return await fn(*args, **kwargs)
                try:
                    result = await fn(*args, **kwargs)
                except BaseException as e:
                    await _outcome_async(log, intent, _status(e))
                    raise
                await _outcome_async(log, intent, "ok")
                return result

            return run_async  # type: ignore[return-value]

        @functools.wraps(fn)
        def run(*args: Any, **kwargs: Any) -> Any:
            try:
                log = default()
                intent = log.intent(draft(log, args, kwargs))
            except TenbriError as e:
                if not failing_open(e):
                    raise
                return fn(*args, **kwargs)
            try:
                result = fn(*args, **kwargs)
            except BaseException as e:
                _outcome(log, intent, _status(e))
                raise
            _outcome(log, intent, "ok")
            return result

        return run  # type: ignore[return-value]

    return wrap


# The action ran: failing the call now would only invite a retry. An outcome that could not be
# written leaves the intent open, and the stream's next writer reconciles it as unknown.
def _outcome(log: Tenbri, intent: Entry, status: Status) -> None:
    try:
        log.outcome(intent, status)
    except TenbriError as e:
        _log.warning("tenbri: the %s outcome of %s was not recorded: %s", status, intent["id"], e)


async def _outcome_async(log: AsyncTenbri, intent: Entry, status: Status) -> None:
    try:
        await log.outcome(intent, status)
    except TenbriError as e:
        _log.warning("tenbri: the %s outcome of %s was not recorded: %s", status, intent["id"], e)


def _adapter(module: str, package: str) -> ModuleType:
    try:
        return importlib.import_module(module)
    except ImportError as e:
        raise ImportError(f"{e}: pip install --pre {package}") from e


def instrument_claude_agent_sdk(**options: Any) -> None:
    """Records every tool call of every Claude Agent SDK session (``query()`` and
    ``ClaudeSDKClient``) on the default stream, approvals through ``can_use_tool`` included. See
    ``tenbri_claude_agent_sdk.instrument`` for the options."""
    _adapter("tenbri_claude_agent_sdk", "tenbri-claude-agent-sdk").instrument(**options)


def instrument_openai_agents(**options: Any) -> None:
    """Records every tool call, handoff and approval of every OpenAI Agents SDK run on the
    default stream. See ``tenbri_openai_agents.instrument`` for the options."""
    _adapter("tenbri_openai_agents", "tenbri-openai-agents").instrument(**options)


def instrument_langchain(**options: Any) -> None:
    """Records every LangChain and LangGraph tool call on the default stream, and the answers to
    ``HumanInTheLoopMiddleware`` interrupts. See ``tenbri_langgraph.instrument`` for the
    options."""
    _adapter("tenbri_langgraph", "tenbri-langgraph").instrument(**options)


def approver(
    configured: Principal | Callable[..., Principal | None] | None, *args: Any
) -> Principal | None:
    """Who approved: ``configured`` (a principal, or a function of the framework's call),
    else ``init(approver=...)`` or ``TENBRI_APPROVER``."""
    if callable(configured):
        return configured(*args)
    if configured is not None:
        return configured
    return _current.approver if _current else os.environ.get("TENBRI_APPROVER") or None
