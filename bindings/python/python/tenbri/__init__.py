"""The open-source Agent Decision Record: every decision signed, chained and provable.

    import tenbri

    tenbri.init()  # TENBRI_STREAM, TENBRI_AGENT; the stream and its keys are made on first use

    @tenbri.decision("issue_refund", target="stripe:{charge}", policy="policy:refund@14")
    def refund(charge: str, amount: int) -> None: ...

    tenbri.instrument_claude_agent_sdk()  # or instrument_openai_agents(), instrument_langchain()

The rest of this module is the lower level those are built on: open a stream yourself, and record
runs and decisions on it.

``Tenbri`` blocks; ``AsyncTenbri`` never blocks the event loop. Both write through the same Rust
core as the ``tenbri`` CLI and tenbrid: an intent is durable before the action runs, every intent
ends in an outcome, and anyone holding the stream key's fingerprint can verify the record offline.

    from tenbri import Tenbri

    with Tenbri.open("./audit/support", create=True) as log:
        with log.run("agent:support-assistant") as run:
            with run.decision("issue_refund", "stripe:ch_123"):
                refund()
        print(log.verify(log.fingerprint).ok)
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import inspect
import json
import os
from dataclasses import dataclass
from types import TracebackType
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Literal, TypeVar, Union

from . import _native
from .errors import (
    DeadlineExceededError,
    IdempotencyConflictError,
    InvalidEntryError,
    InvalidRequestError,
    NoSessionKeyError,
    NotFoundError,
    StoreUnavailableError,
    StreamBrokenError,
    TenbriError,
    WriteConflictError,
)

__version__: str = _native.__version__

__all__ = [
    "AsyncDecision",
    "Default",
    "AsyncRun",
    "AsyncTenbri",
    "Broken",
    "Decision",
    "DeadlineExceededError",
    "Entry",
    "IdempotencyConflictError",
    "InvalidEntryError",
    "InvalidRequestError",
    "Match",
    "NoSessionKeyError",
    "NotFoundError",
    "Principal",
    "Refused",
    "Run",
    "Status",
    "StoreUnavailableError",
    "StreamBrokenError",
    "Tenbri",
    "TenbriError",
    "VerifyReport",
    "WriteConflictError",
    "agent",
    "decision",
    "default",
    "describe",
    "init",
    "instrument_claude_agent_sdk",
    "instrument_langchain",
    "instrument_openai_agents",
    "new_id",
]

Entry = dict[str, Any]
"""An entry as stored (format v1), or a draft of one."""

Principal = Union[str, Mapping[str, str]]
"""Who acts: ``{"kind": "agent", "id": "support"}``, ``"agent:support"``, or ``"support"`` (an
agent). The kinds are ``agent``, ``person`` and ``service``."""

Status = Literal["ok", "error", "refused", "unknown"]

F = TypeVar("F", bound=Callable[..., Any])


def new_id() -> str:
    """A new entry id (ULID). Pass it as ``id=`` to make an append safe to retry: the same entry
    again returns the original instead of writing a second one."""
    return _native.new_id()


class Refused(Exception):
    """Raise inside a decision when your own policy refuses the action: the outcome is recorded as
    ``refused`` and the exception propagates."""


@dataclass(frozen=True)
class Broken:
    """Where a stream stops verifying: the first broken sequence number and the format's code."""

    seq: int
    code: str
    message: str


@dataclass(frozen=True)
class VerifyReport:
    stream: str | None
    """The stream id, ``tnb1:...``."""
    entries: int
    """Entries checked before the first break, or all of them."""
    pinned_key: str | None
    """The genesis key fingerprint the stream was checked against; ``None`` when unpinned, which
    only shows the stream agrees with its own genesis key."""
    broken: Broken | None
    checkpoint: int | None
    """The size of the stream's latest checkpoint, which it matched, if it has one."""

    @property
    def ok(self) -> bool:
        """Verified: nothing broken, against a pinned key."""
        return self.broken is None and self.pinned_key is not None


@dataclass(frozen=True)
class Match:
    """A query result: the entry and its verification status, ``verified``, ``unpinned`` (no key
    pinned at open) or ``broken``."""

    verification: str
    entry: Entry


def _principal(p: Principal) -> dict[str, str]:
    if not isinstance(p, str):
        return dict(p)
    kind, sep, id = p.partition(":")
    if sep and kind in ("agent", "person", "service"):
        return {"kind": kind, "id": id}
    return {"kind": "agent", "id": p}


def _merge(draft: Mapping[str, Any] | None, fields: Mapping[str, Any]) -> Entry:
    d = dict(draft or {})
    d.update({k: v for k, v in fields.items() if v is not None})
    if "principal" in d:
        d["principal"] = _principal(d["principal"])
    return d


def _report(s: str) -> VerifyReport:
    r = json.loads(s)
    b = r["broken"]
    return VerifyReport(
        stream=r["stream"],
        entries=r["entries"],
        pinned_key=r["pinned_key"],
        broken=Broken(b["seq"], b["code"], b["message"]) if b else None,
        checkpoint=r["checkpoint"],
    )


def _filter(
    action: str | None,
    target: str | None,
    principal: Principal | None,
    subject: str | None,
    inputs: Iterable[str | tuple[str, str]],
    after_seq: int,
    limit: int | None,
) -> str:
    pairs = []
    for i in inputs:
        if isinstance(i, str):
            ref, sep, version = i.rpartition("@")
            if not sep:
                raise InvalidRequestError(f"input {i!r}: expected ref@version")
            pairs.append([ref, version])
        else:
            pairs.append(list(i))
    f: dict[str, Any] = {"inputs": pairs, "after_seq": after_seq}
    if principal is not None:
        p = _principal(principal)
        f["principal"] = f"{p['kind']}:{p['id']}"
    for k, v in (("action", action), ("target", target), ("subject", subject), ("limit", limit)):
        if v is not None:
            f[k] = v
    return json.dumps(f)


def _entry(s: str) -> Entry:
    e: Entry = json.loads(s)
    return e


def _matches(s: str) -> list[Match]:
    return [Match(m["verification"], m["entry"]) for m in json.loads(s)]


def _status(e: BaseException | None) -> Status:
    if e is None:
        return "ok"
    if isinstance(e, Refused):
        return "refused"
    # Cancelled, interrupted, exiting: whether the action ran is not known.
    return "error" if isinstance(e, Exception) else "unknown"


def _intent_ref(intent: Mapping[str, Any] | str) -> str:
    return json.dumps({"id": intent} if isinstance(intent, str) else dict(intent))


class _Log:
    _s: _native.Stream
    _digest_key: bytes | None

    def __init__(self, s: _native.Stream, digest_key: bytes | None) -> None:
        self._s = s
        self._digest_key = digest_key

    @property
    def id(self) -> str:
        """The stream id, ``tnb1:...``."""
        return self._s.id

    @property
    def fingerprint(self) -> str | None:
        """The genesis key's fingerprint (pinned, or as this machine's keys hold it): what a
        verifier pins."""
        return self._s.fingerprint

    @property
    def writable(self) -> bool:
        """Whether this machine holds the keys to write the stream; else it is open read-only."""
        return self._s.writable

    def digest(self, content: bytes | str, *, subject: str | None = None) -> str:
        """The keyed digest of an input, ``hmac-sha256:<hex>``: a guessed value cannot be
        confirmed from the log without the key. The key is the ``digest_key`` given at open, else
        ``subject``'s data key (the tenant's without one) from the local key store beside the
        stream's keys, made on first use; erasing that key leaves the digest unconfirmable."""
        data = content.encode() if isinstance(content, str) else content
        if self._digest_key is None:
            return self._s.digest(subject, data)
        return "hmac-sha256:" + hmac.new(self._digest_key, data, hashlib.sha256).hexdigest()

    def _decision_draft(
        self, action: str, principal: Principal | None, fields: Mapping[str, Any]
    ) -> Entry:
        return _merge({"action": {"type": action}}, {"principal": principal, **fields})


class _Run:
    """What a run shares: its principal and the inputs read since its last decision."""

    def __init__(self, log: _Log, principal: Principal) -> None:
        self._log = log
        self.principal = _principal(principal)
        self._reads: list[dict[str, str]] = []

    def read(
        self,
        ref: str,
        version: str,
        content: bytes | str | None = None,
        *,
        digest: str | None = None,
    ) -> None:
        """Records that the run read ``ref`` at ``version``: the next decision lists it among its
        inputs, with the keyed digest of ``content`` (or ``digest`` as given)."""
        if digest is None:
            if content is None:
                raise InvalidRequestError("read() needs content or digest")
            digest = self._log.digest(content)
        self._reads.append({"ref": ref, "version": version, "digest": digest})

    def _take(self, draft: Entry) -> Entry:
        draft.setdefault("principal", self.principal)
        if self._reads:
            draft["inputs"] = self._reads + list(draft.get("inputs", []))
            self._reads = []
        return draft


def _bound_target(target: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    t: str | None = target(*args, **kwargs) if callable(target) else target
    return t


class Decision:
    """``with log.decision(...)`` or ``@log.decision(...)``: the intent is durable before the block
    or function runs; the outcome follows, ``ok``, ``refused`` (on :class:`Refused`) or ``error``
    (any other exception, which propagates). As a decorator, ``target`` may be a function of the
    decorated function's arguments."""

    intent: Entry | None = None
    outcome: Entry | None = None

    def __init__(self, log: Tenbri, draft: Entry, target: Any, run: _Run | None) -> None:
        self._log, self._draft, self._target, self._run = log, draft, target, run

    def _bind(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Decision:
        draft = dict(self._draft)
        target = _bound_target(self._target, args, kwargs)
        if target is not None:
            draft["action"] = {**draft["action"], "target": target}
        return Decision(self._log, draft, None, self._run)

    def __enter__(self) -> Decision:
        if callable(self._target):
            raise TypeError("a callable target needs the decorator form")
        draft = dict(self._draft)
        if self._target is not None:
            draft["action"] = {**draft["action"], "target": self._target}
        if self._run is not None:
            draft = self._run._take(draft)
        self.intent = self._log.intent(draft)
        return self

    def __exit__(
        self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        assert self.intent is not None
        self.outcome = self._log.outcome(self.intent, _status(e))

    def __call__(self, fn: F) -> F:
        if inspect.iscoroutinefunction(fn):
            raise TypeError("decorate async functions with AsyncTenbri's decision")

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self._bind(args, kwargs):
                return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]


class AsyncDecision:
    """The :class:`Decision` of :class:`AsyncTenbri`: ``async with`` or a decorator of async
    functions."""

    intent: Entry | None = None
    outcome: Entry | None = None

    def __init__(self, log: AsyncTenbri, draft: Entry, target: Any, run: _Run | None) -> None:
        self._log, self._draft, self._target, self._run = log, draft, target, run

    def _bind(self, args: tuple[Any, ...], kwargs: dict[str, Any]) -> AsyncDecision:
        draft = dict(self._draft)
        target = _bound_target(self._target, args, kwargs)
        if target is not None:
            draft["action"] = {**draft["action"], "target": target}
        return AsyncDecision(self._log, draft, None, self._run)

    async def __aenter__(self) -> AsyncDecision:
        if callable(self._target):
            raise TypeError("a callable target needs the decorator form")
        draft = dict(self._draft)
        if self._target is not None:
            draft["action"] = {**draft["action"], "target": self._target}
        if self._run is not None:
            draft = self._run._take(draft)
        self.intent = await self._log.intent(draft)
        return self

    async def __aexit__(
        self, t: type[BaseException] | None, e: BaseException | None, tb: TracebackType | None
    ) -> None:
        assert self.intent is not None
        self.outcome = await self._log.outcome(self.intent, _status(e))

    def __call__(self, fn: F) -> F:
        if not inspect.iscoroutinefunction(fn):
            raise TypeError("AsyncTenbri's decision decorates async functions; use Tenbri's")

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            async with self._bind(args, kwargs):
                return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]


class Run(_Run):
    """``with log.run(principal) as run``: decisions by one principal, with the inputs it read."""

    _log: Tenbri

    def decision(self, action: str, target: Any = None, **fields: Any) -> Decision:
        """A decision by the run's principal, listing the inputs read since the last one."""
        return Decision(self._log, self._log._decision_draft(action, None, fields), target, self)

    def __enter__(self) -> Run:
        return self

    def __exit__(self, *exc: object) -> None:
        pass


class AsyncRun(_Run):
    """The :class:`Run` of :class:`AsyncTenbri`."""

    _log: AsyncTenbri

    def decision(self, action: str, target: Any = None, **fields: Any) -> AsyncDecision:
        """A decision by the run's principal, listing the inputs read since the last one."""
        return AsyncDecision(
            self._log, self._log._decision_draft(action, None, fields), target, self
        )

    def __enter__(self) -> AsyncRun:
        return self

    def __exit__(self, *exc: object) -> None:
        pass

    async def __aenter__(self) -> AsyncRun:
        return self

    async def __aexit__(self, *exc: object) -> None:
        pass


class Tenbri(_Log):
    """A stream, opened with :meth:`open`. Every call blocks until done (the GIL is released)."""

    @classmethod
    def open(
        cls,
        url: str | os.PathLike[str],
        *,
        keys: str | os.PathLike[str] | None = None,
        key: str | None = None,
        create: bool = False,
        digest_key: bytes | None = None,
    ) -> Tenbri:
        """Opens the stream at ``url``: a directory, ``file://...``, ``s3://bucket/prefix`` or
        ``r2://bucket/prefix`` (credentials from ``AWS_*``; ``CLOUDFLARE_ACCOUNT_ID`` for R2).

        ``keys`` is the keys directory (default ``$TENBRI_KEYS``, else ``~/.config/tenbri/keys``),
        never inside the stream; without the stream's keys there, the stream is read-only.
        ``key`` pins the genesis key (``sha256:...`` fingerprint or ``ed25519:...``) for writes,
        :meth:`verify` and :meth:`query`. ``create`` creates the stream and its keys if there is
        none. ``digest_key`` keys the digests of inputs a run reads."""
        s = _native.Stream.open(
            os.fspath(url), None if keys is None else os.fspath(keys), key, create
        )
        return cls(s, digest_key)

    def append(self, entry: Mapping[str, Any], /) -> Entry:
        """Appends a draft entry (``note``, ``approval``, ``decision``); returns it as stored, once
        durable. Give it an ``id`` (:func:`new_id`) to make retries idempotent."""
        return _entry(self._s.append(json.dumps(_merge(entry, {}))))

    def intent(self, draft: Mapping[str, Any] | None = None, /, **fields: Any) -> Entry:
        """Records an intent, durable before the action runs: ``action``, ``principal``,
        ``inputs``, ``rule``... as in format v1. ``kind`` and ``phase`` are filled in."""
        return _entry(self._s.intent(json.dumps(_merge(draft, fields))))

    def outcome(
        self, intent: Mapping[str, Any] | str, status: Status = "ok", /, **fields: Any
    ) -> Entry:
        """Records the outcome of ``intent`` (the entry :meth:`intent` returned, or its id).
        ``principal``, ``action``, ``subject`` and ``source`` default to the intent's."""
        return _entry(
            self._s.outcome(_intent_ref(intent), status, json.dumps(_merge(None, fields)))
        )

    def decision(
        self, action: str, target: Any = None, *, principal: Principal | None = None, **fields: Any
    ) -> Decision:
        """A decision to record around an action: a context manager and a decorator."""
        return Decision(self, self._decision_draft(action, principal, fields), target, None)

    def run(self, principal: Principal) -> Run:
        """Decisions by ``principal``; inputs it reads are pinned to its next decision."""
        return Run(self, principal)

    def verify(self, key: str | None = None) -> VerifyReport:
        """Checks the whole stream (canonical bytes, chain, signatures, keys, HEAD, latest
        checkpoint) against ``key``, else the key pinned at open."""
        return _report(self._s.verify(key))

    def query(
        self,
        *,
        action: str | None = None,
        target: str | None = None,
        principal: Principal | None = None,
        subject: str | None = None,
        inputs: Iterable[str | tuple[str, str]] = (),
        after_seq: int = 0,
        limit: int | None = None,
    ) -> list[Match]:
        """Entries matching every filter given, in order, each with its verification status.
        ``inputs`` are ``"ref@version"`` strings or ``(ref, version)`` pairs."""
        f = _filter(action, target, principal, subject, inputs, after_seq, limit)
        return _matches(self._s.query(f))

    def flush(self) -> None:
        """Waits for every append queued so far."""
        self._s.flush()

    def close(self) -> None:
        """Flushes and stops the writer; reads still work."""
        self._s.close()

    def __enter__(self) -> Tenbri:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class AsyncTenbri(_Log):
    """A stream for asyncio, opened with ``await AsyncTenbri.open(...)``; nothing blocks the event
    loop, and concurrent appends share one group commit."""

    @classmethod
    async def open(
        cls,
        url: str | os.PathLike[str],
        *,
        keys: str | os.PathLike[str] | None = None,
        key: str | None = None,
        create: bool = False,
        digest_key: bytes | None = None,
    ) -> AsyncTenbri:
        """See :meth:`Tenbri.open`."""
        s = await _native.Stream.open_async(
            os.fspath(url), None if keys is None else os.fspath(keys), key, create
        )
        return cls(s, digest_key)

    async def append(self, entry: Mapping[str, Any], /) -> Entry:
        """See :meth:`Tenbri.append`."""
        return _entry(await self._s.append_async(json.dumps(_merge(entry, {}))))

    async def intent(self, draft: Mapping[str, Any] | None = None, /, **fields: Any) -> Entry:
        """See :meth:`Tenbri.intent`."""
        return _entry(await self._s.intent_async(json.dumps(_merge(draft, fields))))

    async def outcome(
        self, intent: Mapping[str, Any] | str, status: Status = "ok", /, **fields: Any
    ) -> Entry:
        """See :meth:`Tenbri.outcome`."""
        s = await self._s.outcome_async(
            _intent_ref(intent), status, json.dumps(_merge(None, fields))
        )
        return _entry(s)

    def decision(
        self, action: str, target: Any = None, *, principal: Principal | None = None, **fields: Any
    ) -> AsyncDecision:
        """See :meth:`Tenbri.decision`: ``async with``, or a decorator of async functions."""
        return AsyncDecision(self, self._decision_draft(action, principal, fields), target, None)

    def run(self, principal: Principal) -> AsyncRun:
        """See :meth:`Tenbri.run`."""
        return AsyncRun(self, principal)

    async def verify(self, key: str | None = None) -> VerifyReport:
        """See :meth:`Tenbri.verify`."""
        return _report(await self._s.verify_async(key))

    async def query(
        self,
        *,
        action: str | None = None,
        target: str | None = None,
        principal: Principal | None = None,
        subject: str | None = None,
        inputs: Iterable[str | tuple[str, str]] = (),
        after_seq: int = 0,
        limit: int | None = None,
    ) -> list[Match]:
        """See :meth:`Tenbri.query`."""
        f = _filter(action, target, principal, subject, inputs, after_seq, limit)
        return _matches(await self._s.query_async(f))

    async def flush(self) -> None:
        """See :meth:`Tenbri.flush`."""
        await self._s.flush_async()

    async def close(self) -> None:
        """See :meth:`Tenbri.close`."""
        await self._s.close_async()

    async def __aenter__(self) -> AsyncTenbri:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


from ._auto import (  # noqa: E402  (built on the classes above)
    Default,
    agent,
    decision,
    default,
    describe,
    init,
    instrument_claude_agent_sdk,
    instrument_langchain,
    instrument_openai_agents,
)
