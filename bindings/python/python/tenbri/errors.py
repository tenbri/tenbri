"""Typed exceptions, one per TENBRI_* code: the same catalogue as tenbrid's HTTP and gRPC APIs."""

from __future__ import annotations


class TenbriError(Exception):
    """A Tenbri failure. ``code`` is the stable TENBRI_* code, ``reason`` the format v1 error code
    (``bad_signature``...) where there is one, and ``id`` the id of the entry being written: retry
    with it, and a write that did land is returned instead of written twice."""

    code = "TENBRI_INTERNAL"

    def __init__(self, message: str, *, reason: str | None = None, id: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.id = id


class InvalidRequestError(TenbriError):
    """The call is malformed: a draft that is not an object, a member that contradicts the call."""

    code = "TENBRI_INVALID_REQUEST"


class InvalidEntryError(TenbriError):
    """The entry breaks a rule of format v1 (see ``reason``). Nothing was written."""

    code = "TENBRI_INVALID_ENTRY"


class NotFoundError(TenbriError):
    """No stream at the location."""

    code = "TENBRI_NOT_FOUND"


class IdempotencyConflictError(TenbriError):
    """The entry id was used before for a different entry."""

    code = "TENBRI_IDEMPOTENCY_CONFLICT"


class WriteConflictError(TenbriError):
    """Another writer holds the stream. Nothing was written."""

    code = "TENBRI_WRITE_CONFLICT"


class DeadlineExceededError(TenbriError):
    """The lane's queue stayed full past the deadline (backpressure). Nothing was written."""

    code = "TENBRI_DEADLINE_EXCEEDED"


class StoreUnavailableError(TenbriError):
    """Storage failed; the entry may not be durable. Retrying with the same ``id`` is safe."""

    code = "TENBRI_STORE_UNAVAILABLE"


class NoSessionKeyError(TenbriError):
    """No usable session key and no stream key to certify one: the stream is open read-only."""

    code = "TENBRI_NO_SESSION_KEY"


class StreamBrokenError(TenbriError):
    """The stream does not verify (see ``reason``)."""

    code = "TENBRI_STREAM_BROKEN"


_BY_CODE = {
    c.code: c
    for c in (
        InvalidRequestError,
        InvalidEntryError,
        NotFoundError,
        IdempotencyConflictError,
        WriteConflictError,
        DeadlineExceededError,
        StoreUnavailableError,
        NoSessionKeyError,
        StreamBrokenError,
    )
}


def _from_code(code: str, message: str, reason: str | None, id: str | None) -> TenbriError:
    """The exception for ``code``; the native module raises what this returns."""
    cls = _BY_CODE.get(code, TenbriError)
    e = cls(message, reason=reason, id=id)
    e.code = code
    return e
