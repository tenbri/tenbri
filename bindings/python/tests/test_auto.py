"""tenbri.init(), tenbri.agent() and @tenbri.decision: the default stream and what it records."""

import asyncio
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import tenbri
from tenbri import InvalidRequestError, NoSessionKeyError, Refused, Tenbri


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    for v in ("TENBRI_STREAM", "TENBRI_KEYS", "TENBRI_AGENT", "TENBRI_APPROVER", "TENBRI_SCHEMA"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.chdir(tmp_path)
    yield
    if tenbri._auto._current is not None:
        tenbri.default().close()


def decisions(log: Tenbri) -> list[dict[str, Any]]:
    log.flush()
    return [m.entry for m in log.query() if m.entry["kind"] == "decision"]


def brief(e: dict[str, Any]) -> tuple[str, str, str]:
    return (e["phase"], e["action"]["type"], e.get("status", ""))


def test_init_from_the_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    with pytest.raises(InvalidRequestError, match="TENBRI_STREAM"):
        tenbri.init()
    with pytest.raises(InvalidRequestError, match="init()"):
        tenbri.default()
    monkeypatch.setenv("TENBRI_STREAM", str(tmp_path / "env-stream"))
    monkeypatch.setenv("TENBRI_KEYS", str(tmp_path / "keys"))
    monkeypatch.setenv("TENBRI_AGENT", "agent:support")
    monkeypatch.setenv("TENBRI_APPROVER", "person:alice")
    d = tenbri.init()
    assert tenbri.default() is d and d.writable  # created, keys and all
    assert (d.agent, d.approver, d.fail_open, d.actions) == ("agent:support", "person:alice", False, {})
    assert (tmp_path / "env-stream" / "HEAD").exists() and (tmp_path / "keys").is_dir()
    # Arguments win, and a second init replaces (and closes) the first.
    e = tenbri.init(tmp_path / "arg-stream", agent="agent:billing", fail_open=True)
    assert tenbri.default() is e and e.id != d.id and not d.writable
    assert (e.agent, e.fail_open) == ("agent:billing", True)
    # Again on the same stream, as a notebook cell run twice does: the first lets go of its writer.
    assert tenbri.init(tmp_path / "arg-stream").writable
    # Scoped: the block closes it and it stops being the default.
    with tenbri.init(tmp_path / "scoped") as s:
        assert tenbri.default() is s
    assert not s.writable
    with pytest.raises(InvalidRequestError):
        tenbri.default()


def test_schema_from_tenbri_toml(tmp_path: Path) -> None:
    (tmp_path / "tenbri.toml").write_text(
        '[actions.issue_refund]\ntarget = "stripe:{charge}"\npolicy = "policy:refund@14"\n'
        '[actions.lookup]\ntarget = "orders:*"\n'
    )
    tenbri.init(tmp_path / "s")  # ./tenbri.toml, found in the working directory
    assert tenbri.describe("mcp__billing__issue_refund", {"charge": "ch_1"}) == {
        "action": "issue_refund",
        "target": "stripe:ch_1",
        "rule": {"ref": "policy:refund", "version": "14", "result": "allow"},
    }
    # A glob target cannot be filled; code overrides the schema per tool.
    assert tenbri.describe("lookup", {"order": "o1"}) == {}
    actions = {"lookup": {"target": "orders:{order}", "subject": lambda a: "c-" + a["order"]}}
    assert tenbri.describe("lookup", {"order": "o1"}, actions) == {
        "target": "orders:o1",
        "subject": "c-o1",
    }
    assert tenbri.describe("mcp__shop__lookup", {"order": "o1"}, actions)["action"] == "lookup"
    assert tenbri.describe("other", {}) == {}
    with pytest.raises(InvalidRequestError, match="charge"):
        tenbri.describe("issue_refund", {})
    (tmp_path / "bad.toml").write_text('[actions.x]\npolicy = "no-version"\n')
    with pytest.raises(InvalidRequestError, match="ref@version"):
        tenbri.init(tmp_path / "s2", schema=tmp_path / "bad.toml")


def test_decorator_sync(tmp_path: Path) -> None:
    log = tenbri.init(tmp_path / "s", keys=tmp_path / "k", agent="agent:support")

    @tenbri.decision(
        "issue_refund",
        target="stripe:{charge}",
        policy="policy:refund@14",
        inputs=lambda charge, amount, customer=None: [("ticket:4512", "3", f"refund {charge}")],
        subject="{customer.id}",
    )
    def refund(charge: str, amount: int, customer: Any = None) -> int:
        """Refunds a charge."""
        assert [brief(e) for e in decisions(log)][-1] == ("intent", "issue_refund", "")
        if amount > 500:
            raise Refused("over the ceiling")
        if amount < 0:
            raise ValueError("negative")
        return amount

    class Customer:
        id = "c-42"

    assert refund("ch_1", 20, customer=Customer()) == 20
    assert refund.__doc__ == "Refunds a charge." and refund.__name__ == "refund"
    with pytest.raises(Refused):
        refund("ch_2", 900, Customer())
    with pytest.raises(ValueError):
        refund("ch_3", -1, Customer())
    es = decisions(log)
    assert [brief(e) for e in es if e["phase"] == "outcome"] == [
        ("outcome", "issue_refund", "ok"),
        ("outcome", "issue_refund", "refused"),
        ("outcome", "issue_refund", "error"),
    ]
    intent = es[0]
    assert intent["principal"] == {"kind": "agent", "id": "support"}
    assert intent["action"] == {"type": "issue_refund", "target": "stripe:ch_1"}
    assert intent["rule"] == {"ref": "policy:refund", "version": "14", "result": "allow"}
    assert intent["subject"] == "c-42"
    # Keyed by the subject's data key from the local key store: no key in code.
    [pin] = intent["inputs"]
    assert pin == {
        "ref": "ticket:4512",
        "version": "3",
        "digest": log.digest("refund ch_1", subject="c-42"),
    }
    assert pin["digest"] != log.digest("refund ch_1")  # the tenant's key is another key
    assert log.verify(log.fingerprint).ok


def test_decorator_async_and_agent_scope(tmp_path: Path) -> None:
    log = tenbri.init(tmp_path / "s", keys=tmp_path / "k")

    @tenbri.decision("reply_ticket", "zendesk:{ticket}")
    async def reply(ticket: int) -> str:
        await asyncio.sleep(0)
        if ticket == 0:
            raise Refused("nothing to reply to")
        return "sent"

    async def main() -> None:
        with pytest.raises(InvalidRequestError, match="TENBRI_AGENT"):
            await reply(1)  # who acts is never guessed
        with tenbri.agent("agent:support"):
            assert await reply(1) == "sent"
            with tenbri.agent("person:alice"):
                await reply(2)
            with pytest.raises(Refused):
                await reply(0)
        task = asyncio.create_task(asyncio.sleep(10))
        with tenbri.agent("agent:support"):

            @tenbri.decision("wait")
            async def wait() -> None:
                await task

            pending = asyncio.create_task(wait())
            await asyncio.sleep(0.05)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending

    asyncio.run(main())
    es = decisions(log)
    assert [(e["principal"]["id"], e["action"].get("target"), e.get("status")) for e in es] == [
        ("support", "zendesk:1", None),
        ("support", "zendesk:1", "ok"),
        ("alice", "zendesk:2", None),
        ("alice", "zendesk:2", "ok"),
        ("support", "zendesk:0", None),
        ("support", "zendesk:0", "refused"),
        ("support", None, None),
        ("support", None, "unknown"),  # cancelled: whether it happened is not known
    ]


def test_fail_closed_unless_fail_open(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    Tenbri.open(tmp_path / "s", keys=tmp_path / "keys", create=True).close()
    ran: list[str] = []

    @tenbri.decision("issue_refund", "stripe:{charge}", principal="agent:support")
    def refund(charge: str) -> None:
        ran.append(charge)

    with pytest.raises(InvalidRequestError, match="init"):
        refund("ch_0")  # no stream: no action
    # The stream opens read-only here: its keys are elsewhere, so nothing can be written.
    tenbri.init(tmp_path / "s", keys=tmp_path / "elsewhere")
    with pytest.raises(NoSessionKeyError):
        refund("ch_1")
    assert ran == []

    tenbri.init(tmp_path / "s", keys=tmp_path / "elsewhere", fail_open=True)
    with caplog.at_level(logging.WARNING, "tenbri"):
        refund("ch_2")
    assert ran == ["ch_2"] and "runs unrecorded (fail-open)" in caplog.text

    @tenbri.decision("issue_refund", principal="agent:support", fail_open=False)
    def strict() -> None:
        ran.append("strict")

    with pytest.raises(NoSessionKeyError):
        strict()
    assert ran == ["ch_2"]
