import asyncio
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import tenbri
from tenbri import AsyncTenbri, Refused, Tenbri

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "vectors"
DIGEST_KEY = b"k" * 32


@pytest.fixture
def log(tmp_path: Path) -> Iterator[Tenbri]:
    with Tenbri.open(
        tmp_path / "audit", keys=tmp_path / "keys", create=True, digest_key=DIGEST_KEY
    ) as log:
        yield log


def test_run_decisions_and_verify(log: Tenbri) -> None:
    assert log.writable and log.id.startswith("tnb1:") and log.fingerprint
    with log.run("agent:support-assistant") as run:
        run.read("policy:refund", "14", b"refunds under 50 EUR are automatic")
        with run.decision(
            "issue_refund",
            "stripe:ch_1",
            rule={"ref": "policy:refund", "version": "14", "result": "allow"},
        ) as d:
            assert d.intent is not None and d.intent["phase"] == "intent"
        with pytest.raises(Refused):
            with run.decision("issue_refund", "stripe:ch_2"):
                raise Refused("over the limit")
        with pytest.raises(ZeroDivisionError):
            with run.decision("reply_ticket", "zendesk:4821"):
                1 / 0
    assert (
        d.outcome is not None
        and d.outcome["status"] == "ok"
        and d.outcome["intent"] == d.intent["id"]
    )
    assert d.intent["inputs"] == [
        {
            "ref": "policy:refund",
            "version": "14",
            "digest": log.digest(b"refunds under 50 EUR are automatic"),
        }
    ]
    assert d.intent["principal"] == {"kind": "agent", "id": "support-assistant"}

    statuses = [
        m.entry["status"]
        for m in log.query(principal="agent:support-assistant")
        if m.entry["phase"] == "outcome"
    ]
    assert statuses == ["ok", "refused", "error"]
    [m] = log.query(inputs=["policy:refund@14"])
    assert m.entry == d.intent and m.verification == "unpinned"

    r = log.verify(log.fingerprint)
    assert r.ok and r.broken is None and r.entries == 8 and r.pinned_key == log.fingerprint
    assert not log.verify().ok  # consistent, but unpinned: proves nothing


def test_decorator_with_target_from_arguments(log: Tenbri) -> None:
    @log.decision(
        "issue_refund",
        target=lambda charge, amount: f"stripe:{charge}",
        principal="service:billing",
    )
    def refund(charge: str, amount: int) -> int:
        return amount

    assert refund("ch_9", 30) == 30
    [intent, outcome] = [m.entry for m in log.query(target="stripe:ch_9")]
    assert intent["principal"] == {"kind": "service", "id": "billing"}
    assert outcome["status"] == "ok"


def test_idempotent_retries_and_typed_errors(log: Tenbri, tmp_path: Path) -> None:
    id = tenbri.new_id()
    draft = {"id": id, "action": {"type": "reply_ticket"}, "principal": "support"}
    first = log.intent(draft)
    assert log.intent(draft) == first  # a retry returns the original
    with pytest.raises(tenbri.IdempotencyConflictError) as e:
        log.intent(draft, action={"type": "close_ticket"})
    assert e.value.code == "TENBRI_IDEMPOTENCY_CONFLICT"
    with pytest.raises(tenbri.InvalidEntryError) as e2:
        log.append({"kind": "note", "colour": "red"})
    assert e2.value.reason == "unknown_field" and e2.value.id is None
    with pytest.raises(tenbri.InvalidRequestError):
        log.intent(kind="note")
    with pytest.raises(tenbri.NotFoundError):
        Tenbri.open(tmp_path / "nothing")

    # Another machine, without the keys: it verifies, it does not write.
    reader = Tenbri.open(
        f"file://{tmp_path / 'audit'}", keys=tmp_path / "other", key=log.fingerprint
    )
    assert not reader.writable
    with pytest.raises(tenbri.NoSessionKeyError):
        reader.append({"kind": "note"})
    assert reader.verify().ok
    assert reader.query(limit=1, after_seq=2)[0] == tenbri.Match("verified", first)


def test_async_concurrent_intents_share_group_commit(tmp_path: Path) -> None:
    async def main() -> None:
        async with await AsyncTenbri.open(
            tmp_path / "audit", keys=tmp_path / "keys", create=True
        ) as log:
            intents = await asyncio.gather(
                *(
                    log.intent(action={"type": "t", "target": str(i)}, principal="a")
                    for i in range(200)
                )
            )
            assert sorted(e["seq"] for e in intents) == list(range(3, 203))

            @log.decision("issue_refund", principal="agent:billing")
            async def refund() -> str:
                return "done"

            assert await refund() == "done"
            async with log.run("person:ana") as run:
                run.read("ticket:1", "3", digest="hmac-sha256:" + "0" * 64)
                async with run.decision("close_ticket", "zendesk:1") as d:
                    pass
            assert d.outcome is not None and d.outcome["principal"] == {
                "kind": "person",
                "id": "ana",
            }
            r = await log.verify(log.fingerprint)
            assert r.ok and r.entries == 206
            assert len(await log.query(action="t")) == 200

    asyncio.run(main())


@pytest.mark.parametrize(
    "case", json.loads((VECTORS / "streams.json").read_text())["cases"], ids=lambda c: c["name"]
)
def test_conformance_streams(case: dict[str, Any], tmp_path: Path) -> None:
    log = Tenbri.open(VECTORS / "streams" / case["name"], keys=tmp_path, key=case["pin"])
    r, want = log.verify(), case["result"]
    if want["ok"]:
        assert r.ok and r.entries == want["entries"]
    else:
        assert r.broken == tenbri.Broken(
            want["seq"], want["error"], r.broken.message if r.broken else ""
        )


@pytest.mark.skipif(not hasattr(os, "fork"), reason="no fork here")
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_forked_child_starts_its_own_runtime(log: Tenbri, tmp_path: Path) -> None:
    log.append({"kind": "note"})
    pid = os.fork()
    if pid == 0:  # the parent's Tokio threads are not in the child: it must start its own
        child = Tenbri.open(tmp_path / "child", keys=tmp_path / "keys", create=True)
        child.append({"kind": "note"})
        os._exit(0 if child.verify(child.fingerprint).ok else 1)
    assert os.waitpid(pid, 0)[1] == 0
    assert log.verify(log.fingerprint).entries == 3
