"""The adapter against the real SDK and a real stream, with a scripted model: no API key.

The conformance scenario (one tool call allowed, one refused, one crash mid-action), plus errors,
approvals, handoffs and failing closed or open.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from agents import (
    Agent,
    Runner,
    ToolGuardrailFunctionOutput,
    ToolInputGuardrailData,
    function_tool,
    set_trace_processors,
    tool_input_guardrail,
)
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import (
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
)
from tenbri import AsyncTenbri, Entry, Tenbri, TenbriError

from tenbri_openai_agents import TenbriRecorder

# Traces are kept (their ids land in entries) but exported nowhere.
set_trace_processors([])


class Scripted(Model):
    """A model that answers with the next scripted turn."""

    def __init__(self, *turns: list[Any]) -> None:
        self.turns = list(turns)

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def call(name: str, call_id: str, **args: Any) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall(
        id=call_id, call_id=call_id, type="function_call", name=name, arguments=json.dumps(args)
    )


def say(text: str) -> ResponseOutputMessage:
    content: list[ResponseOutputText | ResponseOutputRefusal] = [
        ResponseOutputText(text=text, type="output_text", annotations=[])
    ]
    return ResponseOutputMessage(
        id="msg", type="message", role="assistant", status="completed", content=content
    )


@pytest.fixture
def stream(tmp_path: Path) -> Iterator[Callable[[], Awaitable[AsyncTenbri]]]:
    async def open() -> AsyncTenbri:
        return await AsyncTenbri.open(
            tmp_path / "audit", keys=tmp_path / "keys", create=True, digest_key=b"k" * 32
        )

    yield open


async def decisions(log: AsyncTenbri) -> list[Entry]:
    return [m.entry for m in await log.query() if m.entry["kind"] in ("decision", "approval")]


def brief(e: Entry) -> tuple[str, ...]:
    """kind or phase, action, status, principal: enough to read a stream at a glance."""
    p = e["principal"]
    return (
        str(e.get("phase", e["kind"])),
        e["action"]["type"],
        e.get("status", ""),
        f"{p['kind']}:{p['id']}",
    )


def test_allowed_error_refused_and_handoff(stream: Callable[[], Awaitable[AsyncTenbri]]) -> None:
    async def main() -> None:
        log = await stream()
        seen_before_refund: list[tuple[str, ...]] = []

        @function_tool
        async def issue_refund(charge: str, amount: int) -> str:
            # The intent is durable before the tool runs (the three calls run concurrently).
            seen_before_refund.extend(brief(e) for e in await decisions(log))
            return f"refunded {amount}"

        @function_tool
        def lookup_order(order: str) -> str:
            raise RuntimeError("orders database is down")

        @tool_input_guardrail
        def no_wipes(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
            return ToolGuardrailFunctionOutput.reject_content("wiping is not allowed")

        @function_tool(tool_input_guardrails=[no_wipes])
        def wipe_account(account: str) -> str:
            raise AssertionError("a refused tool must not run")

        billing = Agent(name="billing", model=Scripted([say("done")]))
        support = Agent(
            name="support",
            tools=[issue_refund, lookup_order, wipe_account],
            handoffs=[billing],
            model=Scripted(
                [
                    call("issue_refund", "c1", charge="ch_123", amount=40),
                    call("lookup_order", "c2", order="o_9"),
                    call("wipe_account", "c3", account="acct_1"),
                ],
                [call("transfer_to_billing", "c4")],
            ),
        )
        recorder = TenbriRecorder(
            log,
            target=lambda tool, args: f"stripe:{args['charge']}" if "charge" in args else None,
            inputs=lambda tool, args: (
                [{"ref": "policy:refund", "version": "14", "content": "under 50 EUR"}]
                if tool == "issue_refund"
                else []
            ),
        )
        recorder.read("ticket:4821", "3", "please refund my order")
        async with recorder:
            result = await Runner.run(
                support, "refund ch_123", hooks=recorder, run_config=recorder.run_config()
            )
        assert result.final_output == "done"

        entries = await decisions(log)
        assert ("intent", "issue_refund", "", "agent:support") in seen_before_refund
        assert sorted(brief(e) for e in entries) == sorted(
            [
                ("intent", "issue_refund", "", "agent:support"),
                ("outcome", "issue_refund", "ok", "agent:support"),
                ("intent", "lookup_order", "", "agent:support"),
                ("outcome", "lookup_order", "error", "agent:support"),
                ("intent", "wipe_account", "", "agent:support"),
                ("outcome", "wipe_account", "refused", "agent:support"),
                ("intent", "handoff", "", "agent:support"),
                ("outcome", "handoff", "ok", "agent:support"),
            ]
        )
        refund = next(e for e in entries if e["action"]["type"] == "issue_refund")
        assert refund["action"]["target"] == "stripe:ch_123"
        assert [(i["ref"], i["version"]) for i in refund["inputs"]] == [
            ("ticket:4821", "3"),
            ("policy:refund", "14"),
        ]
        assert refund["inputs"][1]["digest"] == log.digest("under 50 EUR")
        assert len(refund["trace"]["trace_id"]) == 32 and len(refund["trace"]["span_id"]) == 16
        handoff = next(e for e in entries if e["action"]["type"] == "handoff")
        assert handoff["action"]["target"] == "agent:billing"
        # Tool arguments and results are never written, only what target= and inputs= make of them.
        assert not {"o_9", "acct_1", "refunded", "orders database"} & set(json.dumps(entries).split('"'))
        assert "orders database" not in json.dumps(entries)
        assert (await log.verify(log.fingerprint)).ok

    asyncio.run(main())


def test_approvals_recorded_and_named(stream: Callable[[], Awaitable[AsyncTenbri]]) -> None:
    async def main() -> None:
        log = await stream()
        ran: list[str] = []

        @function_tool(needs_approval=True)
        def pay_invoice(invoice: str) -> str:
            ran.append(invoice)
            return "paid"

        @function_tool(needs_approval=True)
        def delete_vendor(vendor: str) -> str:
            ran.append(vendor)
            return "deleted"

        agent = Agent(
            name="finance",
            tools=[pay_invoice, delete_vendor],
            model=Scripted(
                [call("pay_invoice", "p1", invoice="inv_7"), call("delete_vendor", "d1", vendor="v_2")],
                [say("paid, not deleted")],
            ),
        )
        recorder = TenbriRecorder(log, target=lambda tool, args: next(iter(args.values()), None))
        async with recorder:
            first = await Runner.run(agent, "pay inv_7", hooks=recorder)
            assert {i.name for i in first.interruptions} == {"pay_invoice", "delete_vendor"}
            assert await decisions(log) == []  # waiting for a person
            state = first.to_state()
            for item in first.interruptions:
                if item.name == "pay_invoice":
                    await recorder.approve(state, item, "person:alice")
                else:
                    await recorder.reject(state, item, "person:bob")
            await Runner.run(agent, state, hooks=recorder)
        assert ran == ["inv_7"]

        entries = await decisions(log)
        approval = next(e for e in entries if e["kind"] == "approval")
        assert brief(approval) == ("approval", "pay_invoice", "", "person:alice")
        assert approval["action"]["target"] == "inv_7"
        pay = next(e for e in entries if e.get("phase") == "intent" and e["action"]["type"] == "pay_invoice")
        assert pay["approval"]["by"] == {"kind": "person", "id": "alice"}
        assert ("outcome", "pay_invoice", "ok", "agent:finance") in map(brief, entries)
        assert ("outcome", "delete_vendor", "refused", "person:bob") in map(brief, entries)
        # The approval member names the approval entry's hash: the stream verifies only if it does.
        assert (await log.verify(log.fingerprint)).ok

    asyncio.run(main())


def test_crash_mid_action_and_tripwire(stream: Callable[[], Awaitable[AsyncTenbri]]) -> None:
    async def main() -> None:
        log = await stream()

        @function_tool(failure_error_function=None)
        def migrate(db: str) -> str:
            raise RuntimeError("connection lost")

        @tool_input_guardrail
        def stop(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
            return ToolGuardrailFunctionOutput.raise_exception()

        @function_tool(tool_input_guardrails=[stop])
        def drop_table(table: str) -> str:
            raise AssertionError("a refused tool must not run")

        crash = Agent(name="ops", tools=[migrate], model=Scripted([call("migrate", "m1", db="prod")]))
        with pytest.raises(Exception, match="connection lost"):
            async with TenbriRecorder(log) as recorder:
                await Runner.run(crash, "migrate", hooks=recorder)

        tripped = Agent(name="ops", tools=[drop_table], model=Scripted([call("drop_table", "t1", table="users")]))
        with pytest.raises(Exception, match="guardrail"):
            async with TenbriRecorder(log) as recorder:
                await Runner.run(tripped, "drop users", hooks=recorder)

        assert sorted(map(brief, await decisions(log))) == sorted(
            [
                ("intent", "migrate", "", "agent:ops"),
                ("outcome", "migrate", "error", "agent:ops"),
                ("intent", "drop_table", "", "agent:ops"),
                ("outcome", "drop_table", "refused", "agent:ops"),
            ]
        )

    asyncio.run(main())


def test_tool_selection_and_failing_closed_or_open(
    stream: Callable[[], Awaitable[AsyncTenbri]], caplog: pytest.LogCaptureFixture
) -> None:
    async def main() -> None:
        log = await stream()
        ran: list[str] = []

        @function_tool
        def send_email(to: str) -> str:
            ran.append(to)
            return "sent"

        @function_tool
        def get_time() -> str:
            ran.append("time")
            return "noon"

        def agent() -> Agent[Any]:
            turns = [call("get_time", "g1"), call("send_email", "s1", to="a@example.com")]
            return Agent(name="mailer", tools=[send_email, get_time], model=Scripted(turns, [say("ok")]))

        await Runner.run(agent(), "mail", hooks=TenbriRecorder(log, tools=["send_email"]))
        assert {e["action"]["type"] for e in await decisions(log)} == {"send_email"}

        await log.close()  # the stream can no longer be written
        ran.clear()
        with pytest.raises(Exception) as failed:
            await Runner.run(agent(), "mail", hooks=TenbriRecorder(log, tools=["send_email"]))
        # The SDK wraps what a hook raises.
        assert isinstance(failed.value.__cause__ or failed.value, TenbriError)
        assert "a@example.com" not in ran  # fail closed: the action never ran

        ran.clear()
        with caplog.at_level(logging.WARNING, logger="tenbri.openai_agents"):
            await Runner.run(agent(), "mail", hooks=TenbriRecorder(log, fail_open=True))
        assert "a@example.com" in ran and "fail_open" in caplog.text

    asyncio.run(main())


def test_instrument_one_liner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """tenbri.init() and tenbri.instrument_openai_agents(): plain Runner.run and RunState answers
    are recorded, the action mapped by a dict, the approver from the environment."""
    import tenbri

    from tenbri_openai_agents import uninstrument

    monkeypatch.setenv("TENBRI_APPROVER", "person:alice")
    ran: list[str] = []

    async def over_50(ctx: Any, args: dict[str, Any], call_id: str) -> bool:
        return bool(args["amount"] > 50)

    @function_tool(needs_approval=over_50)
    def issue_refund(charge: str, amount: int) -> str:
        ran.append(charge)
        return "refunded"

    agent = Agent(
        name="support",
        tools=[issue_refund],
        model=Scripted(
            [call("issue_refund", "c1", charge="ch_1", amount=20)],
            [call("issue_refund", "c2", charge="ch_2", amount=80), call("issue_refund", "c3", charge="ch_3", amount=90)],
            [say("done")],
        ),
    )
    log = tenbri.init(tmp_path / "audit", keys=tmp_path / "keys")
    tenbri.instrument_openai_agents(
        actions={"issue_refund": {"target": "stripe:{charge}", "policy": "policy:refund@14"}}
    )

    async def main() -> None:
        result = await Runner.run(agent, "refund ch_1, then ch_2 and ch_3")
        state = result.to_state()
        for item in result.interruptions:
            (state.approve if item.call_id == "c2" else state.reject)(item)
        await Runner.run(agent, state)

    try:
        asyncio.run(main())
    finally:
        uninstrument()
        log.close()
    assert ran == ["ch_1", "ch_2"]
    log = Tenbri.open(tmp_path / "audit", keys=tmp_path / "keys")
    es = [m.entry for m in log.query() if m.entry["kind"] in ("decision", "approval")]
    assert [brief(e) for e in es] == [
        ("intent", "issue_refund", "", "agent:support"),
        ("outcome", "issue_refund", "ok", "agent:support"),
        ("approval", "issue_refund", "", "person:alice"),
        ("intent", "issue_refund", "", "agent:support"),
        ("outcome", "issue_refund", "refused", "person:alice"),
        ("intent", "issue_refund", "", "agent:support"),
        ("outcome", "issue_refund", "ok", "agent:support"),
    ]
    assert es[0]["action"] == {"type": "issue_refund", "target": "stripe:ch_1"}
    assert es[0]["rule"] == {"ref": "policy:refund", "version": "14", "result": "allow"}
    assert es[3]["action"]["target"] == "stripe:ch_3"  # refused
    assert es[5]["approval"]["by"] == {"kind": "person", "id": "alice"}  # ch_2, approved
    assert log.verify(log.fingerprint).ok
