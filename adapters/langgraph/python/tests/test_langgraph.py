"""The adapter against LangChain's create_agent and LangGraph, with a fake chat model: the
conformance scenario (one tool call allowed, one refused, one crash), human approval through
interrupts, fail-closed and fail-open, tool selection and input pinning."""

from __future__ import annotations

import asyncio
import inspect
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import ToolException, tool
from langgraph.checkpoint.memory import InMemorySaver
from tenbri import NoSessionKeyError, Refused, Tenbri

from tenbri_langgraph import TenbriCallbackHandler

DIGEST_KEY = b"k" * 32


class FakeModel(GenericFakeChatModel):
    """Plays back AI messages, tool calls included; binding tools changes nothing."""

    def bind_tools(self, tools: Any, **kwargs: Any) -> FakeModel:
        return self


def model(*calls: list[tuple[str, dict[str, Any]]]) -> FakeModel:
    """One AI message per turn, each with its tool calls, then a final answer."""
    msgs = [
        AIMessage(
            "",
            tool_calls=[
                {"name": n, "args": a, "id": f"call_{t}_{i}"} for i, (n, a) in enumerate(c)
            ],
        )
        for t, c in enumerate(calls)
    ]
    return FakeModel(messages=iter([*msgs, AIMessage("done")]))


ran: list[str] = []


@tool
def issue_refund(charge: str, amount: int) -> str:
    """Refund a charge."""
    if amount > 50:
        raise Refused("over the automatic limit")
    ran.append(charge)
    return "refunded"


@tool
def lookup(order: str) -> str:
    """Look an order up."""
    ran.append(order)
    return "shipped"


@tool
def explode(x: int) -> str:
    """Always fails."""
    raise RuntimeError("boom")


@tool
def handled(x: int) -> str:
    """Fails, and says so to the model."""
    raise ToolException("unavailable")


handled.handle_tool_error = True


def msg(text: str) -> dict[str, Any]:
    return {"messages": [("user", text)]}


@pytest.fixture(autouse=True)
def _clear() -> None:
    ran.clear()


@pytest.fixture
def log(tmp_path: Path) -> Tenbri:
    keys = tmp_path / "keys"
    s = Tenbri.open(tmp_path / "s", keys=keys, create=True, digest_key=DIGEST_KEY)
    yield s
    s.close()


def decisions(log: Tenbri) -> list[dict[str, Any]]:
    log.flush()
    return [m.entry for m in log.query() if m.entry["kind"] in ("decision", "approval", "note")]


def outcomes(log: Tenbri) -> dict[str, str]:
    return {e["action"]["type"]: e["status"] for e in decisions(log) if e.get("phase") == "outcome"}


def test_allowed_refused_error(log: Tenbri) -> None:
    h = TenbriCallbackHandler(log, target=lambda t, a: f"stripe:{a.get('charge')}")
    config: Any = {"callbacks": [h]}
    ok = [("issue_refund", {"charge": "ch_1", "amount": 20})]
    create_agent(model(ok), [issue_refund], name="support").invoke(msg("refund"), config)
    # Refused by the tool's own policy, and a crash in the tool: both reach the caller.
    no = [("issue_refund", {"charge": "ch_2", "amount": 90})]
    with pytest.raises(Refused):
        create_agent(model(no), [issue_refund], name="support").invoke(msg("refund"), config)
    with pytest.raises(RuntimeError):
        create_agent(model([("explode", {"x": 1})]), [explode], name="support").invoke(
            msg("x"), config
        )
    # An error the tool handles itself (handle_tool_error) is an error too.
    create_agent(model([("handled", {"x": 1})]), [handled], name="support").invoke(msg("x"), config)

    es = decisions(log)
    assert [(e["phase"], e["action"]["type"], e.get("status")) for e in es] == [
        ("intent", "issue_refund", None),
        ("outcome", "issue_refund", "ok"),
        ("intent", "issue_refund", None),
        ("outcome", "issue_refund", "refused"),
        ("intent", "explode", None),
        ("outcome", "explode", "error"),
        ("intent", "handled", None),
        ("outcome", "handled", "error"),
    ]
    intent = es[0]
    assert intent["principal"] == {"kind": "agent", "id": "support"}
    assert intent["action"]["target"] == "stripe:ch_1"
    assert intent["ext"]["langchain"]["tool_call_id"] == "call_0_0"
    # The arguments are pinned as a keyed digest and never stored.
    [pin] = intent["inputs"]
    assert pin["ref"] == "langchain:tool_call/call_0_0" and pin["digest"].startswith("hmac-sha256:")
    assert "ch_1" not in str({k: v for k, v in intent.items() if k != "action"})
    assert ran == ["ch_1"]
    assert log.verify(log.fingerprint).ok


def test_crash_mid_action_leaves_the_intent(tmp_path: Path) -> None:
    """The process dies inside the tool: the intent is durable, there is no outcome, the stream
    verifies, and the next writer reconciles it."""
    script = textwrap.dedent(
        f"""
        import os, sys
        sys.path.insert(0, {str(Path(__file__).parent)!r})
        from test_langgraph import FakeModel, model
        from langchain.agents import create_agent
        from langchain_core.tools import ToolException, tool
        from tenbri import Tenbri
        from tenbri_langgraph import TenbriCallbackHandler

        @tool
        def deploy(env: str) -> str:
            \"\"\"Deploy.\"\"\"
            os._exit(3)

        log = Tenbri.open({str(tmp_path / "s")!r}, keys={str(tmp_path / "keys")!r}, create=True)
        agent = create_agent(model([("deploy", {{"env": "prod"}})]), [deploy])
        agent.invoke({{"messages": [("user", "go")]}}, {{"callbacks": [TenbriCallbackHandler(log)]}})
        """
    )
    p = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True)
    assert p.returncode == 3, p.stderr
    log = Tenbri.open(tmp_path / "s", keys=tmp_path / "keys")
    es = decisions(log)
    assert [(e["phase"], e["action"]["type"]) for e in es] == [("intent", "deploy")]
    assert log.verify(log.fingerprint).ok


def test_fail_closed_and_open(tmp_path: Path) -> None:
    Tenbri.open(tmp_path / "s", keys=tmp_path / "keys", create=True).close()
    read_only = Tenbri.open(tmp_path / "s", keys=tmp_path / "elsewhere")
    calls = [("lookup", {"order": "o1"})]

    agent = create_agent(model(calls), [lookup])
    with pytest.raises(NoSessionKeyError):
        agent.invoke(
            {"messages": [("user", "x")]}, {"callbacks": [TenbriCallbackHandler(read_only)]}
        )
    assert ran == []

    agent = create_agent(model(calls), [lookup])
    h = TenbriCallbackHandler(read_only, fail_open=True)
    agent.invoke({"messages": [("user", "x")]}, {"callbacks": [h]})
    assert ran == ["o1"]


def test_tool_selection_and_inputs(log: Tenbri) -> None:
    calls = [("lookup", {"order": "o1"}), ("issue_refund", {"charge": "ch_1", "amount": 5})]
    agent = create_agent(model(calls), [lookup, issue_refund])
    h = TenbriCallbackHandler(
        log,
        principal="agent:billing",
        tools=["issue_refund"],
        inputs=lambda t, a: [("policy:refund", "14", b"refunds under 50 EUR are automatic")],
    )
    agent.invoke({"messages": [("user", "x")]}, {"callbacks": [h]})
    es = decisions(log)
    assert {e["action"]["type"] for e in es} == {"issue_refund"}
    assert es[0]["principal"] == {"kind": "agent", "id": "billing"}
    assert [i["ref"] for i in es[0]["inputs"]] == ["policy:refund", "langchain:tool_call/call_0_1"]
    assert [m.entry["phase"] for m in log.query(inputs=["policy:refund@14"])] == ["intent"]
    assert sorted(ran) == ["ch_1", "o1"]


@pytest.mark.parametrize("mode", ["batched", "per_call"])
def test_human_approval(log: Tenbri, mode: str) -> None:
    calls = [
        ("issue_refund", {"charge": "ch_1", "amount": 20}),
        ("issue_refund", {"charge": "ch_2", "amount": 30}),
    ]
    if (
        mode == "per_call"
        and "interrupt_mode" not in inspect.signature(HumanInTheLoopMiddleware).parameters
    ):
        pytest.skip("per_call HITL is new in langchain 1.4")
    kw = {} if mode == "batched" else {"interrupt_mode": mode}
    hitl = HumanInTheLoopMiddleware(interrupt_on={"issue_refund": True}, **kw)
    agent = create_agent(
        model(calls),
        [issue_refund],
        middleware=[hitl],
        checkpointer=InMemorySaver(),
        name="support",
    )
    h = TenbriCallbackHandler(log)
    config = {"callbacks": [h], "configurable": {"thread_id": "t1"}}
    agent.invoke({"messages": [("user", "refund both")]}, config)
    assert decisions(log) == []  # paused before either call

    approve, reject = {"type": "approve"}, {"type": "reject", "message": "no"}
    if mode == "batched":
        answer: Any = {"decisions": [approve, reject]}
    else:
        ids = [i.id for i in agent.get_state(config).interrupts]
        answer = dict(zip(ids, [approve, reject]))
    agent.invoke(h.resume(agent, config, answer, by="person:alice"), config)

    es = decisions(log)
    approval = next(e for e in es if e["kind"] == "approval")
    assert approval["principal"] == {"kind": "person", "id": "alice"}
    assert approval["ext"]["langchain"]["tool_call_id"] == "call_0_0"
    assert approval["ext"]["langchain"]["thread_id"] == "t1"
    intent = next(e for e in es if e.get("phase") == "intent" and "approval" in e)
    assert intent["ext"]["langchain"]["tool_call_id"] == "call_0_0"
    assert intent["approval"]["by"] == {"kind": "person", "id": "alice"}
    refused = [e for e in es if e.get("status") == "refused"]
    assert len(refused) == 1 and refused[0]["principal"] == {"kind": "agent", "id": "support"}
    rejected = next(e for e in es if e.get("ext", {}).get("langchain", {}).get("decision"))
    assert rejected["ext"]["langchain"]["reviewer"] == "person:alice"
    assert ran == ["ch_1"]
    assert log.verify(log.fingerprint).ok  # approval.entry names the approval: verified


def test_trace_from_opentelemetry(log: Tenbri) -> None:
    from opentelemetry.sdk.trace import TracerProvider

    tracer = TracerProvider().get_tracer("test")
    agent = create_agent(model([("lookup", {"order": "o1"})]), [lookup])
    with tracer.start_as_current_span("request") as span:
        agent.invoke({"messages": [("user", "x")]}, {"callbacks": [TenbriCallbackHandler(log)]})
    assert decisions(log)[0]["trace"]["trace_id"] == format(
        span.get_span_context().trace_id, "032x"
    )


def test_async_agent(log: Tenbri) -> None:
    agent = create_agent(model([("lookup", {"order": "o1"})]), [lookup])
    run = agent.ainvoke({"messages": [("user", "x")]}, {"callbacks": [TenbriCallbackHandler(log)]})
    asyncio.run(run)
    assert outcomes(log) == {"lookup": "ok"}
