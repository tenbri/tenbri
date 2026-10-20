"""A support agent that refunds charges, recorded in Tenbri: one refund under the policy limit,
one a person reviews and approves first. Runs offline with a scripted model; swap in a real one
(``init_chat_model("anthropic:claude-sonnet-5-5")``) and nothing else changes.

    pip install --pre tenbri-langgraph langchain
    python refund_agent.py
"""

from __future__ import annotations

import tempfile
from typing import Any

import tenbri

from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command
from tenbri import Refused


@tool
def issue_refund(charge: str, amount: int) -> str:
    """Refund `amount` EUR of a charge."""
    if amount > 500:
        raise Refused("over the refund ceiling")
    return f"refunded {amount} EUR of {charge}"


class Scripted(GenericFakeChatModel):
    def bind_tools(self, tools: Any, **kwargs: Any) -> Scripted:
        return self


def call(id: str, charge: str, amount: int) -> AIMessage:
    return AIMessage(
        "",
        tool_calls=[
            {"name": "issue_refund", "id": id, "args": {"charge": charge, "amount": amount}}
        ],
    )


model = Scripted(
    messages=iter(
        [
            call("c1", "ch_1", 20),
            AIMessage("Refunded."),
            call("c2", "ch_2", 120),
            AIMessage("Refunded."),
        ]
    )
)

with tempfile.TemporaryDirectory() as d:
    log = tenbri.init(f"{d}/support", keys=f"{d}/keys", approver="person:alice")
    tenbri.instrument_langchain(
        actions={"issue_refund": {"target": "stripe:{charge}", "policy": "policy:refund@14"}}
    )
    agent = create_agent(
        model,
        [issue_refund],
        name="support",
        # Refunds over 50 EUR wait for a person.
        middleware=[
            HumanInTheLoopMiddleware(
                interrupt_on={
                    "issue_refund": {
                        "allowed_decisions": ["approve", "reject"],
                        "when": lambda r: r.tool_call["args"]["amount"] > 50,
                    }
                }
            )
        ],
        checkpointer=InMemorySaver(),
    )
    config: Any = {"configurable": {"thread_id": "ticket-42"}}

    agent.invoke({"messages": [("user", "Refund 20 EUR of ch_1")]}, config)
    agent.invoke({"messages": [("user", "Refund 120 EUR of ch_2")]}, config)
    print(
        "waiting for a person:",
        [i.value["action_requests"] for i in agent.get_state(config).interrupts],
    )
    # Recorded as an approval by person:alice.
    agent.invoke(Command(resume={"decisions": [{"type": "approve"}]}), config)

    for m in log.query():
        e = m.entry
        if e["kind"] in ("decision", "approval"):
            who = f"{e['principal']['kind']}:{e['principal']['id']}"
            print(
                f"{e['seq']:>2} {e['kind']:<8} {e.get('phase', ''):<7} {e.get('status', ''):<7} {who:<14} {e['action']['target']}"
            )
    report = log.verify(log.fingerprint)
    print("verified:", report.ok, f"({report.entries} entries)")
    log.close()
