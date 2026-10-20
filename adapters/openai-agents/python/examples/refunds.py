"""A support agent whose refunds are recorded in a Tenbri stream, approvals included.

    pip install tenbri-openai-agents
    python examples/refunds.py ./audit

With OPENAI_API_KEY set it asks the model; without, a scripted model plays the same turns, so the
example runs anywhere. Then `tenbri verify ./audit --key <fingerprint>` checks the record.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from agents import Agent, Runner, function_tool, set_trace_processors
from agents.items import ModelResponse
from agents.models.interface import Model
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText
from tenbri import AsyncTenbri

from tenbri_openai_agents import TenbriRecorder

POLICY = "Refunds up to 50 EUR are automatic; above that a person approves."


async def over_50(ctx: Any, args: dict[str, Any], call_id: str) -> bool:
    return bool(args["amount"] > 50)


@function_tool(needs_approval=over_50)
def issue_refund(charge: str, amount: int) -> str:
    """Refunds `amount` EUR on the card charge `charge`."""
    return f"refunded {amount} EUR on {charge}"


class Scripted(Model):
    """Stands in for the model when there is no API key: two refunds, then a reply."""

    def __init__(self) -> None:
        refunds = (("c1", {"charge": "ch_1", "amount": 20}), ("c2", {"charge": "ch_2", "amount": 80}))
        reply = ResponseOutputText(text="Both refunds are done.", type="output_text", annotations=[])
        self.turns: list[list[Any]] = [
            [
                ResponseFunctionToolCall(
                    id=c, call_id=c, type="function_call", name="issue_refund", arguments=json.dumps(a)
                )
                for c, a in refunds
            ],
            [ResponseOutputMessage(id="m", type="message", role="assistant", status="completed", content=[reply])],
        ]

    async def get_response(self, *args: Any, **kwargs: Any) -> ModelResponse:
        return ModelResponse(output=self.turns.pop(0), usage=Usage(), response_id=None)

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


async def main(path: str) -> None:
    # A real deployment keeps the digest key in its secret store.
    log = await AsyncTenbri.open(path, create=True, digest_key=b"example digest key")
    if not os.environ.get("OPENAI_API_KEY"):
        set_trace_processors([])  # nowhere to export traces to; entries still carry their ids
    agent = Agent(
        name="support-assistant",
        instructions=f"You handle refunds. Policy: {POLICY}",
        tools=[issue_refund],
        model=None if os.environ.get("OPENAI_API_KEY") else Scripted(),
    )
    recorder = TenbriRecorder(log, target=lambda tool, args: f"stripe:{args.get('charge')}")
    recorder.read("policy:refund", "14", POLICY)

    async with recorder:
        run_config = recorder.run_config()
        result = await Runner.run(
            agent, "Refund 20 EUR on ch_1 and 80 EUR on ch_2.", hooks=recorder, run_config=run_config
        )
        while result.interruptions:
            state = result.to_state()
            for item in result.interruptions:
                await recorder.approve(state, item, "person:alice")  # a person said yes
            result = await Runner.run(agent, state, hooks=recorder, run_config=run_config)

    for m in await log.query():
        e = m.entry
        who = e.get("principal", {})
        print(e["seq"], e["kind"], e.get("phase", ""), e.get("status", ""),
              f"{who.get('kind', '')}:{who.get('id', '')}", e.get("action", {}))
    report = await log.verify(log.fingerprint)
    print("verified" if report.ok else f"broken: {report.broken}", "- key", log.fingerprint)
    await log.close()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "./audit"))
