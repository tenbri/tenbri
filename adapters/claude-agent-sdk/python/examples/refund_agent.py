"""A support agent that can issue refunds, every tool call recorded in a Tenbri stream.

    pip install --pre tenbri-claude-agent-sdk
    export ANTHROPIC_API_KEY=...
    python refund_agent.py

The refund tool asks you first (``can_use_tool``); your answer is recorded as an approval by
``person:$USER``. Then the stream is verified and its decisions listed.
"""

from __future__ import annotations

import asyncio
import getpass
from collections.abc import AsyncIterator
from typing import Any

import tenbri
from claude_agent_sdk import (
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ToolPermissionContext,
    create_sdk_mcp_server,
    query,
    tool,
)

tenbri.init("./audit/support", agent="agent:support", approver=f"person:{getpass.getuser()}")
tenbri.instrument_claude_agent_sdk(
    actions={"issue_refund": {"target": "stripe:{charge}", "policy": "policy:refund@14"}}
)


@tool("issue_refund", "Refund a Stripe charge", {"charge": str, "amount_eur": int})
async def issue_refund(args: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": f"refunded {args['amount_eur']} EUR"}]}


async def ask(tool: str, tool_input: dict[str, Any], _: ToolPermissionContext) -> Any:
    answer = await asyncio.to_thread(input, f"Allow {tool} {tool_input}? [y/N] ")
    return PermissionResultAllow() if answer.lower() == "y" else PermissionResultDeny(message="no")


async def prompt() -> AsyncIterator[dict[str, Any]]:
    content = "Ticket 4512: the customer was charged twice (ch_123, 30 EUR). Refund the duplicate."
    yield {"type": "user", "message": {"role": "user", "content": content}}


async def main() -> None:
    options = ClaudeAgentOptions(
        mcp_servers={"billing": create_sdk_mcp_server("billing", tools=[issue_refund])},
        tools=[],  # no built-in tools: only the refund, which asks first
        can_use_tool=ask,
    )
    async for message in query(prompt=prompt(), options=options):
        print(type(message).__name__)

    log = tenbri.default()
    print("verified:", log.verify(log.fingerprint).ok)
    for m in log.query(action="issue_refund"):
        e = m.entry
        print(e["seq"], e.get("phase"), e.get("status", ""), e["action"], e.get("approval", ""))


if __name__ == "__main__":
    asyncio.run(main())
