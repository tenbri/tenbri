"""The adapter under the real claude_agent_sdk, its CLI replaced by testing/fake-claude.mjs: no model,
no API key. Each test plays tool calls through the SDK and reads back what the stream holds."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from claude_agent_sdk import (
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    ToolPermissionContext,
    query,
)
from opentelemetry import trace
from tenbri import AsyncTenbri

from tenbri_claude_agent_sdk import TenbriHooks, entry_hash

FAKE = Path(__file__).resolve().parents[2] / "testing" / "fake-claude.mjs"
KEY = b"k" * 32


async def _prompt() -> AsyncIterator[dict[str, Any]]:
    # can_use_tool needs a streamed prompt.
    yield {"type": "user", "message": {"role": "user", "content": "go"}}


async def session(
    log: AsyncTenbri, calls: list[dict[str, Any]], *, can_use_tool: Any = None, **kw: Any
) -> dict[str, Any]:
    """Plays ``calls``; returns the SDK's answers per call id (``crashed`` if the CLI died)."""
    options = ClaudeAgentOptions(
        cli_path=str(FAKE),
        env={"FAKE_CLAUDE_SCENARIO": json.dumps(calls)},
        can_use_tool=can_use_tool,
    )
    options = TenbriHooks(log, "agent:support", **kw).instrument(options)
    answers: dict[str, Any] = {"crashed": False}
    try:
        async for m in query(prompt=_prompt(), options=options):
            if isinstance(m, ResultMessage) and m.result:
                answers.update({a["id"]: a for a in json.loads(m.result)})
    except Exception:
        answers["crashed"] = True
    return answers


async def entries(log: AsyncTenbri) -> list[dict[str, Any]]:
    return [m.entry for m in await log.query() if m.entry["kind"] in ("decision", "approval")]


async def open_log(tmp: Path, **kw: Any) -> AsyncTenbri:
    return await AsyncTenbri.open(tmp / "stream", keys=tmp / "keys", create=True, **kw)


def test_allowed_refused_and_crashed(tmp_path: Path) -> None:
    """The conformance scenario: one call allowed (by a person), one refused, one crash mid-action."""

    async def ask(tool: str, _: dict[str, Any], ctx: ToolPermissionContext) -> Any:
        return PermissionResultDeny(message="no") if tool == "Bash" else PermissionResultAllow()

    async def main() -> None:
        log = await open_log(tmp_path)
        calls: list[dict[str, Any]] = [
            {"tool": "Read", "input": {"file_path": "/srv/policy.md"}, "id": "t1", "ask": True, "result": "ok"},
            {"tool": "Bash", "input": {"command": "rm -rf /"}, "id": "t2", "ask": True, "result": "ok"},
            {"tool": "Write", "input": {"file_path": "/srv/out"}, "id": "t3", "result": "crash"},
        ]
        answers = await session(log, calls, can_use_tool=ask, approver="person:alice")
        assert answers["crashed"]
        e = await entries(log)
        assert [(x["kind"], x.get("phase"), x.get("status")) for x in e] == [
            ("decision", "intent", None),
            ("approval", None, None),
            ("decision", "outcome", "ok"),
            ("decision", "intent", None),
            ("decision", "outcome", "refused"),
            ("decision", "intent", None),
        ]
        read, approval, ok, bash, refused, write = e
        assert read["principal"] == {"kind": "agent", "id": "support"}
        assert read["action"] == {"type": "Read", "target": "/srv/policy.md"}
        assert approval["principal"] == {"kind": "person", "id": "alice"}
        assert ok["intent"] == read["id"]
        assert ok["approval"] == {"by": approval["principal"], "entry": entry_hash(approval)}
        assert bash["action"] == {"type": "Bash"}  # the command is not stored
        assert refused["intent"] == bash["id"]
        assert write["action"]["type"] == "Write"  # open: reconciled as unknown later
        assert (await log.verify(log.fingerprint)).ok

    asyncio.run(main())


def test_error_interrupt_and_denial_by_rule(tmp_path: Path) -> None:
    async def main() -> None:
        log = await open_log(tmp_path)
        calls = [
            {"tool": "WebFetch", "input": {"url": "https://x.test"}, "id": "e", "result": "error"},
            {"tool": "Bash", "input": {"command": "sleep 9"}, "id": "i", "result": "interrupt"},
            {"tool": "Edit", "input": {"file_path": "/etc/hosts"}, "id": "d", "result": "denied"},
        ]
        await session(log, calls)
        outcomes = [x["status"] for x in await entries(log) if x.get("phase") == "outcome"]
        assert outcomes == ["error", "unknown", "refused"]

    asyncio.run(main())


def test_selection_mapping_and_pinned_inputs(tmp_path: Path) -> None:
    def describe(tool: str, tool_input: dict[str, Any]) -> dict[str, Any]:
        return {
            "action": "issue_refund",
            "target": f"stripe:{tool_input['charge']}",
            "rule": {"ref": "policy:refund", "version": "14", "result": "allow"},
        }

    async def main() -> None:
        log = await open_log(tmp_path, digest_key=KEY)
        tool_input = {"charge": "ch_1", "amount": 20}
        calls = [
            {"tool": "mcp__stripe__refund", "input": tool_input, "id": "r", "result": "ok"},
            {"tool": "Read", "input": {"file_path": "/a"}, "id": "s", "result": "ok"},
        ]
        await session(log, calls, tools=["mcp__stripe__refund"], describe=describe)
        intent, outcome = await entries(log)  # Read is not selected
        assert intent["action"] == {"type": "issue_refund", "target": "stripe:ch_1"}
        assert intent["rule"]["version"] == "14"
        digest = log.digest(json.dumps(tool_input, sort_keys=True, separators=(",", ":")))
        assert intent["inputs"] == [{"ref": "claude:tool_input", "version": "r", "digest": digest}]
        assert outcome["status"] == "ok"
        found = await log.query(inputs=["claude:tool_input@r"])
        assert [m.entry["id"] for m in found] == [intent["id"]]

    asyncio.run(main())


@pytest.mark.parametrize("fail_open", [False, True])
def test_fail_closed_by_default(tmp_path: Path, fail_open: bool) -> None:
    async def main() -> None:
        log = await open_log(tmp_path)
        await log.close()  # nothing can be written
        calls = [{"tool": "Bash", "input": {"command": "ls"}, "id": "b", "result": "ok"}]
        answers = await session(log, calls, fail_open=fail_open)
        decision = answers["b"]["pre"][0]["response"].get("hookSpecificOutput", {})
        assert (decision.get("permissionDecision") == "deny") is not fail_open
        assert ("post" in answers["b"]) is fail_open  # the tool ran

    asyncio.run(main())


def test_trace_of_the_active_span(tmp_path: Path) -> None:
    ctx = trace.SpanContext(0xABC, 0xDEF, is_remote=False, trace_flags=trace.TraceFlags(1))

    async def main() -> None:
        log = await open_log(tmp_path)
        with trace.use_span(trace.NonRecordingSpan(ctx)):
            await session(log, [{"tool": "Read", "input": {}, "id": "t", "result": "ok"}])
        e = await entries(log)
        assert len(e) == 2
        for x in e:
            assert x["trace"] == {"trace_id": f"{0xABC:032x}", "span_id": f"{0xDEF:016x}"}

    asyncio.run(main())


def test_instrument_one_liner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """tenbri.init() and tenbri.instrument_claude_agent_sdk(): the stream, principal, approver and
    action mapping from the environment and tenbri.toml, and plain SDK code after that."""
    import tenbri
    from claude_agent_sdk import ClaudeSDKClient

    from tenbri_claude_agent_sdk import uninstrument

    (tmp_path / "tenbri.toml").write_text(
        '[actions.issue_refund]\ntarget = "stripe:{charge}"\npolicy = "policy:refund@14"\n'
    )
    monkeypatch.setenv("TENBRI_STREAM", str(tmp_path / "stream"))
    monkeypatch.setenv("TENBRI_KEYS", str(tmp_path / "keys"))
    monkeypatch.setenv("TENBRI_AGENT", "agent:support")
    monkeypatch.setenv("TENBRI_APPROVER", "person:alice")
    monkeypatch.setenv("TENBRI_SCHEMA", str(tmp_path / "tenbri.toml"))

    async def ask(tool: str, _: dict[str, Any], ctx: ToolPermissionContext) -> Any:
        return PermissionResultAllow()

    def options(calls: list[dict[str, Any]]) -> ClaudeAgentOptions:
        env = {"FAKE_CLAUDE_SCENARIO": json.dumps(calls)}
        return ClaudeAgentOptions(cli_path=str(FAKE), env=env, can_use_tool=ask)

    refund = {"charge": "ch_1", "amount": 20}
    calls = [{"tool": "mcp__billing__issue_refund", "input": refund, "id": "r", "ask": True, "result": "ok"}]

    async def main() -> list[dict[str, Any]]:
        log = tenbri.init()
        tenbri.instrument_claude_agent_sdk()
        try:
            async for _ in query(prompt=_prompt(), options=options(calls)):
                pass
            with tenbri.agent("agent:triage"):
                client = ClaudeSDKClient(options([{"tool": "Read", "input": {"file_path": "/a"}, "id": "c", "result": "ok"}]))
            async with client:
                await client.query("go")
                async for _ in client.receive_response():
                    pass
        finally:
            uninstrument()
        async for _ in query(prompt=_prompt(), options=options(calls)):
            pass  # not recorded any more
        return await entries(log.aio)

    try:
        intent, approval, outcome, read, read_ok = asyncio.run(main())
    finally:
        tenbri.default().close()
    assert intent["principal"] == {"kind": "agent", "id": "support"}
    assert intent["action"] == {"type": "issue_refund", "target": "stripe:ch_1"}
    assert intent["rule"] == {"ref": "policy:refund", "version": "14", "result": "allow"}
    # The tool input is pinned by its digest, keyed by the local key store.
    assert [i["ref"] for i in intent["inputs"]] == ["claude:tool_input"]
    assert approval["principal"] == {"kind": "person", "id": "alice"}
    assert outcome["status"] == "ok" and outcome["approval"]["entry"] == entry_hash(approval)
    assert read["principal"] == {"kind": "agent", "id": "triage"}
    assert read["action"] == {"type": "Read", "target": "/a"} and read_ok["status"] == "ok"
