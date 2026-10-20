# tenbri-claude-agent-sdk

[Tenbri](https://github.com/tenbri/tenbri) for the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk):
every tool call your agent makes becomes a signed, chained decision in a Tenbri stream. One line at
agent setup.

```sh
pip install --pre tenbri-claude-agent-sdk
```

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from tenbri import AsyncTenbri
from tenbri_claude_agent_sdk import TenbriHooks

log = await AsyncTenbri.open("./audit/support", create=True, digest_key=b"a 32-byte secret, kept apart....")
options = TenbriHooks(log, "agent:support", approver="person:alice").instrument(
    ClaudeAgentOptions(can_use_tool=ask_a_human)
)
async for message in query(prompt=prompt(), options=options):
    ...
```

## What is recorded

| SDK event | Entry |
| --- | --- |
| `PreToolUse` | An **intent**: principal = your agent, `action.type` = the tool name, `action.target` from the tool input (file path, URL), the input pinned by its keyed digest. Durable before the tool runs. |
| `can_use_tool` allows, with an `approver` | An **approval** by that person, for the same action |
| `PostToolUse` | Outcome `ok`, naming the approval if there was one |
| `PostToolUseFailure` | Outcome `error`; `unknown` when interrupted |
| `can_use_tool` denies, or `PermissionDenied` | Outcome `refused` |

Each entry carries the `trace` of the active OpenTelemetry span (install `opentelemetry-api`). An
intent left open (the process died mid-action) is reconciled as `unknown` by the next writer.

Nothing of the prompt, the tool input or the tool output is stored: the input is pinned by its
keyed digest (`claude:tool_input@<tool_use_id>`) when the stream was opened with a `digest_key`,
so whoever holds the input and the key can prove what the agent sent.

## Options

- `tools`: names to record, or a predicate of the name. All by default.
- `describe(tool, tool_input)`: the intent's fields: `target`, `inputs` (what the call read,
  `{ref, version, digest}`), `rule`, `subject`, or `action` to rename it. The default records the
  target of file and web tools.
- `approver`: who approves through `can_use_tool`, a principal or a function of
  `(tool, tool_input, context)` returning one; `None` (the default) when your own code decides and
  no person approves.
- `fail_open`: by default the adapter **fails closed**: a tool whose intent is not durable within
  `timeout` seconds (default 2) is denied. With `fail_open=True` it runs anyway, unrecorded, and a
  warning is logged.

`TenbriHooks` adds its hooks next to yours and wraps your `can_use_tool`; `can_use_tool` itself
needs a streamed prompt (an async iterable), as the SDK requires. See
[examples/refund_agent.py](examples/refund_agent.py).
