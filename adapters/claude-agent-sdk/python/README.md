# tenbri-claude-agent-sdk

[Tenbri](https://github.com/tenbri/tenbri) for the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk):
every tool call your agent makes becomes a signed, chained decision in a Tenbri stream.

```sh
pip install --pre tenbri-claude-agent-sdk
```

```python
import tenbri

tenbri.init()  # TENBRI_STREAM=./audit/support TENBRI_AGENT=agent:support TENBRI_APPROVER=person:alice
tenbri.instrument_claude_agent_sdk()
```

From then on every `query()` and `ClaudeSDKClient` session the process starts is recorded, with no
change to your options: Tenbri's hooks go next to yours and your `can_use_tool` is wrapped.
`tenbri.init()` creates the stream and its keys on first use and flushes at exit; see the
[tenbri package](../../../bindings/python) for its settings and `@tenbri.decision` for your own
functions.

## Which action, which target, which policy

A tool call is the action of the tool's name. Declare the action in `tenbri.toml` (the action
schemas tenbrid and `tenbri schema check` validate against) and the record takes its target and
rule from there, filled from the tool's arguments:

```toml
[actions.issue_refund]
target = "stripe:{charge}"      # each {argument} is filled from the call; validated as *
policy = "policy:refund@14"     # the rule that allowed it: ref@version
```

`init()` reads `./tenbri.toml` (or `TENBRI_SCHEMA`). A tool matches an action by its name or its
last `__` part, so the MCP tool `mcp__billing__issue_refund` is `issue_refund`. A plain dict in
code says the same, and wins:

```python
tenbri.instrument_claude_agent_sdk(
    actions={"issue_refund": {"target": "stripe:{charge}", "policy": "policy:refund@14"}}
)
```

File and web tools with no action record their path or URL as the target.

## Approvals

A tool your `can_use_tool` allows is recorded as approved by `TENBRI_APPROVER` (or
`init(approver=...)`, or `instrument_claude_agent_sdk(approver=...)`: a principal, or a function of
`(tool, tool_input, context)` returning one). With no approver, an allowance is your own code's
decision and no approval entry is written. Who acts is `TENBRI_AGENT`, or the innermost
`with tenbri.agent("agent:..."):` around the session's start, or `agent=`.

## Advanced: `TenbriHooks`

The one-liner is built on `TenbriHooks`, one session's hooks on a stream you opened. Use it to
record some sessions and not others, or to see every option. What it records,
below, is what the one-liner records.

```python
from claude_agent_sdk import ClaudeAgentOptions, query
from tenbri import AsyncTenbri
from tenbri_claude_agent_sdk import TenbriHooks

log = await AsyncTenbri.open("./audit/support", create=True)
options = TenbriHooks(log, "agent:support", approver="person:alice").instrument(
    ClaudeAgentOptions(can_use_tool=ask_a_human)
)
async for message in query(prompt=prompt(), options=options):
    ...
```

### What is recorded

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
keyed digest (`claude:tool_input@<tool_use_id>`), keyed by the stream's local key store,
so whoever holds the input and the key can prove what the agent sent.

### Options

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
