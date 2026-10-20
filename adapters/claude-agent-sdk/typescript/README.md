# @tenbri/claude-agent-sdk

[Tenbri](https://github.com/tenbri/tenbri) for the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk):
every tool call your agent makes becomes a signed, chained decision in a Tenbri stream.

```sh
npm install @tenbri/claude-agent-sdk tenbri@next @anthropic-ai/claude-agent-sdk
```

```ts
import { query } from '@anthropic-ai/claude-agent-sdk'
import { init } from 'tenbri'
import { instrumentClaudeAgentSdk } from '@tenbri/claude-agent-sdk'

init() // TENBRI_STREAM=./audit/support TENBRI_AGENT=agent:support TENBRI_APPROVER=person:alice
for await (const message of query({ prompt, options: instrumentClaudeAgentSdk({ canUseTool: askAHuman }) })) {
  // ...
}
```

`instrumentClaudeAgentSdk(options)` returns your options with Tenbri's hooks next to yours and
your `canUseTool` wrapped. (The Python package patches the SDK instead; an ES module's exports
cannot be.) `init()` creates the stream and its keys on first use and flushes before the process exits; see
the [tenbri package](../../../bindings/node) for its settings and `decision()` for your own
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
last `__` part, so the MCP tool `mcp__billing__issue_refund` is `issue_refund`. A plain object in
code says the same, and wins:

```ts
instrumentClaudeAgentSdk(options, {
  actions: { issue_refund: { target: 'stripe:{charge}', policy: 'policy:refund@14' } },
})
```

File and web tools with no action record their path or URL as the target.

## Approvals

A tool your `canUseTool` allows is recorded as approved by `TENBRI_APPROVER` (or
`init({ approver })`, or the `approver` option: a principal, or a function of the call returning
one). With no approver, an allowance is your own code's decision and no approval entry is written.
Who acts is `TENBRI_AGENT`, or the `agent('agent:...', fn)` scope `instrumentClaudeAgentSdk` is
called in, or the `agent` option.

## Advanced: `TenbriHooks`

`instrumentClaudeAgentSdk` is built on `TenbriHooks`, one session's hooks on a stream you opened. What it records,
below, is what the one-liner records.

```ts
import { query } from '@anthropic-ai/claude-agent-sdk'
import { Tenbri } from 'tenbri'
import { TenbriHooks } from '@tenbri/claude-agent-sdk'

const log = await Tenbri.open('./audit/support', { create: true })
const options = new TenbriHooks(log, { principal: 'agent:support', approver: 'person:alice' }).instrument({
  canUseTool: askAHuman,
})
for await (const message of query({ prompt: prompt(), options })) {
  // ...
}
```

### What is recorded

| SDK event | Entry |
| --- | --- |
| `PreToolUse` | An **intent**: principal = your agent, `action.type` = the tool name, `action.target` from the tool input (file path, URL), the input pinned by its keyed digest. Durable before the tool runs. |
| `canUseTool` allows, with an `approver` | An **approval** by that person, for the same action |
| `PostToolUse` | Outcome `ok`, naming the approval if there was one |
| `PostToolUseFailure` | Outcome `error`; `unknown` when interrupted |
| `canUseTool` denies, or `PermissionDenied` | Outcome `refused` |

Each entry carries the `trace` of the active OpenTelemetry span (install `@opentelemetry/api` and a
context manager). An intent left open (the process died mid-action) is reconciled as `unknown` by
the next writer.

Nothing of the prompt, the tool input or the tool output is stored: the input is pinned by its
keyed digest (`claude:tool_input@<toolUseID>`), keyed by the stream's local key store, so
whoever holds the input and the key can prove what the agent sent.

### Options

- `tools`: names to record, or a predicate of the name. All by default.
- `describe(tool, input)`: the intent's fields: `target`, `inputs` (what the call read,
  `{ref, version, digest}`), `rule`, `subject`, or `action` to rename it. The default records the
  target of file and web tools.
- `approver`: who approves through `canUseTool`, a principal or a function of the call returning
  one; none (the default) when your own code decides and no person approves.
- `failOpen`: by default the adapter **fails closed**: a tool whose intent is not durable within
  `timeout` ms (default 2000) is denied. With `failOpen: true` it runs anyway, unrecorded, with a
  warning.

`instrument` adds its hooks next to yours and wraps your `canUseTool`, which needs a streamed
prompt (an async iterable), as the SDK requires. See
[examples/refund-agent.ts](examples/refund-agent.ts).
