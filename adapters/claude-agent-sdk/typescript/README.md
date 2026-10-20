# @tenbri/claude-agent-sdk

[Tenbri](https://github.com/tenbri/tenbri) for the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk):
every tool call your agent makes becomes a signed, chained decision in a Tenbri stream. One line at
agent setup.

```sh
npm install @tenbri/claude-agent-sdk@next tenbri@next @anthropic-ai/claude-agent-sdk
```

```ts
import { query } from '@anthropic-ai/claude-agent-sdk'
import { Tenbri } from 'tenbri'
import { TenbriHooks } from '@tenbri/claude-agent-sdk'

const log = await Tenbri.open('./audit/support', { create: true, digestKey: process.env.TENBRI_DIGEST_KEY })
const options = new TenbriHooks(log, { principal: 'agent:support', approver: 'person:alice' }).instrument({
  canUseTool: askAHuman,
})
for await (const message of query({ prompt: prompt(), options })) {
  // ...
}
```

## What is recorded

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
keyed digest (`claude:tool_input@<toolUseID>`) when the stream was opened with a `digestKey`, so
whoever holds the input and the key can prove what the agent sent.

## Options

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
