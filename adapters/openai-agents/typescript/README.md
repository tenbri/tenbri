# @tenbri/openai-agents

[Tenbri](https://github.com/tenbri/tenbri) for the [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/)
in TypeScript: every tool call, handoff and approval of an agent becomes a signed, chained decision
that anyone holding the stream's key fingerprint can verify offline.

```sh
npm install @tenbri/openai-agents@next tenbri@next @openai/agents
```

```ts
import { init } from 'tenbri'
import { instrumentOpenAIAgents } from '@tenbri/openai-agents'

init() // TENBRI_STREAM=./audit/support TENBRI_APPROVER=person:alice
instrumentOpenAIAgents()
```

From then on every `run()` (and `Runner.run`) records its agent, the agents it hands off to, and
every `RunState` `approve()` and `reject()`. A run that is not streamed returns once its entries
are written. `init()` creates the stream and its keys on first use and flushes before the process exits; see
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
instrumentOpenAIAgents({ actions: { issue_refund: { target: 'stripe:{charge}', policy: 'policy:refund@14' } } })
```

## Approvals

Answer interruptions the SDK's way; both answers are recorded before the tool's intent:

```ts
let result = await run(agent, 'Refund 80 EUR on ch_2')
for (const item of result.interruptions) result.state.approve(item) // an approval by TENBRI_APPROVER
result = await run(agent, result.state)
```

`reject(item)` records the call's intent and a `refused` outcome by the approver. The approver is
`TENBRI_APPROVER`, `init({ approver })`, or the `approver` option: a principal, or a function of
the item.

## Advanced: `TenbriRecorder`

`instrumentOpenAIAgents` is built on `TenbriRecorder`, on a stream you opened. What it records,
below, is what the one-liner records.

```ts
import { Agent, run } from '@openai/agents'
import { Tenbri } from 'tenbri'
import { TenbriRecorder } from '@tenbri/openai-agents'

const log = await Tenbri.open('s3://acme-audit/tenbri/support')
const recorder = new TenbriRecorder(log)
const agent = recorder.instrument(new Agent({ name: 'support-assistant', tools: [issueRefund] }))
const result = await run(agent, 'Refund ch_123')
await recorder.flush()
```

| What happens | What is recorded |
| --- | --- |
| A tool call | An intent by `agent:<name>`, action the tool's name, durable before the tool runs; then the outcome `ok`, or `error` if the tool threw or timed out |
| A tool input guardrail rejects or trips, or a person rejects the call | An intent and the outcome `refused` (by the person, for a rejection) |
| A handoff | An intent and an outcome `ok`, action `handoff`, target `agent:<next agent>` |
| `await recorder.approve(result.state, item, 'person:alice')` | An `approval` entry; the tool's intent names it in `approval` |

The SDK does not wait for its run hooks (they are events), so `instrument` adds a tool input
guardrail to each recorded tool, after the tool's own guardrails: the SDK awaits it before the tool
runs. The guarantee is **enforce**: if the intent cannot be written, the tool does not run.
`failOpen: true` lets it run instead and warns. Outcomes and handoffs are written in the background
and in order; the next intent and `flush()` wait for them and throw what failed.

`instrument` also covers the agents an agent hands off to. A tool is recorded by one recorder; a
recorder can serve many runs. Tools an agent gets at run time (MCP servers) are not instrumented.

Tool arguments, results and prompts are never written. Choose what is:

```ts
new TenbriRecorder(log, {
  tools: ['issue_refund', 'close_ticket'],                 // default: every function tool
  target: (tool, args) => `stripe:${args.charge}`,         // action.target
  inputs: (tool, args) => [{ ref: 'policy:refund', version: '14', content: policy }],
  subject: customerHandle,                                 // per-subject keys, for erasure
})
recorder.read('ticket:4821', { version: '3', content: ticketText }) // pinned to the next decision
```

Contents are pinned by keyed digest, keyed by the stream's local key store. Entries carry the SDK's trace
id, so a decision and its trace find each other.

[examples/refunds.ts](examples/refunds.ts) runs end to end, with or without an OpenAI API key.
