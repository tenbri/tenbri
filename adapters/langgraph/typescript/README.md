# @tenbri/langgraph

[Tenbri](https://github.com/tenbri/tenbri) for LangGraph and LangChain.js: every tool call your
agent makes is a signed, chained decision. One callback handler at agent setup.

```sh
npm install tenbri@next @tenbri/langgraph@next
```

```ts
import { createAgent } from 'langchain'
import { Tenbri } from 'tenbri'
import { TenbriCallbackHandler } from '@tenbri/langgraph'

const log = await Tenbri.open('./audit/support', { create: true, digestKey: process.env.TENBRI_DIGEST_KEY })
const tenbri = new TenbriCallbackHandler(log, { target: (_tool, args) => `stripe:${args.charge}` })

const agent = createAgent({ model, tools: [issueRefund], name: 'support' })
await agent.invoke({ messages: [{ role: 'user', content: 'refund ch_123' }] }, { callbacks: [tenbri] })
console.log((await log.verify(log.fingerprint!)).ok)
```

- **Before each tool call** its intent is durable in the stream, or the tool does not run (the
  handler raises its errors, so LangChain awaits it). After it comes the outcome: `ok`, `error`,
  or `refused` when the tool throws tenbri's `Refused`. `createAgent`'s tool node hands a tool's
  error, or a failed intent, to the model as an error message; the tool has not run. A process
  that dies mid-call leaves the intent open, and the stream's next writer reconciles it as
  `unknown`.
- **Who and what**: `principal` is the agent (`createAgent({ name })`, or `principal`), `action`
  is the tool, `target` is what `target(tool, args)` returns.
- **Inputs**: with a `digestKey`, the call's arguments are pinned as a keyed digest
  (`langchain:tool_call/<id>@args`); `inputs(tool, args)` pins more, such as a policy version.
  Arguments and results are never stored.
- **Selection**: `tools: ['issue_refund']` or a predicate records only those tools.
- **Traces**: the active OpenTelemetry span goes into `trace`; the LangChain run id, the tool call
  id and the LangGraph thread id go into `ext.langchain`, so a LangSmith run and a decision find
  each other.
- **Fail closed** by default: when the stream can't be written, the tool call fails.
  `failOpen: true` runs the tool anyway and logs a warning.

## Human in the loop

With `humanInTheLoopMiddleware` (and a checkpointer), record the person's answer as you resume:

```ts
const config = { callbacks: [tenbri], configurable: { thread_id: 't1' } }
await agent.invoke({ messages: [{ role: 'user', content: 'refund ch_123' }] }, config) // paused for review
await agent.invoke(await tenbri.resume(agent, config, { decisions: [{ type: 'approve' }] }, { by: 'person:alice' }), config)
```

`approve` and `edit` write an `approval` entry, and the tool's intent names it
(`approval: {by, entry}`). `reject` writes the call's intent and a `refused` outcome. In batched
mode, LangChain.js runs none of a batch's calls when one is rejected; their approvals stay in the
stream, unused. For an `interrupt()` of your own, call
`tenbri.approve(tool, args, { by, toolCallId })` once the person has answered.

A runnable example is in [examples/refund-agent.mts](examples/refund-agent.mts)
(`npm run build && npm run example`).
