# tenbri (Node.js)

Node.js bindings for [Tenbri](https://github.com/tenbri/tenbri). Audit trail for AI agents:
every decision signed, chained and provable. The same Rust core as the `tenbri` CLI and tenbrid,
as a native addon (napi-rs) for Linux (glibc and musl), macOS and Windows, Node 20 and later,
with TypeScript types.

```sh
npm install tenbri@next
```

## Quick start

```ts
import { Refused, decision, init } from 'tenbri'

init() // TENBRI_STREAM, TENBRI_AGENT...: see below

const refund = decision(
  { action: 'issue_refund', target: 'stripe:{charge}', policy: 'policy:refund@14' },
  async ({ charge, amount }: { charge: string; amount: number }) => {
    if (amount > 500) throw new Refused('over the ceiling') // recorded as refused
    // issue the refund
  },
)
```

Each call of `refund` is a decision: its intent is durable before the function runs (if it cannot
be written, the function does not run), then its outcome follows: `ok`, `refused` when it throws
`Refused`, `error` for anything else it throws (rethrown), `unknown` for an `AbortError`.

- `target` and `subject` are templates of the arguments (`'stripe:{charge}'` reads the first
  argument's `charge`, `'{1}'` is the second argument) or functions of them; `policy`
  (`'ref@version'`) is the rule that allowed it; `inputs` pins what the decision relied on,
  `{ ref, version, content }` or a function of the arguments returning those, by keyed digest.
- Who acts: `principal`, else the innermost `agent('agent:billing', () => ...)`, else
  `init({ agent })`. Nothing is guessed: with none, the call rejects.
- With an agent framework, one more line records every tool call: `instrumentClaudeAgentSdk(options)`
  from `@tenbri/claude-agent-sdk`, `instrumentOpenAIAgents()` from `@tenbri/openai-agents`, or
  `instrumentLangChain()` from `@tenbri/langgraph`.

`init()` opens the process's default stream, creating it and its keys on first use, and closes it
(flushing) before the process exits; `await using log = await init(...)` scopes it to a block.
Awaiting it is optional: a decision waits for it. Creating a stream (here or with
`Tenbri.open(..., { create: true })`) records its pin in `<keys>/pins`, as `tenbri init` does, so
`tenbri verify <stream>` on this machine needs no `--key`. Every option defaults to an environment
variable:

| Option | Variable | |
| --- | --- | --- |
| `stream` | `TENBRI_STREAM` | A directory, `file://...`, `s3://bucket/prefix` or `r2://bucket/prefix` |
| `keys` | `TENBRI_KEYS` | The keys directory, apart from the stream; default `~/.config/tenbri/keys` |
| `agent` | `TENBRI_AGENT` | Who acts when nothing narrower says: `agent:support` |
| `approver` | `TENBRI_APPROVER` | Who answers the frameworks' approval prompts: `person:alice` |
| `schema` | `TENBRI_SCHEMA` | The action schemas; default `./tenbri.toml` when there is one |
| `failOpen` | | Run actions, unrecorded and with a warning, when their intent cannot be written. Default: block them |

Input digests are keyed by the stream's local key store (per subject, so erasing a subject's key
leaves its digests unconfirmable): no secret in code. `digestKey` keys them yourself instead.

## Advanced: the stream itself

`init()` and `decision()` are built on this; use it to hold several streams, or to see every call.

```ts
import { Refused, Tenbri } from 'tenbri'

// A directory, file://..., s3://bucket/prefix or r2://bucket/prefix. create makes the stream and
// its keys (in $TENBRI_KEYS, else ~/.config/tenbri/keys) when there is none.
const log = await Tenbri.open('./audit/support', { create: true })
console.log('pin this:', log.fingerprint)

await log.run({ principal: 'agent:support-assistant' }, async (run) => {
  // Reads are pinned to the next decision's inputs, with a keyed digest of what was read.
  run.read('policy:refund', { version: '14', content: 'refunds under 50 EUR are automatic' })
  // The intent is durable before the callback runs; the outcome follows: ok, refused or error.
  await run.decision({ action: 'issue_refund', target: 'stripe:ch_123' }, async () => {
    // issue the refund here; throw new Refused(...) when your policy says no
  })
})

const report = await log.verify(log.fingerprint!)
console.log(report.ok, report.entries)
for (const m of await log.query({ inputs: ['policy:refund@14'] })) console.log(m.verification, m.entry.action)
await log.close()
```

- **Low level**: `log.intent(draft)`, `log.outcome(intent, status, fields)` and
  `log.append(entry)` take format v1 drafts and resolve to entries as stored.
- **Concurrency**: every call returns a Promise; concurrent appends share one group commit.
- **Idempotent retries**: give a draft an `id` (`newId()`); appending the same entry again
  resolves to the original. Every write error carries the `id` it was writing.
- **Errors** are typed, one per stable code shared with tenbrid: `TenbriError` and its
  subclasses (`StoreUnavailableError` is `TENBRI_STORE_UNAVAILABLE`, ...), with `.code`,
  `.reason` (the format's error code) and `.id`.
- **Read-only**: without the stream's keys, a stream opens read-only; `verify` and `query` work,
  writes reject with `NoSessionKeyError`.
- `verify(key)` is only `ok` against a pinned key: without one it shows that the stream agrees
  with its own genesis key, which proves nothing about who wrote it.

For a verifier in the browser, see [`@tenbri/wasm`](../wasm).
