# tenbri (Node.js)

Node.js bindings for [Tenbri](https://github.com/tenbri/tenbri). Audit trail for AI agents:
every decision signed, chained and provable. The same Rust core as the `tenbri` CLI and tenbrid,
as a native addon (napi-rs) for Linux (glibc and musl), macOS and Windows, Node 20 and later,
with TypeScript types.

```sh
npm install tenbri@next
```

```ts
import { Refused, Tenbri } from 'tenbri'

// A directory, file://..., s3://bucket/prefix or r2://bucket/prefix. create makes the stream and
// its keys (in $TENBRI_KEYS, else ~/.config/tenbri/keys) when there is none.
const log = await Tenbri.open('./audit/support', { create: true, digestKey: 'a 32-byte secret, kept apart....' })
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
