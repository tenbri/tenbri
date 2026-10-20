# @tenbri/wasm

The offline verifier of [Tenbri](https://github.com/tenbri/tenbri) (audit trail for AI agents:
every decision signed, chained and provable), compiled to WebAssembly from the same Rust code as
the CLI. It checks a stream export, or a set of entries, against a key you pin: canonical bytes,
the hash chain, signatures, key rotation and revocation, intents and outcomes, and, given a
checkpoint you saw before, truncation and rewrites behind it. No network, no keys, nothing
trusted but what you pin. About 150 KB gzipped.

```sh
npm install @tenbri/wasm@next
```

An export is JSON Lines, one stored entry per line from seq 1: a stream's batch files concatenated
in order (`cat <stream>/batches/*.jsonl`).

In the browser (ES module):

```js
import init, { verifyExport } from '@tenbri/wasm'

await init() // fetches tenbri_wasm_bg.wasm next to the module
const jsonl = await (await fetch('/audit/support.jsonl')).text()
const report = verifyExport(jsonl, 'sha256:170241c12e8724974ea3b10fe536b7d848f7cbd0963f55eecf0a11e9edf52e9c')
if (!report.ok) console.log(`broken at seq ${report.broken?.seq}: ${report.broken?.code}`)
```

In Node:

```js
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { initSync, verifyEntries } from '@tenbri/wasm'

const require = createRequire(import.meta.url)
initSync({ module: readFileSync(require.resolve('@tenbri/wasm/pkg/tenbri_wasm_bg.wasm')) })
const lines = readFileSync('support.jsonl', 'utf8').trimEnd().split('\n')
console.log(verifyEntries(lines, process.argv[2], readFileSync('checkpoint.note', 'utf8')))
```

Both functions take `(entries, key?, checkpoint?)` and return a `Report`: `ok` (at least one
entry, nothing broken, against a pinned key), `stream`, `entries` (checked before the first break),
`pinnedKey`, `broken` (`{ seq, code, message }` with the format's error code, or `null`) and
`checkpoint` (the size of the checkpoint given, when the entries match it). `key` is the genesis
key's fingerprint (`sha256:…`, what `tenbri init` prints) or the key itself (`ed25519:…`); without
one, `ok` is false: entries that agree with their own genesis key prove nothing about who wrote
them. A malformed key or checkpoint throws.
