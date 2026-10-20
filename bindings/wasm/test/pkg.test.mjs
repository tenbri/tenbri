// The built package (pkg/, wasm-pack --target web) as npm ships it, loaded in Node.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { initSync, verifyEntries, verifyExport, version } from '../pkg/tenbri_wasm.js'

initSync({ module: readFileSync(new URL('../pkg/tenbri_wasm_bg.wasm', import.meta.url)) })

const stream = join(import.meta.dirname, '..', '..', '..', 'spec', 'vectors', 'streams', 'basic')
const batches = join(stream, 'batches')
const exported = readdirSync(batches).sort().map((f) => readFileSync(join(batches, f), 'utf8')).join('')
const pin = 'sha256:170241c12e8724974ea3b10fe536b7d848f7cbd0963f55eecf0a11e9edf52e9c'

test('a stream export verifies against its pinned key', () => {
  assert.ok(version())
  const r = verifyExport(exported, pin)
  assert.deepEqual(r, { ok: true, stream: 'tnb1:170241c12e8724974ea3b10fe536b7d8', entries: 14, pinnedKey: pin, broken: null, checkpoint: null })
  assert.equal(verifyExport(exported).ok, false, 'unpinned proves nothing')
})

test('an edited entry is caught at its sequence number', () => {
  const lines = exported.trimEnd().split('\n')
  lines[2] = lines[2].replace('"seq":3', '"seq":3 ')
  const r = verifyEntries(lines, pin)
  assert.equal(r.ok, false)
  assert.deepEqual([r.broken.seq, r.broken.code, r.entries], [3, 'not_canonical', 2])
  assert.throws(() => verifyExport(exported, 'sha256:00'), /expected sha256/)
})
