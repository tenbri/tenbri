// The tenbri package end to end, in TypeScript: run with Node's type stripping, checked by tsc.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  IdempotencyConflictError,
  InvalidEntryError,
  NoSessionKeyError,
  NotFoundError,
  Refused,
  Tenbri,
  TenbriError,
  newId,
  version,
  type Entry,
} from '../tenbri.js'

const vectors = join(import.meta.dirname, '..', '..', '..', 'spec', 'vectors')
const tmp = () => mkdtempSync(join(tmpdir(), 'tenbri-node-'))

async function open(dir = tmp()) {
  const keys = join(dir, 'keys')
  const log = await Tenbri.open(join(dir, 'audit'), { keys, create: true, digestKey: 'k'.repeat(32) })
  return { log, dir }
}

test('runs, decisions, verify and query', async () => {
  assert.ok(version)
  const { log } = await open()
  assert.ok(log.writable && log.id.startsWith('tnb1:') && log.fingerprint)
  let intent: Entry | undefined
  await log.run({ principal: 'agent:support-assistant' }, async (run) => {
    run.read('policy:refund', { version: '14', content: 'refunds under 50 EUR are automatic' })
    const r = await run.decision({ action: 'issue_refund', target: 'stripe:ch_1' }, async (i) => {
      intent = i
      return 42
    })
    assert.equal(r, 42)
    const refused = run.decision({ action: 'issue_refund', target: 'stripe:ch_2' }, () => {
      throw new Refused('over the limit')
    })
    await assert.rejects(refused, Refused)
    const failed = run.decision({ action: 'reply_ticket' }, () => {
      throw new TypeError('boom')
    })
    await assert.rejects(failed, TypeError)
  })
  const digest = log.digest('refunds under 50 EUR are automatic')
  assert.deepEqual(intent?.inputs, [{ ref: 'policy:refund', version: '14', digest }])
  const mine = await log.query({ principal: 'agent:support-assistant' })
  const outcomes = mine.filter((m) => m.entry.phase === 'outcome').map((m) => m.entry.status)
  assert.deepEqual(outcomes, ['ok', 'refused', 'error'])
  const [m] = await log.query({ inputs: ['policy:refund@14'] })
  assert.deepEqual(m, { verification: 'unpinned', entry: intent })

  const r = await log.verify(log.fingerprint!)
  assert.equal(r.ok, true)
  assert.equal(r.entries, 8)
  assert.equal((await log.verify()).ok, false, 'unpinned proves nothing')
  await log.close()
})

test('idempotent retries, typed errors, read-only open', async () => {
  const { log, dir } = await open()
  const draft = { id: newId(), action: { type: 'reply_ticket' }, principal: 'support' }
  const first = await log.intent(draft)
  assert.deepEqual(await log.intent(draft), first)
  await assert.rejects(log.intent({ ...draft, action: { type: 'close_ticket' } }), (e: unknown) => {
    assert.ok(e instanceof IdempotencyConflictError && e instanceof TenbriError)
    assert.equal(e.code, 'TENBRI_IDEMPOTENCY_CONFLICT')
    return true
  })
  await assert.rejects(
    log.append({ kind: 'note', colour: 'red' }),
    (e: unknown) => e instanceof InvalidEntryError && e.reason === 'unknown_field',
  )
  await assert.rejects(Tenbri.open(join(dir, 'nothing')), NotFoundError)

  const other = { keys: join(dir, 'other'), key: log.fingerprint! }
  const reader = await Tenbri.open(`file://${join(dir, 'audit')}`, other)
  assert.equal(reader.writable, false)
  await assert.rejects(reader.append({ kind: 'note' }), NoSessionKeyError)
  assert.equal((await reader.verify()).ok, true)
  const after = await reader.query({ afterSeq: 2, limit: 1 })
  assert.deepEqual(after, [{ verification: 'verified', entry: first }])
})

test('concurrent intents share group commit', async () => {
  const { log } = await open()
  const intents = await Promise.all(
    Array.from({ length: 200 }, (_, i) => log.intent({ action: { type: 't', target: `${i}` }, principal: 'a' })),
  )
  const seqs = intents.map((e) => e.seq).sort((a, b) => a - b)
  assert.deepEqual(seqs, Array.from({ length: 200 }, (_, i) => i + 3))
  assert.equal((await log.verify(log.fingerprint!)).entries, 202)
})

test('conformance: spec/vectors/streams.json', async () => {
  const { cases } = JSON.parse(readFileSync(join(vectors, 'streams.json'), 'utf8'))
  for (const c of cases) {
    const log = await Tenbri.open(join(vectors, 'streams', c.name), { keys: tmp(), key: c.pin })
    const r = await log.verify()
    if (c.result.ok) {
      assert.ok(r.ok, c.name)
      assert.equal(r.entries, c.result.entries, c.name)
    } else {
      assert.deepEqual([r.broken?.seq, r.broken?.code], [c.result.seq, c.result.error], c.name)
    }
  }
})
