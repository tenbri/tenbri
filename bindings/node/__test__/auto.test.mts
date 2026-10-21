// init(), agent() and decision(): the default stream and what it records.
import { test, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  InvalidRequestError,
  NoSessionKeyError,
  Refused,
  Tenbri,
  agent,
  decision,
  defaultStream,
  describe,
  init,
  type Entry,
} from '../tenbri.js'

const tmp = () => mkdtempSync(join(tmpdir(), 'tenbri-auto-'))
const VARS = ['TENBRI_STREAM', 'TENBRI_KEYS', 'TENBRI_AGENT', 'TENBRI_APPROVER', 'TENBRI_SCHEMA']

beforeEach(async () => {
  for (const v of VARS) delete process.env[v]
  try {
    await (await defaultStream()).close()
  } catch {
    // none open
  }
})

// The CLI cargo built in this checkout, if any; TENBRI_BIN names another.
const TENBRI_BIN = process.env.TENBRI_BIN || join(import.meta.dirname, '..', '..', '..', 'target', 'debug', 'tenbri')

test('init records the pin, and tenbri verify uses it', async (t) => {
  const dir = tmp()
  const keys = join(dir, 'keys')
  process.env.TENBRI_KEYS = keys
  const stream = join(dir, 'audit')
  const d = await init({ stream })
  const line = `${realpathSync(stream)} ${d.fingerprint}\n`
  assert.equal(readFileSync(join(keys, 'pins'), 'utf8'), line)
  await init({ stream }) // opening it again records nothing
  assert.equal(readFileSync(join(keys, 'pins'), 'utf8'), line)
  if (!existsSync(TENBRI_BIN)) return t.skip(`no tenbri CLI at ${TENBRI_BIN}: cargo build -p tenbri-cli`)
  const out = execFileSync(TENBRI_BIN, ['verify', stream], { encoding: 'utf8' }) // throws unless exit 0
  assert.match(out, new RegExp(`pinned to ${d.fingerprint}`))
})

async function decisions(log: Tenbri): Promise<Entry[]> {
  await log.flush()
  return (await log.query()).map((m) => m.entry).filter((e) => e.kind === 'decision')
}

test('init from the environment, arguments first, scoped with using', async () => {
  await assert.rejects(init(), /TENBRI_STREAM/)
  await assert.rejects(defaultStream(), InvalidRequestError)
  const dir = tmp()
  process.env.TENBRI_STREAM = join(dir, 'env-stream')
  process.env.TENBRI_KEYS = join(dir, 'keys')
  process.env.TENBRI_AGENT = 'agent:support'
  process.env.TENBRI_APPROVER = 'person:alice'
  const d = await init()
  assert.equal(await defaultStream(), d)
  assert.ok(d.writable)
  assert.deepEqual([d.agent, d.approver, d.failOpen, d.actions], ['agent:support', 'person:alice', false, {}])
  const e = await init({ stream: join(dir, 'arg-stream'), agent: 'agent:billing', failOpen: true })
  assert.notEqual(e.id, d.id)
  assert.ok(!d.writable) // replaced, and closed
  assert.deepEqual([e.agent, e.failOpen], ['agent:billing', true])
  assert.ok((await init({ stream: join(dir, 'arg-stream') })).writable) // the same stream again
  {
    await using s = await init({ stream: join(dir, 'scoped') })
    assert.equal(await defaultStream(), s)
  }
  await assert.rejects(defaultStream(), InvalidRequestError)
})

test('describe from tenbri.toml and code', async () => {
  const dir = tmp()
  writeFileSync(
    join(dir, 'tenbri.toml'),
    '[actions.issue_refund]\ntarget = "stripe:{charge}"\npolicy = "policy:refund@14"\n[actions.lookup]\ntarget = "orders:*"\n',
  )
  await init({ stream: join(dir, 's'), keys: join(dir, 'k'), schema: join(dir, 'tenbri.toml') })
  assert.deepEqual(describe('mcp__billing__issue_refund', { charge: 'ch_1' }), {
    action: 'issue_refund',
    target: 'stripe:ch_1',
    rule: { ref: 'policy:refund', version: '14', result: 'allow' },
  })
  assert.deepEqual(describe('lookup', { order: 'o1' }), {})
  const actions = { lookup: { target: 'orders:{order}', subject: (a: Record<string, any>) => `c-${a.order}` } }
  assert.deepEqual(describe('lookup', { order: 'o1' }, actions), { target: 'orders:o1', subject: 'c-o1' })
  assert.equal(describe('mcp__shop__lookup', { order: 'o1' }, actions).action, 'lookup')
  assert.throws(() => describe('issue_refund', {}), /charge/)
  writeFileSync(join(dir, 'bad.toml'), '[actions.x]\npolicy = "no-version"\n')
  await assert.rejects(init({ stream: join(dir, 's2'), schema: join(dir, 'bad.toml') }), /ref@version/)
})

test('decision: ok, refused, error, templates, policy and inputs keyed by the key store', async () => {
  const dir = tmp()
  const log = await init({ stream: join(dir, 's'), keys: join(dir, 'k'), agent: 'agent:support' })
  const refund = decision(
    {
      action: 'issue_refund',
      target: 'stripe:{charge}',
      policy: 'policy:refund@14',
      subject: '{customer.id}',
      inputs: ({ charge }: { charge: string }) => [{ ref: 'ticket:4512', version: '3', content: `refund ${charge}` }],
    },
    async function refund({ amount }: { charge: string; amount: number; customer: { id: string } }) {
      const es = await decisions(log)
      assert.equal(es.at(-1)?.phase, 'intent') // durable before the action
      if (amount > 500) throw new Refused('over the ceiling')
      if (amount < 0) throw new RangeError('negative')
      return amount
    },
  )
  const customer = { id: 'c-42' }
  assert.equal(refund.name, 'refund')
  assert.equal(await refund({ charge: 'ch_1', amount: 20, customer }), 20)
  await assert.rejects(refund({ charge: 'ch_2', amount: 900, customer }), Refused)
  await assert.rejects(refund({ charge: 'ch_3', amount: -1, customer }), RangeError)
  const es = await decisions(log)
  assert.deepEqual(
    es.filter((e) => e.phase === 'outcome').map((e) => e.status),
    ['ok', 'refused', 'error'],
  )
  const [intent] = es
  assert.deepEqual(intent.principal, { kind: 'agent', id: 'support' })
  assert.deepEqual(intent.action, { type: 'issue_refund', target: 'stripe:ch_1' })
  assert.deepEqual(intent.rule, { ref: 'policy:refund', version: '14', result: 'allow' })
  assert.equal(intent.subject, 'c-42')
  assert.deepEqual(intent.inputs, [
    { ref: 'ticket:4512', version: '3', digest: log.digest('refund ch_1', { subject: 'c-42' }) },
  ])
  assert.notEqual(intent.inputs?.[0].digest, log.digest('refund ch_1'))
  assert.equal(await log.digestAsync('refund ch_1', { subject: 'c-42' }), intent.inputs?.[0].digest)
  assert.ok((await log.verify(log.fingerprint ?? undefined)).ok)
})

test('agent() scopes the principal; positional templates; aborted is unknown', async () => {
  const dir = tmp()
  const log = await init({ stream: join(dir, 's'), keys: join(dir, 'k') })
  const reply = decision({ action: 'reply_ticket', target: 'zendesk:{0}' }, async (ticket: number, signal?: AbortSignal) => {
    if (signal) {
      const e = new Error('aborted')
      e.name = 'AbortError'
      throw e
    }
    return `sent ${ticket}`
  })
  await assert.rejects(reply(1), /TENBRI_AGENT/) // who acts is never guessed
  assert.equal(await agent('agent:support', () => reply(1)), 'sent 1')
  await agent('agent:support', () => agent('person:alice', () => reply(2)))
  await assert.rejects(agent('agent:support', () => reply(3, AbortSignal.abort())))
  const es = await decisions(log)
  assert.deepEqual(
    es.map((e) => [e.principal?.id, e.action?.target, e.status]),
    [
      ['support', 'zendesk:1', undefined],
      ['support', 'zendesk:1', 'ok'],
      ['alice', 'zendesk:2', undefined],
      ['alice', 'zendesk:2', 'ok'],
      ['support', 'zendesk:3', undefined],
      ['support', 'zendesk:3', 'unknown'],
    ],
  )
})

test('fail closed unless fail-open', async () => {
  const dir = tmp()
  await (await Tenbri.open(join(dir, 's'), { keys: join(dir, 'keys'), create: true })).close()
  const ran: string[] = []
  const refund = decision({ action: 'issue_refund', target: 'stripe:{0}', principal: 'agent:support' }, (charge: string) => {
    ran.push(charge)
  })
  await assert.rejects(refund('ch_0'), /init/) // no stream: no action
  await init({ stream: join(dir, 's'), keys: join(dir, 'elsewhere') }) // read-only here
  await assert.rejects(refund('ch_1'), NoSessionKeyError)
  assert.equal(ran.length, 0)
  await init({ stream: join(dir, 's'), keys: join(dir, 'elsewhere'), failOpen: true })
  await refund('ch_2')
  assert.deepEqual(ran, ['ch_2'])
  const strict = decision({ action: 'issue_refund', principal: 'agent:support', failOpen: false }, () => {
    ran.push('strict')
  })
  await assert.rejects(strict(), NoSessionKeyError)
  assert.deepEqual(ran, ['ch_2'])
})
