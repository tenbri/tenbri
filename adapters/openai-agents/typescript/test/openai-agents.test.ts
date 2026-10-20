// The adapter against the real SDK and a real stream, with a scripted model: no API key.
// The conformance scenario (one tool call allowed, one refused, one crash mid-action), plus
// errors, approvals, handoffs and failing closed or open.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  Agent,
  Runner,
  ToolCallError,
  ToolGuardrailFunctionOutputFactory,
  Usage,
  defineToolInputGuardrail,
  setTraceProcessors,
  run,
  tool,
  type AgentOutputItem,
  type Model,
  type ModelResponse,
} from '@openai/agents-core'
import { Tenbri, TenbriError, init, type Entry } from 'tenbri'
import { TenbriRecorder, instrumentOpenAIAgents, uninstrumentOpenAIAgents } from '../src/index.ts'

// Traces are kept (their ids land in entries) but exported nowhere.
setTraceProcessors([])

/** A model that answers with the next scripted turn. */
function scripted(...turns: AgentOutputItem[][]): Model {
  return {
    async getResponse(): Promise<ModelResponse> {
      return { output: turns.shift() ?? [], usage: new Usage(), responseId: undefined }
    },
    getStreamedResponse() {
      throw new Error('not scripted')
    },
  }
}

const call = (name: string, callId: string, args: object = {}): AgentOutputItem => ({
  type: 'function_call',
  name,
  callId,
  arguments: JSON.stringify(args),
  status: 'completed',
})
const say = (text: string): AgentOutputItem => ({
  type: 'message',
  role: 'assistant',
  status: 'completed',
  content: [{ type: 'output_text', text }],
})

function fn(name: string, props: string[], execute: (args: any) => unknown, more: object = {}) {
  return tool({
    name,
    description: name,
    parameters: {
      type: 'object',
      properties: Object.fromEntries(props.map((p) => [p, { type: 'string' }])),
      required: props,
      additionalProperties: false,
    },
    strict: true,
    execute: async (args) => execute(args),
    ...more,
  })
}

async function open() {
  const dir = mkdtempSync(join(tmpdir(), 'tenbri-openai-agents-'))
  return Tenbri.open(join(dir, 'audit'), { keys: join(dir, 'keys'), create: true, digestKey: 'k'.repeat(32) })
}

async function decisions(log: Tenbri): Promise<Entry[]> {
  return (await log.query()).map((m) => m.entry).filter((e) => e.kind === 'decision' || e.kind === 'approval')
}

/** phase or kind, action, status, principal: enough to read a stream at a glance. */
const brief = (e: Entry) => `${e.phase ?? e.kind} ${e.action?.type} ${e.status ?? ''} ${e.principal?.kind}:${e.principal?.id}`.replace('  ', ' ')

test('allowed, error, refused and a handoff', async () => {
  const log = await open()
  const seenBeforeRefund: string[] = []
  const refund = fn('issue_refund', ['charge', 'amount'], async ({ amount }) => {
    // The intent is durable before the tool runs (the three calls run concurrently).
    seenBeforeRefund.push(...(await decisions(log)).map(brief))
    return `refunded ${amount}`
  })
  const lookup = fn('lookup_order', ['order'], () => {
    throw new Error('orders database is down')
  })
  const noWipes = defineToolInputGuardrail({
    name: 'no_wipes',
    run: async () => ToolGuardrailFunctionOutputFactory.rejectContent('wiping is not allowed'),
  })
  const wipe = fn('wipe_account', ['account'], () => assert.fail('a refused tool must not run'), {
    inputGuardrails: [noWipes],
  })
  const billing = new Agent({ name: 'billing', model: scripted([say('done')]) })
  const support = new Agent({
    name: 'support',
    tools: [refund, lookup, wipe],
    handoffs: [billing],
    model: scripted(
      [
        call('issue_refund', 'c1', { charge: 'ch_123', amount: '40' }),
        call('lookup_order', 'c2', { order: 'o_9' }),
        call('wipe_account', 'c3', { account: 'acct_1' }),
      ],
      [call('transfer_to_billing', 'c4')],
    ),
  })
  const recorder = new TenbriRecorder(log, {
    target: (_tool, args) => (typeof args.charge === 'string' ? `stripe:${args.charge}` : undefined),
    inputs: (tool) => (tool === 'issue_refund' ? [{ ref: 'policy:refund', version: '14', content: 'under 50 EUR' }] : []),
  })
  recorder.instrument(support)
  recorder.read('ticket:4821', { version: '3', content: 'please refund my order' })

  const result = await new Runner().run(support, 'refund ch_123')
  await recorder.flush()
  assert.equal(result.finalOutput, 'done')

  const entries = await decisions(log)
  assert.ok(seenBeforeRefund.includes('intent issue_refund agent:support'))
  assert.deepEqual(entries.map(brief).sort(), [
    'intent handoff agent:support',
    'intent issue_refund agent:support',
    'intent lookup_order agent:support',
    'intent wipe_account agent:support',
    'outcome handoff ok agent:support',
    'outcome issue_refund ok agent:support',
    'outcome lookup_order error agent:support',
    'outcome wipe_account refused agent:support',
  ])
  const intent = entries.find((e) => e.phase === 'intent' && e.action?.type === 'issue_refund')!
  assert.equal(intent.action?.target, 'stripe:ch_123')
  assert.deepEqual(intent.inputs?.map((i) => [i.ref, i.version]), [['ticket:4821', '3'], ['policy:refund', '14']])
  assert.equal(intent.inputs?.[1]?.digest, log.digest('under 50 EUR'))
  const trace = intent.trace as { trace_id: string; span_id: string }
  assert.equal(trace.trace_id.length, 32)
  assert.equal(trace.span_id.length, 16)
  assert.equal(entries.find((e) => e.action?.type === 'handoff')?.action?.target, 'agent:billing')
  // Tool arguments and results are never written, only what target and inputs make of them.
  for (const secret of ['o_9', 'acct_1', 'refunded', 'orders database']) assert.ok(!JSON.stringify(entries).includes(secret))
  assert.ok((await log.verify(log.fingerprint!)).ok)
})

test('approvals are recorded and named by the intent', async () => {
  const log = await open()
  const ran: string[] = []
  const pay = fn('pay_invoice', ['invoice'], ({ invoice }) => ran.push(invoice), { needsApproval: true })
  const del = fn('delete_vendor', ['vendor'], ({ vendor }) => ran.push(vendor), { needsApproval: true })
  const agent = new Agent({
    name: 'finance',
    tools: [pay, del],
    model: scripted(
      [call('pay_invoice', 'p1', { invoice: 'inv_7' }), call('delete_vendor', 'd1', { vendor: 'v_2' })],
      [say('paid, not deleted')],
    ),
  })
  const recorder = new TenbriRecorder(log, { target: (_tool, args) => Object.values(args)[0] as string })
  recorder.instrument(agent)
  const runner = new Runner()

  const first = await runner.run(agent, 'pay inv_7')
  assert.deepEqual(first.interruptions.map((i) => i.name).sort(), ['delete_vendor', 'pay_invoice'])
  await recorder.flush()
  assert.deepEqual(await decisions(log), []) // waiting for a person
  for (const item of first.interruptions) {
    if (item.name === 'pay_invoice') await recorder.approve(first.state, item, 'person:alice')
    else await recorder.reject(first.state, item, 'person:bob')
  }
  await runner.run(agent, first.state)
  await recorder.flush()
  assert.deepEqual(ran, ['inv_7'])

  const entries = await decisions(log)
  const approval = entries.find((e) => e.kind === 'approval')!
  assert.equal(brief(approval), 'approval pay_invoice person:alice')
  assert.equal(approval.action?.target, 'inv_7')
  const intent = entries.find((e) => e.phase === 'intent' && e.action?.type === 'pay_invoice')!
  assert.deepEqual((intent.approval as { by: unknown }).by, { kind: 'person', id: 'alice' })
  assert.ok(entries.map(brief).includes('outcome pay_invoice ok agent:finance'))
  assert.ok(entries.map(brief).includes('outcome delete_vendor refused person:bob'))
  // The approval member names the approval entry's hash: the stream verifies only if it does.
  assert.ok((await log.verify(log.fingerprint!)).ok)
})

test('a crash mid-action and a guardrail tripwire', async () => {
  const log = await open()
  const migrate = fn('migrate', ['db'], () => {
    throw new Error('connection lost')
  }, { errorFunction: null, outputSchema: undefined })
  const stop = defineToolInputGuardrail({
    name: 'stop',
    run: async () => ToolGuardrailFunctionOutputFactory.throwException(),
  })
  const drop = fn('drop_table', ['table'], () => assert.fail('a refused tool must not run'), { inputGuardrails: [stop] })

  const crash = new TenbriRecorder(log).instrument(
    new Agent({ name: 'ops', tools: [migrate], model: scripted([call('migrate', 'm1', { db: 'prod' })], [say('ok')]) }),
  )
  await new Runner().run(crash, 'migrate').catch(() => {})
  const tripped = new Agent({ name: 'ops', tools: [drop], model: scripted([call('drop_table', 't1', { table: 'users' })]) })
  const recorder = new TenbriRecorder(log)
  recorder.instrument(tripped)
  await assert.rejects(new Runner().run(tripped, 'drop users'), /guardrail/i)
  await recorder.flush()

  assert.deepEqual((await decisions(log)).map(brief).sort(), [
    'intent drop_table agent:ops',
    'intent migrate agent:ops',
    'outcome drop_table refused agent:ops',
    'outcome migrate error agent:ops',
  ])
})

test('tool selection, failing closed and failing open', async () => {
  const log = await open()
  const ran: string[] = []
  // A tool is recorded by one recorder, so each run gets its own.
  const agent = () =>
    new Agent({
      name: 'mailer',
      tools: [fn('send_email', ['to'], ({ to }) => ran.push(to)), fn('get_time', [], () => ran.push('time'))],
      model: scripted([call('get_time', 'g1'), call('send_email', 's1', { to: 'a@example.com' })], [say('ok')]),
    })

  const selective = new TenbriRecorder(log, { tools: ['send_email'] })
  await new Runner().run(selective.instrument(agent()), 'mail')
  await selective.flush()
  assert.deepEqual(new Set((await decisions(log)).map((e) => e.action?.type)), new Set(['send_email']))

  await log.close() // the stream can no longer be written
  ran.length = 0
  const closed = new TenbriRecorder(log)
  // The SDK wraps what a guardrail throws in a ToolCallError.
  await assert.rejects(new Runner().run(closed.instrument(agent()), 'mail'), (e: ToolCallError) => e.error instanceof TenbriError)
  assert.ok(!ran.includes('a@example.com')) // fail closed: the action never ran

  ran.length = 0
  const warnings: string[] = []
  const warn = console.warn
  console.warn = (m: string) => warnings.push(m)
  try {
    const open = new TenbriRecorder(log, { failOpen: true })
    await new Runner().run(open.instrument(agent()), 'mail')
    await open.flush()
  } finally {
    console.warn = warn
  }
  assert.ok(ran.includes('a@example.com'))
  assert.ok(warnings.some((w) => w.includes('failOpen')))
})

test('the one-liner: init() and instrumentOpenAIAgents(), mapping from tenbri.toml, approver from the environment', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tenbri-openai-agents-'))
  writeFileSync(join(dir, 'tenbri.toml'), '[actions.issue_refund]\ntarget = "stripe:{charge}"\npolicy = "policy:refund@14"\n')
  process.env.TENBRI_APPROVER = 'person:alice'
  const log = await init({ stream: join(dir, 'audit'), keys: join(dir, 'keys'), schema: join(dir, 'tenbri.toml') })
  instrumentOpenAIAgents()
  const ran: string[] = []
  const refund = fn('issue_refund', ['charge'], ({ charge }) => ran.push(charge), {
    needsApproval: async (_ctx: unknown, { charge }: { charge: string }) => charge !== 'ch_1',
  })
  const agent = new Agent({
    name: 'support',
    tools: [refund],
    model: scripted(
      [call('issue_refund', 'c1', { charge: 'ch_1' })],
      [call('issue_refund', 'c2', { charge: 'ch_2' }), call('issue_refund', 'c3', { charge: 'ch_3' })],
      [say('done')],
    ),
  })
  try {
    const first = await run(agent, 'refund ch_1, then ch_2 and ch_3')
    for (const item of first.interruptions) {
      if ((item.rawItem as { callId: string }).callId === 'c2') first.state.approve(item)
      else first.state.reject(item)
    }
    await run(agent, first.state)
  } finally {
    uninstrumentOpenAIAgents()
    delete process.env.TENBRI_APPROVER
  }
  assert.deepEqual(ran, ['ch_1', 'ch_2'])
  const entries = await decisions(log)
  assert.deepEqual(entries.map(brief), [
    'intent issue_refund agent:support',
    'outcome issue_refund ok agent:support',
    'approval issue_refund person:alice',
    'intent issue_refund agent:support',
    'outcome issue_refund refused person:alice',
    'intent issue_refund agent:support',
    'outcome issue_refund ok agent:support',
  ])
  assert.deepEqual(entries[0].action, { type: 'issue_refund', target: 'stripe:ch_1' })
  assert.deepEqual(entries[0].rule, { ref: 'policy:refund', version: '14', result: 'allow' })
  assert.equal(entries[3].action?.target, 'stripe:ch_3') // refused
  assert.deepEqual((entries[5].approval as { by: unknown }).by, { kind: 'person', id: 'alice' })
  assert.ok((await log.verify(log.fingerprint!)).ok)
  await log.close()
})
