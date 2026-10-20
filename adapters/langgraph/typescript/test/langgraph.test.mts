// The adapter against LangChain.js's createAgent and LangGraph, with a fake chat model: the
// conformance scenario (one tool call allowed, one refused, one crash), human approval through
// interrupts, fail-closed and fail-open, tool selection and input pinning.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { context, trace } from '@opentelemetry/api'
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks'
import { BasicTracerProvider } from '@opentelemetry/sdk-trace-base'
import { MemorySaver } from '@langchain/langgraph'
import { createAgent, humanInTheLoopMiddleware, tool } from 'langchain'
import { z } from 'zod'
import { Refused, Tenbri, type Entry } from 'tenbri'
import { TenbriCallbackHandler } from '../dist/index.js'
import { model } from './fake.mts'

const tmp = () => mkdtempSync(join(tmpdir(), 'tenbri-langgraph-'))

async function open(dir = tmp()) {
  return Tenbri.open(join(dir, 's'), { keys: join(dir, 'keys'), create: true, digestKey: 'k'.repeat(32) })
}

async function decisions(log: Tenbri): Promise<Entry[]> {
  await log.flush()
  return (await log.query()).map((m) => m.entry).filter((e) => ['decision', 'approval', 'note'].includes(e.kind))
}

const ran: string[] = []
const issueRefund = tool(
  async ({ charge, amount }: { charge: string; amount: number }) => {
    if (amount > 50) throw new Refused('over the automatic limit')
    ran.push(charge)
    return 'refunded'
  },
  { name: 'issue_refund', description: 'Refund a charge.', schema: z.object({ charge: z.string(), amount: z.number() }) },
)
const lookup = tool(
  async ({ order }: { order: string }) => {
    ran.push(order)
    return 'shipped'
  },
  { name: 'lookup', description: 'Look an order up.', schema: z.object({ order: z.string() }) },
)
const explode = tool(
  async () => {
    throw new Error('boom')
  },
  { name: 'explode', description: 'Always fails.', schema: z.object({ x: z.number() }) },
)
const msg = (text: string) => ({ messages: [{ role: 'user', content: text }] })
const shape = (es: Entry[]) => es.map((e) => [e.phase, e.action?.type, e.status])

test('allowed, refused, error', async () => {
  ran.length = 0
  const log = await open()
  const h = new TenbriCallbackHandler(log, { target: (_t, a) => `stripe:${a.charge}` })
  const config = { callbacks: [h] }
  const agent = (calls: Parameters<typeof model>[0], tools: any[] = [issueRefund]) =>
    createAgent({ model: model(calls), tools, name: 'support' })
  await agent([[['issue_refund', { charge: 'ch_1', amount: 20 }]]]).invoke(msg('refund'), config)
  // ToolNode hands a tool's exception to the model as an error message, after the outcome.
  await agent([[['issue_refund', { charge: 'ch_2', amount: 90 }]]]).invoke(msg('refund'), config)
  await agent([[['explode', { x: 1 }]]], [explode]).invoke(msg('x'), config)

  const es = await decisions(log)
  assert.deepEqual(shape(es), [
    ['intent', 'issue_refund', undefined],
    ['outcome', 'issue_refund', 'ok'],
    ['intent', 'issue_refund', undefined],
    ['outcome', 'issue_refund', 'refused'],
    ['intent', 'explode', undefined],
    ['outcome', 'explode', 'error'],
  ])
  const intent = es[0]
  assert.deepEqual(intent.principal, { kind: 'agent', id: 'support' })
  assert.equal(intent.action?.target, 'stripe:ch_1')
  assert.equal((intent.ext as any).langchain.tool_call_id, 'call_0_0')
  // The arguments are pinned as a keyed digest and never stored.
  assert.equal(intent.inputs?.length, 1)
  assert.equal(intent.inputs![0].ref, 'langchain:tool_call/call_0_0')
  assert.match(intent.inputs![0].digest, /^hmac-sha256:/)
  assert.deepEqual(ran, ['ch_1'])
  assert.ok((await log.verify(log.fingerprint!)).ok)
  await log.close()
})

test('a crash mid-action leaves the intent', async () => {
  const dir = tmp()
  const child = spawnSync(process.execPath, [join(import.meta.dirname, 'crash.mts'), dir], { encoding: 'utf8' })
  assert.equal(child.status, 3, child.stderr)
  const log = await Tenbri.open(join(dir, 's'), { keys: join(dir, 'keys') })
  assert.deepEqual(shape(await decisions(log)), [['intent', 'deploy', undefined]])
  assert.ok((await log.verify(log.fingerprint!)).ok)
})

test('fail closed, and fail open', async () => {
  ran.length = 0
  const dir = tmp()
  await (await open(dir)).close()
  const readOnly = await Tenbri.open(join(dir, 's'), { keys: join(dir, 'elsewhere') })
  const calls: Parameters<typeof model>[0] = [[['lookup', { order: 'o1' }]]]
  const closed = createAgent({ model: model(calls), tools: [lookup] })
  // The failed intent fails the tool call: ToolNode reports it to the model, and the tool never ran.
  const out = await closed.invoke(msg('x'), { callbacks: [new TenbriCallbackHandler(readOnly)] })
  assert.ok(out.messages.some((m: any) => /read-only/.test(String(m.content))))
  assert.deepEqual(ran, [])
  const open_ = createAgent({ model: model(calls), tools: [lookup] })
  await open_.invoke(msg('x'), { callbacks: [new TenbriCallbackHandler(readOnly, { failOpen: true })] })
  assert.deepEqual(ran, ['o1'])
})

test('tool selection and inputs', async () => {
  const log = await open()
  const h = new TenbriCallbackHandler(log, {
    principal: 'agent:billing',
    tools: ['issue_refund'],
    inputs: () => [{ ref: 'policy:refund', version: '14', content: 'refunds under 50 EUR are automatic' }],
  })
  const calls: Parameters<typeof model>[0] = [[['lookup', { order: 'o1' }], ['issue_refund', { charge: 'ch_1', amount: 5 }]]]
  await createAgent({ model: model(calls), tools: [lookup, issueRefund] }).invoke(msg('x'), { callbacks: [h] })
  const es = await decisions(log)
  assert.deepEqual(new Set(es.map((e) => e.action?.type)), new Set(['issue_refund']))
  assert.deepEqual(es[0].principal, { kind: 'agent', id: 'billing' })
  assert.deepEqual(es[0].inputs?.map((i) => i.ref), ['policy:refund', 'langchain:tool_call/call_0_1'])
  assert.deepEqual((await log.query({ inputs: ['policy:refund@14'] })).map((m) => m.entry.phase), ['intent'])
})

// per_call HITL is new in langchain 1.5.
const langchain = JSON.parse(readFileSync(join(import.meta.dirname, '..', 'node_modules', 'langchain', 'package.json'), 'utf8'))
const perCall = Number(langchain.version.split('.')[1]) >= 5 ? false : 'per_call HITL is new in langchain 1.5'

for (const interruptMode of ['batched', 'per_call'] as const) {
  test(`human approval, ${interruptMode}`, { skip: interruptMode === 'per_call' && perCall }, async () => {
    ran.length = 0
    const log = await open()
    const h = new TenbriCallbackHandler(log)
    const agent = createAgent({
      model: model([[['issue_refund', { charge: 'ch_1', amount: 20 }], ['issue_refund', { charge: 'ch_2', amount: 30 }]]]),
      tools: [issueRefund],
      middleware: [humanInTheLoopMiddleware({ interruptOn: { issue_refund: true }, interruptMode } as any)],
      checkpointer: new MemorySaver(),
      name: 'support',
    })
    const config = { callbacks: [h], configurable: { thread_id: 't1' } }
    await agent.invoke(msg('refund both'), config)
    assert.deepEqual(await decisions(log), []) // paused before either call

    const approve = { type: 'approve' }
    const reject = { type: 'reject', message: 'no' }
    let answer: unknown
    // A batch with a rejection runs none of its calls in LangChain.js: approve both there.
    if (interruptMode === 'batched') {
      answer = { decisions: [approve, approve] }
    } else {
      const state: { tasks: Array<{ interrupts: Array<{ id?: string }> }> } = await agent.getState(config)
      const ids = state.tasks.flatMap((t) => t.interrupts).map((i) => i.id!)
      answer = Object.fromEntries(ids.map((id, i) => [id, [approve, reject][i]]))
    }
    await agent.invoke(await h.resume(agent, config, answer, { by: 'person:alice' }), config)

    const es = await decisions(log)
    const approval = es.find((e) => e.kind === 'approval')!
    assert.deepEqual(approval.principal, { kind: 'person', id: 'alice' })
    assert.equal((approval.ext as any).langchain.tool_call_id, 'call_0_0')
    assert.equal((approval.ext as any).langchain.thread_id, 't1')
    const intent = es.find((e) => e.phase === 'intent' && e.approval)!
    assert.equal((intent.ext as any).langchain.tool_call_id, 'call_0_0')
    assert.deepEqual((intent.approval as any).by, { kind: 'person', id: 'alice' })
    const refused = es.filter((e) => e.status === 'refused')
    if (interruptMode === 'batched') {
      assert.equal(es.filter((e) => e.phase === 'intent' && e.approval).length, 2)
      assert.deepEqual([...ran].sort(), ['ch_1', 'ch_2']) // the two calls run in parallel
    } else {
      assert.equal(refused.length, 1)
      assert.deepEqual(refused[0].principal, { kind: 'agent', id: 'support' })
      assert.equal((es.find((e) => (e.ext as any)?.langchain?.decision)!.ext as any).langchain.reviewer, 'person:alice')
      assert.deepEqual(ran, ['ch_1'])
    }
    assert.ok((await log.verify(log.fingerprint!)).ok) // approval.entry names the approval: verified
  })
}

test('trace from OpenTelemetry', async () => {
  context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable())
  const log = await open()
  const agent = createAgent({ model: model([[['lookup', { order: 'o1' }]]]), tools: [lookup] })
  const span = new BasicTracerProvider().getTracer('test').startSpan('request')
  await context.with(trace.setSpan(context.active(), span), () =>
    agent.invoke(msg('x'), { callbacks: [new TenbriCallbackHandler(log)] }),
  )
  assert.equal(((await decisions(log))[0].trace as any)?.trace_id, span.spanContext().traceId)
})
