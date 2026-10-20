// The adapter under the real Agent SDK, its CLI replaced by testing/fake-claude.mjs: no model, no
// API key. Each test plays tool calls through the SDK and reads back what the stream holds.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { query, type CanUseTool, type SDKUserMessage } from '@anthropic-ai/claude-agent-sdk'
import { context, trace, TraceFlags } from '@opentelemetry/api'
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks'
import { Tenbri, agent, init, type Entry } from 'tenbri'
import { TenbriHooks, entryHash, instrumentClaudeAgentSdk, type TenbriHooksOptions } from '../src/index.js'

const FAKE = fileURLToPath(new URL('../../../testing/fake-claude.mjs', import.meta.url))
context.setGlobalContextManager(new AsyncLocalStorageContextManager().enable())

interface Call {
  tool: string
  input: Record<string, unknown>
  id: string
  ask?: boolean
  result: 'ok' | 'error' | 'interrupt' | 'denied' | 'crash'
}
type Answers = Record<string, any> & { crashed: boolean }

async function* prompt(): AsyncGenerator<SDKUserMessage> {
  // canUseTool needs a streamed prompt.
  yield { type: 'user', message: { role: 'user', content: 'go' }, parent_tool_use_id: null, session_id: '' }
}

/** Plays `calls`; returns the SDK's answers per call id (`crashed` if the CLI died). */
async function session(
  log: Tenbri,
  calls: Call[],
  o: Partial<TenbriHooksOptions> & { canUseTool?: CanUseTool } = {},
): Promise<Answers> {
  const { canUseTool, ...hooks } = o
  const options = new TenbriHooks(log, { principal: 'agent:support', ...hooks }).instrument({
    pathToClaudeCodeExecutable: FAKE,
    executable: 'node',
    env: { ...process.env, FAKE_CLAUDE_SCENARIO: JSON.stringify(calls) },
    ...(canUseTool && { canUseTool }),
  })
  const answers: Answers = { crashed: false }
  try {
    for await (const m of query({ prompt: prompt(), options })) {
      if (m.type === 'result' && m.subtype === 'success') {
        for (const a of JSON.parse(m.result)) answers[a.id] = a
      }
    }
  } catch {
    answers.crashed = true
  }
  return answers
}

async function entries(log: Tenbri): Promise<Entry[]> {
  return (await log.query()).map((m) => m.entry).filter((e) => e.kind === 'decision' || e.kind === 'approval')
}

async function openLog(digestKey?: string): Promise<Tenbri> {
  const dir = mkdtempSync(join(tmpdir(), 'tenbri-claude-'))
  return Tenbri.open(join(dir, 'stream'), { keys: join(dir, 'keys'), create: true, digestKey })
}

const shape = (e: Entry) => [e.kind, e.phase, e.status]

test('the conformance scenario: one call allowed by a person, one refused, one crash mid-action', async () => {
  const log = await openLog()
  const ask: CanUseTool = async (tool) =>
    tool === 'Bash' ? { behavior: 'deny', message: 'no' } : { behavior: 'allow', updatedInput: {} }
  const answers = await session(
    log,
    [
      { tool: 'Read', input: { file_path: '/srv/policy.md' }, id: 't1', ask: true, result: 'ok' },
      { tool: 'Bash', input: { command: 'rm -rf /' }, id: 't2', ask: true, result: 'ok' },
      { tool: 'Write', input: { file_path: '/srv/out' }, id: 't3', result: 'crash' },
    ],
    { canUseTool: ask, approver: 'person:alice' },
  )
  assert.ok(answers.crashed)
  const e = await entries(log)
  assert.deepEqual(e.map(shape), [
    ['decision', 'intent', undefined],
    ['approval', undefined, undefined],
    ['decision', 'outcome', 'ok'],
    ['decision', 'intent', undefined],
    ['decision', 'outcome', 'refused'],
    ['decision', 'intent', undefined],
  ])
  const [read, approval, ok, bash, refused, write] = e
  assert.deepEqual(read.principal, { kind: 'agent', id: 'support' })
  assert.deepEqual(read.action, { type: 'Read', target: '/srv/policy.md' })
  assert.deepEqual(approval.principal, { kind: 'person', id: 'alice' })
  assert.equal(ok.intent, read.id)
  assert.deepEqual(ok.approval, { by: approval.principal, entry: entryHash(approval) })
  assert.deepEqual(bash.action, { type: 'Bash' }) // the command is not stored
  assert.equal(refused.intent, bash.id)
  assert.equal(write.action?.type, 'Write') // open: reconciled as unknown later
  assert.ok((await log.verify(log.fingerprint ?? undefined)).ok)
  await log.close()
})

test('errors, interrupts and denials by a rule', async () => {
  const log = await openLog()
  await session(log, [
    { tool: 'WebFetch', input: { url: 'https://x.test' }, id: 'e', result: 'error' },
    { tool: 'Bash', input: { command: 'sleep 9' }, id: 'i', result: 'interrupt' },
    { tool: 'Edit', input: { file_path: '/etc/hosts' }, id: 'd', result: 'denied' },
  ])
  const outcomes = (await entries(log)).filter((e) => e.phase === 'outcome').map((e) => e.status)
  assert.deepEqual(outcomes, ['error', 'unknown', 'refused'])
  await log.close()
})

test('tool selection, input mapping and pinned inputs', async () => {
  const log = await openLog('k'.repeat(32))
  const input = { charge: 'ch_1', amount: 20 }
  await session(
    log,
    [
      { tool: 'mcp__stripe__refund', input, id: 'r', result: 'ok' },
      { tool: 'Read', input: { file_path: '/a' }, id: 's', result: 'ok' },
    ],
    {
      tools: ['mcp__stripe__refund'],
      describe: (_, i) => ({
        action: 'issue_refund',
        target: `stripe:${i.charge}`,
        rule: { ref: 'policy:refund', version: '14', result: 'allow' },
      }),
    },
  )
  const [intent, outcome, ...rest] = await entries(log) // Read is not selected
  assert.equal(rest.length, 0)
  assert.deepEqual(intent.action, { type: 'issue_refund', target: 'stripe:ch_1' })
  assert.equal(intent.rule?.version, '14')
  const digest = log.digest('{"amount":20,"charge":"ch_1"}')
  assert.deepEqual(intent.inputs, [{ ref: 'claude:tool_input', version: 'r', digest }])
  assert.equal(outcome.status, 'ok')
  assert.deepEqual((await log.query({ inputs: ['claude:tool_input@r'] })).map((m) => m.entry.id), [intent.id])
  await log.close()
})

for (const failOpen of [false, true]) {
  test(`fail ${failOpen ? 'open when asked' : 'closed by default'}`, async () => {
    const log = await openLog()
    await log.close() // nothing can be written
    const answers = await session(log, [{ tool: 'Bash', input: { command: 'ls' }, id: 'b', result: 'ok' }], {
      failOpen,
    })
    const decision = answers.b.pre[0].response.hookSpecificOutput?.permissionDecision
    assert.equal(decision === 'deny', !failOpen)
    assert.equal('post' in answers.b, failOpen) // the tool ran
  })
}

test('the trace of the active OpenTelemetry span', async () => {
  const log = await openLog()
  const span = { traceId: 'abc'.padStart(32, '0'), spanId: 'def'.padStart(16, '0'), traceFlags: TraceFlags.SAMPLED }
  await context.with(trace.setSpanContext(context.active(), span), () =>
    session(log, [{ tool: 'Read', input: {}, id: 't', result: 'ok' }]),
  )
  const e = await entries(log)
  assert.equal(e.length, 2)
  for (const x of e) assert.deepEqual(x.trace, { trace_id: span.traceId, span_id: span.spanId })
  await log.close()
})

test('the one-liner: init() and instrumentClaudeAgentSdk(), mapping from tenbri.toml, approver from the environment', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'tenbri-claude-'))
  writeFileSync(join(dir, 'tenbri.toml'), '[actions.issue_refund]\ntarget = "stripe:{charge}"\npolicy = "policy:refund@14"\n')
  Object.assign(process.env, {
    TENBRI_STREAM: join(dir, 'stream'),
    TENBRI_KEYS: join(dir, 'keys'),
    TENBRI_AGENT: 'agent:support',
    TENBRI_APPROVER: 'person:alice',
    TENBRI_SCHEMA: join(dir, 'tenbri.toml'),
  })
  const log = await init()
  const options = (calls: Call[]) => ({
    pathToClaudeCodeExecutable: FAKE,
    executable: 'node' as const,
    env: { ...process.env, FAKE_CLAUDE_SCENARIO: JSON.stringify(calls) },
    canUseTool: (async (_tool, input) => ({ behavior: 'allow', updatedInput: input })) as CanUseTool,
  })
  const play = async (o: ReturnType<typeof options>) => {
    for await (const _ of query({ prompt: prompt(), options: instrumentClaudeAgentSdk(o) }));
  }
  await play(options([{ tool: 'mcp__billing__issue_refund', input: { charge: 'ch_1', amount: 20 }, id: 'r', ask: true, result: 'ok' }]))
  await agent('agent:triage', () => play(options([{ tool: 'Read', input: { file_path: '/a' }, id: 'c', result: 'ok' }])))
  const [intent, approval, outcome, read, readOk] = await entries(log)
  assert.deepEqual(intent.principal, { kind: 'agent', id: 'support' })
  assert.deepEqual(intent.action, { type: 'issue_refund', target: 'stripe:ch_1' })
  assert.deepEqual(intent.rule, { ref: 'policy:refund', version: '14', result: 'allow' })
  assert.deepEqual(intent.inputs?.map((i) => i.ref), ['claude:tool_input']) // keyed by the key store
  assert.deepEqual(approval.principal, { kind: 'person', id: 'alice' })
  assert.equal(outcome.status, 'ok')
  assert.equal((outcome.approval as { entry: string }).entry, entryHash(approval))
  assert.deepEqual(read.principal, { kind: 'agent', id: 'triage' })
  assert.deepEqual(read.action, { type: 'Read', target: '/a' })
  assert.equal(readOk.status, 'ok')
  await log.close()
  for (const v of ['TENBRI_STREAM', 'TENBRI_KEYS', 'TENBRI_AGENT', 'TENBRI_APPROVER', 'TENBRI_SCHEMA']) delete process.env[v]
})
