#!/usr/bin/env node
// A stand-in for the Claude Code CLI that both Agent SDKs drive over stdin/stdout (stream-json and
// the control protocol), so the adapter's tests run the real SDK with no model and no API key.
//
// FAKE_CLAUDE_SCENARIO is a JSON array of tool calls, played after the first user message:
//   { "tool": "Read", "input": {...}, "id": "toolu_1",
//     "ask": true,          // ask the SDK's canUseTool before running it
//     "result": "ok" | "error" | "interrupt" | "denied" | "crash" }
// "denied" is a denial outside canUseTool (a permission rule, auto mode): PermissionDenied hooks.
// "crash" exits mid-action, after PreToolUse, as a killed process would.
// The result message's `result` is a JSON array of what the SDK answered: one
// { id, pre: [hook outputs], permission, post: [hook outputs] } per call.
import { createInterface } from 'node:readline'

if (process.argv.includes('-v') || process.argv.includes('--version')) {
  console.log('2.9.99 (Claude Code)')
  process.exit(0)
}

const scenario = JSON.parse(process.env.FAKE_CLAUDE_SCENARIO ?? '[]')
const session_id = 'fake-session'
const send = (m) => process.stdout.write(JSON.stringify(m) + '\n')

let hooks = {}
let next = 0
const pending = new Map()
function request(body) {
  const request_id = `fake_${++next}`
  send({ type: 'control_request', request_id, request: body })
  return new Promise((resolve) => pending.set(request_id, resolve))
}

const matches = (m, tool) => !m || m === '*' || new RegExp(`^(?:${m})$`).test(tool)
async function fire(event, call, extra) {
  const out = []
  for (const { matcher, hookCallbackIds } of hooks[event] ?? []) {
    if (!matches(matcher, call.tool)) continue
    for (const callback_id of hookCallbackIds) {
      const input = {
        session_id,
        transcript_path: '/dev/null',
        cwd: process.cwd(),
        permission_mode: 'default',
        hook_event_name: event,
        tool_name: call.tool,
        tool_input: call.input,
        tool_use_id: call.id,
        ...extra,
      }
      out.push(await request({ subtype: 'hook_callback', callback_id, input, tool_use_id: call.id }))
    }
  }
  return out
}

async function play() {
  const answers = []
  for (const call of scenario) {
    const a = { id: call.id, pre: await fire('PreToolUse', call, {}) }
    answers.push(a)
    if (a.pre.some((r) => r.response?.hookSpecificOutput?.permissionDecision === 'deny')) continue
    if (call.ask) {
      a.permission = await request({
        subtype: 'can_use_tool',
        tool_name: call.tool,
        input: call.input,
        tool_use_id: call.id,
        permission_suggestions: [],
      })
      if (a.permission.response?.behavior !== 'allow') continue
    }
    if (call.result === 'crash') process.exit(137)
    if (call.result === 'denied') {
      a.post = await fire('PermissionDenied', call, { reason: 'denied by a rule' })
    } else if (call.result === 'ok') {
      a.post = await fire('PostToolUse', call, { tool_response: { ok: true }, duration_ms: 1 })
    } else {
      const interrupt = call.result === 'interrupt'
      a.post = await fire('PostToolUseFailure', call, { error: 'boom', is_interrupt: interrupt })
    }
  }
  send({
    type: 'result',
    subtype: 'success',
    is_error: false,
    duration_ms: 1,
    duration_api_ms: 1,
    num_turns: 1,
    result: JSON.stringify(answers),
    stop_reason: 'end_turn',
    session_id,
    total_cost_usd: 0,
    usage: { input_tokens: 0, output_tokens: 0 },
    uuid: '00000000-0000-4000-8000-000000000000',
  })
}

let started = false
for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue
  const m = JSON.parse(line)
  if (m.type === 'control_response') {
    const r = m.response
    pending.get(r.request_id)?.(r.subtype === 'error' ? { error: r.error } : { response: r.response })
    pending.delete(r.request_id)
  } else if (m.type === 'control_request') {
    if (m.request.subtype === 'initialize') {
      hooks = m.request.hooks ?? {}
      send({ type: 'system', subtype: 'init', session_id, tools: [], model: 'fake', cwd: process.cwd() })
    }
    send({
      type: 'control_response',
      response: { subtype: 'success', request_id: m.request_id, response: { commands: [], models: [] } },
    })
  } else if (m.type === 'user' && !started) {
    started = true
    play().catch((e) => {
      console.error(e)
      process.exit(1)
    })
  }
}
