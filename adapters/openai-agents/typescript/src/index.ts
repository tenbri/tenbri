// Tenbri for the OpenAI Agents SDK: every tool call and handoff recorded as a decision.
//
//   import { init } from 'tenbri'
//   import { instrumentOpenAIAgents } from '@tenbri/openai-agents'
//
//   init()
//   instrumentOpenAIAgents()
//   // every run() from here on is recorded, and every RunState approve() and reject()
//
// `TenbriRecorder` is the lower level, on a stream you opened:
//
//   const log = await Tenbri.open('./audit/support', { create: true })
//   const recorder = new TenbriRecorder(log)
//   recorder.instrument(agent)
//   const result = await run(agent, 'refund ch_123')
//   await recorder.flush()
//
// The JS SDK's run hooks are event emitters it does not await, so they cannot hold a tool back
// until its intent is durable. The recorder adds a tool input guardrail instead, after the tool's
// own: the SDK awaits it before the tool runs, so a failed write stops the tool (fail closed).
// Outcomes and handoffs are written in the background, in order; the next intent and flush() wait
// for them and throw what failed.
import { createHash } from 'node:crypto'
import {
  Agent,
  Handoff,
  RunState as RunStateClass,
  Runner,
  getCurrentSpan,
  getCurrentTrace,
  type FunctionTool,
  type RunState,
  type RunToolApprovalItem,
  type ToolGuardrailFunctionOutput,
  type ToolInputGuardrailData,
  type ToolInputGuardrailDefinition,
} from '@openai/agents-core'
import {
  TenbriError,
  approverOf,
  defaultStream,
  describe as describeAction,
  type Actions,
  type Described,
  type Draft,
  type Entry,
  type Input,
  type Principal,
  type Status,
  type Tenbri,
} from 'tenbri'

/** An input to pin: its `content` is digested with the stream's `digestKey`, or `digest` is given. */
export interface InputSpec {
  ref: string
  version: string
  content?: string | Uint8Array
  digest?: string
}

export interface RecorderOptions {
  /** The tools recorded: names, or a predicate. Default: every function tool. */
  tools?: string[] | ((tool: string) => boolean)
  /** The action type of a tool; default its name. */
  action?: (tool: string) => string
  /** The action's target, from the tool's name and parsed arguments. */
  target?: (tool: string, args: Record<string, unknown>) => string | undefined
  /** Inputs a call relied on, pinned by keyed digest. */
  inputs?: (tool: string, args: Record<string, unknown>) => InputSpec[]
  /** The pseudonymous handle of the person the run is about (per-subject keys, erasure). */
  subject?: string
  /** Any of `action`, `target`, `rule` and `subject` from the tool's name and parsed arguments, at
   * once, over the options above. */
  describe?: (tool: string, args: Record<string, unknown>) => Described
  /** Let actions run when the stream cannot be written (warned, not recorded). Default: block. */
  failOpen?: boolean
  /** Whether a tool's output means it failed. Default: the SDK's own error and timeout messages. */
  isError?: (output: unknown) => boolean
}

interface Call {
  agent: Agent<any, any>
  name: string
  arguments?: string
  callId: string
}

const allow: ToolGuardrailFunctionOutput = { behavior: { type: 'allow' } }
const owners = new WeakMap<object, TenbriRecorder>()

/** What the SDK tells the model when a tool threw or timed out. */
export function sdkError(output: unknown): boolean {
  return (
    typeof output === 'string' &&
    (output === 'An error occurred while running the tool. Please try again.' ||
      /^Tool '.*' timed out after \d+ms\.$/.test(output))
  )
}

/**
 * Records an agent's tool calls, handoffs and approvals in a Tenbri stream.
 *
 * - A tool call: an intent by `agent:<name>` (action the tool's name) before the tool runs, then
 *   the outcome `ok` or `error`.
 * - A call a tool input guardrail rejects or trips, or a person rejects: an intent and `refused`.
 * - A handoff: an intent and `ok`, action `handoff`, target `agent:<next>`.
 * - {@link approve}: an `approval` entry, which the tool's intent names.
 *
 * Tool arguments and results are never written.
 */
export class TenbriRecorder {
  readonly log: Tenbri
  #o: RecorderOptions
  #reads: Input[] = []
  #open = new Map<string, Entry>()
  #returned = new Map<string, Status>()
  #approvals = new Map<string, { by: Entry['principal']; entry: string }>()
  #pending: Promise<unknown> = Promise.resolve()
  #failure: unknown

  constructor(log: Tenbri, options: RecorderOptions = {}) {
    this.log = log
    this.#o = options
  }

  /** Records `agent`'s function tools and handoffs, and those of the agents it hands off to. */
  instrument<A extends Agent<any, any>>(agent: A): A {
    if (this.#claim(agent)) {
      for (const tool of agent.tools) {
        if (tool.type === 'function' && this.#selected(tool.name) && this.#claim(tool)) this.#guard(tool)
      }
      agent.on('agent_handoff', (_context, next) => {
        const action = { type: 'handoff', target: `agent:${next.name}` }
        const draft = { ...this.#trace(), principal: who(agent), action, subject: this.#o.subject }
        this.#later(() => this.#decide(draft, 'ok'))
      })
      agent.on('agent_tool_end', (_context, _tool, _output, { toolCall }) => {
        if (toolCall.type !== 'function_call') return
        const intent = this.#open.get(toolCall.callId)
        if (!intent) return
        this.#open.delete(toolCall.callId)
        // No output guardrail ran: the tool threw.
        const status = this.#returned.get(toolCall.callId) ?? 'error'
        this.#returned.delete(toolCall.callId)
        this.#later(() => this.log.outcome(intent, status))
      })
      for (const h of agent.handoffs) this.instrument(h instanceof Handoff ? h.agent : h)
    }
    return agent
  }

  /** Pins `ref` at `version` to the next decision, by the keyed digest of `content`. */
  read(ref: string, read: { version: string; content?: string | Uint8Array; digest?: string }): void {
    this.#reads.push(this.#input({ ref, ...read }))
  }

  /** Approves `item` on `state` as `by` (`'person:alice'`): the approval is recorded first, and the
   * tool's intent names it. */
  async approve(state: RunState<any, any>, item: RunToolApprovalItem, by: Principal, options?: { alwaysApprove?: boolean }) {
    const call = this.#call(item)
    if (call) {
      await this.flush()
      const draft = { kind: 'approval' as const, principal: by, action: this.#action(call), subject: this.#o.subject }
      const entry = await this.#write(() => this.log.append(draft))
      if (entry) this.#approvals.set(call.callId, { by: entry.principal, entry: entryHash(entry) })
    }
    state.approve(item, options)
  }

  /** Rejects `item` on `state` as `by`: recorded as a refused decision whose outcome names `by`. */
  async reject(state: RunState<any, any>, item: RunToolApprovalItem, by: Principal, options?: { message?: string }) {
    const call = this.#call(item)
    if (call) {
      await this.flush()
      await this.#write(() => this.#decide(this.#draft(call), 'refused', { principal: by }))
    }
    state.reject(item, options)
  }

  /** Records a person's answer to `item` in the background, before the next intent: an approval
   * by `by`, which the tool's intent names, or a refused decision. Does not answer `state`. */
  answer(item: RunToolApprovalItem, approved: boolean, by: Principal | undefined): void {
    const call = this.#call(item)
    if (!call) return
    if (!approved) {
      this.#later(() => this.#decide(this.#draft(call), 'refused', by === undefined ? undefined : { principal: by }))
    } else if (by === undefined) {
      console.warn(`tenbri: ${call.callId} approved by nobody known: set TENBRI_APPROVER`)
    } else {
      const draft = { kind: 'approval' as const, principal: by, action: this.#action(call), subject: this.#o.subject }
      this.#later(async () => {
        const entry = await this.log.append(draft)
        this.#approvals.set(call.callId, { by: entry.principal, entry: entryHash(entry) })
      })
    }
  }

  /** Waits for the entries written in the background; throws the first that failed. */
  async flush(): Promise<void> {
    await this.#pending
    const failure = this.#failure
    this.#failure = undefined
    if (failure !== undefined) throw failure
  }

  #claim(o: object): boolean {
    const owner = owners.get(o)
    if (owner && owner !== this) throw new Error('already recorded by another TenbriRecorder')
    owners.set(o, this)
    return !owner
  }

  #guard(tool: FunctionTool<any, any, any>) {
    const watched = (tool.inputGuardrails ?? []).map((g) => ({
      ...g,
      run: async (data: ToolInputGuardrailData) => {
        const out = await g.run(data)
        const b = out.behavior?.type
        if (b === 'rejectContent' || b === 'throwException') {
          await this.flush()
          await this.#write(() => this.#decide(this.#draft(callOf(data)), 'refused'))
        }
        return out
      },
    }))
    const intent: ToolInputGuardrailDefinition = {
      type: 'tool_input',
      name: 'tenbri',
      run: async (data) => {
        await this.flush()
        const call = callOf(data)
        const entry = await this.#write(() => this.log.intent(this.#draft(call)))
        if (entry) this.#open.set(call.callId, entry)
        return allow
      },
    }
    tool.inputGuardrails = [...watched, intent]
    tool.outputGuardrails = [
      {
        type: 'tool_output',
        name: 'tenbri',
        run: async ({ toolCall, output }) => {
          this.#returned.set(toolCall.callId, (this.#o.isError ?? sdkError)(output) ? 'error' : 'ok')
          return allow
        },
      },
      ...(tool.outputGuardrails ?? []),
    ]
  }

  #selected(tool: string): boolean {
    const t = this.#o.tools
    return t === undefined || (typeof t === 'function' ? t(tool) : t.includes(tool))
  }

  #call(item: RunToolApprovalItem): Call | undefined {
    const raw = item.rawItem
    if (raw.type !== 'function_call' || !this.#selected(raw.name)) return undefined
    return { agent: item.agent, name: raw.name, arguments: raw.arguments, callId: raw.callId }
  }

  #described(call: Call): Described {
    return this.#o.describe?.(call.name, parse(call.arguments)) ?? {}
  }

  #action(call: Call) {
    const d = this.#described(call)
    const target = d.target ?? this.#o.target?.(call.name, parse(call.arguments))
    return { type: d.action ?? this.#o.action?.(call.name) ?? call.name, ...(target ? { target } : {}) }
  }

  #draft(call: Call): Draft {
    const mapped = this.#o.inputs?.(call.name, parse(call.arguments)) ?? []
    const inputs = [...this.#reads, ...mapped.map((i) => this.#input(i))]
    this.#reads = []
    const approval = this.#approvals.get(call.callId)
    this.#approvals.delete(call.callId)
    const { rule, subject } = this.#described(call)
    return {
      ...this.#trace(),
      principal: who(call.agent),
      action: this.#action(call),
      ...(inputs.length ? { inputs } : {}),
      ...(approval ? { approval } : {}),
      ...(rule ? { rule } : {}),
      subject: subject ?? this.#o.subject,
    }
  }

  #input(i: InputSpec): Input {
    if (i.digest === undefined && i.content === undefined) throw new TypeError(`input ${i.ref}: content or digest`)
    return { ref: i.ref, version: i.version, digest: i.digest ?? this.log.digest(i.content!) }
  }

  /** The SDK's current trace and span, when it is tracing. */
  #trace(): { trace?: { trace_id: string; span_id: string } } {
    const traceId = getCurrentTrace()?.traceId.replace(/^trace_/, '') ?? ''
    // ponytail: the SDK's span ids have 24 hex digits, the format's 16; the first 16 still find
    // the span in a trace.
    const spanId = getCurrentSpan()?.spanId.replace(/^span_/, '').slice(0, 16) ?? ''
    return /^[0-9a-f]{32}$/.test(traceId) && /^[0-9a-f]{16}$/.test(spanId)
      ? { trace: { trace_id: traceId, span_id: spanId } }
      : {}
  }

  /** An intent and its outcome at once: refusals and handoffs. */
  async #decide(draft: Draft, status: Status, fields?: Draft): Promise<Entry> {
    return this.log.outcome(await this.log.intent(draft), status, fields)
  }

  async #write<T>(append: () => Promise<T>): Promise<T | undefined> {
    try {
      return await append()
    } catch (e) {
      if (!this.#o.failOpen || !(e instanceof TenbriError)) throw e
      console.warn(`tenbri: not recorded, the action goes ahead (failOpen): ${e.message}`)
      return undefined
    }
  }

  /** Appends in the background, after what is already queued. */
  #later(append: () => Promise<unknown>) {
    this.#pending = this.#pending
      .then(() => this.#write(append))
      .catch((e: unknown) => {
        this.#failure ??= e
      })
  }
}

function callOf({ agent, toolCall }: ToolInputGuardrailData): Call {
  return { agent, name: toolCall.name, arguments: toolCall.arguments, callId: toolCall.callId }
}

function who(agent: Agent<any, any>) {
  return { kind: 'agent' as const, id: agent.name }
}

function parse(args: string | undefined): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(args || '{}')
    return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

/** RFC 8785 canonical JSON, for what entries hold (strings, integers, objects, arrays). */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`)
      .join(',')}}`
  }
  return JSON.stringify(v)
}

/** The entry hash (format v1, 6.2): SHA-256 of 0x00 and the stored line. */
// ponytail: the binding returns the entry parsed, not its stored line, so the line is rebuilt; an
// entryHash from the binding would remove this.
export function entryHash(entry: Entry): string {
  return `sha256:${createHash('sha256').update(Buffer.from([0])).update(canonical(entry)).digest('hex')}`
}

export interface InstrumentOptions extends Pick<RecorderOptions, 'tools' | 'subject' | 'failOpen'> {
  /** Per tool name, over the action schemas of tenbri.toml: `{ issue_refund: { target:
   * 'stripe:{charge}', policy: 'policy:refund@14' } }`. */
  actions?: Actions
  /** Who answers an interruption: a principal, or a function of the item. Default
   * `init({ approver })` or TENBRI_APPROVER. */
  approver?: Principal | ((item: RunToolApprovalItem) => Principal | undefined)
}

const originals: { run?: Runner['run']; approve?: RunState<any, any>['approve']; reject?: RunState<any, any>['reject'] } = {}

/**
 * Records every run from now on (`run()` and `Runner.run`, streamed or not) on the stream `init()`
 * opened, and every `RunState` approve() and reject(). Each tool call is by `agent:<the agent's
 * name>`, the action of the tool's name or of the action schema in tenbri.toml of that name: the
 * schema's `target` (`stripe:{charge}`) is filled from the call's arguments and its `policy` is
 * the rule. `actions` overrides that per tool name.
 */
export function instrumentOpenAIAgents(o: InstrumentOptions = {}): void {
  uninstrumentOpenAIAgents()
  const run = (originals.run = Runner.prototype.run)
  const approve = (originals.approve = RunStateClass.prototype.approve)
  const reject = (originals.reject = RunStateClass.prototype.reject)
  Runner.prototype.run = async function (this: Runner, agent: Agent<any, any>, ...rest: any[]) {
    const log = await defaultStream()
    if (!owners.has(agent)) {
      const describe = (tool: string, args: Record<string, unknown>) => describeAction(tool, args, o.actions)
      new TenbriRecorder(log, { ...o, describe, failOpen: o.failOpen ?? log.failOpen }).instrument(agent)
    }
    const result = await (run as any).call(this, agent, ...rest)
    // A streamed run is still going: its entries are written as it goes, and before the next.
    if (!rest[1]?.stream) await owners.get(agent)!.flush()
    return result
  } as Runner['run']
  RunStateClass.prototype.approve = function (this: RunState<any, any>, item, ...rest) {
    owners.get(item.agent)?.answer(item, true, approverOf(o.approver, item))
    return approve.call(this, item, ...rest)
  }
  RunStateClass.prototype.reject = function (this: RunState<any, any>, item, ...rest) {
    owners.get(item.agent)?.answer(item, false, approverOf(o.approver, item))
    return reject.call(this, item, ...rest)
  }
}

/** Stops recording runs started from now on (agents already recorded stay recorded). */
export function uninstrumentOpenAIAgents(): void {
  if (originals.run) Runner.prototype.run = originals.run
  if (originals.approve) RunStateClass.prototype.approve = originals.approve
  if (originals.reject) RunStateClass.prototype.reject = originals.reject
  delete originals.run
}
