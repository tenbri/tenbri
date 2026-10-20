// Tenbri for LangGraph and LangChain.js: every tool call recorded as a decision.
//
// A LangChain callback handler with raiseError and awaitHandlers: before a tool runs, its intent is
// durable in the stream, or the tool does not run; after it, the outcome follows (ok, error, or
// refused when the tool throws tenbri's Refused). LangGraph interrupts a person answers are recorded
// with `resume()`: an approved call's intent names the approval entry that granted it.
import { createHash } from 'node:crypto'
import { BaseCallbackHandler } from '@langchain/core/callbacks/base'
import type { Serialized } from '@langchain/core/load/serializable'
import { Command, isGraphBubbleUp } from '@langchain/langgraph'
import { trace as otel } from '@opentelemetry/api'
import { Refused, TenbriError, type Draft, type Entry, type Input, type Principal, type Status, type Tenbri } from 'tenbri'

export type Args = Record<string, unknown>
/** An input to pin: `{ref, version, digest}`, or `{ref, version, content}` digested with the
 * stream's `digestKey`. */
export type PinnedInput = Input | { ref: string; version: string; content: string | Uint8Array }

export interface TenbriCallbackHandlerOptions {
  /** Who acts; default the agent's name (`createAgent({ name })`), else `agent:langgraph`. */
  principal?: Principal
  /** Which tools to record, by name or as a predicate; default all. */
  tools?: string[] | ((tool: string) => boolean)
  /** The reference the call acts on. */
  target?: (tool: string, args: Args) => string | undefined
  /** Inputs to pin to the decision. With a `digestKey`, the call's arguments are pinned too, as a
   * keyed digest. Arguments and results are never stored. */
  inputs?: (tool: string, args: Args) => PinnedInput[]
  /** When the intent can't be written, run the tool anyway (with a warning) instead of failing
   * the call. Off by default: no record, no action. */
  failOpen?: boolean
}

export interface ApproveOptions {
  by: Principal
  toolCallId?: string
  threadId?: string
  checkpointId?: string
}

type Decision = { type: string; editedAction?: { args?: Args }; message?: string }
type Interrupt = { id?: string; value?: any }
/** A compiled graph, or what `createAgent` returns (its graph is `.graph`). */
type Graph = {
  getState(config: any): Promise<{ values: any; config: any; tasks?: Array<{ interrupts?: Interrupt[] }> }>
  config?: { metadata?: Record<string, unknown> }
  graph?: { config?: { metadata?: Record<string, unknown> } }
}

// RFC 8785 for what entries hold (strings, integers, objects, arrays, ASCII keys).
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canon(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v) ?? 'null'
}

/** The entry hash (format v1, 6.2). ponytail: recomputed here; the bindings don't return it. */
function entryHash(e: Entry): string {
  return 'sha256:' + createHash('sha256').update(Buffer.from([0])).update(canon(e)).digest('hex')
}

function statusOf(e: unknown): Status {
  if (e instanceof Refused) return 'refused'
  // An interrupt inside the tool pauses it: it runs again from the start on resume, as a new
  // decision, and whatever it did before the interrupt is not known.
  if (isGraphBubbleUp(e)) return 'unknown'
  return 'error'
}

function currentTrace(): { trace_id: string; span_id: string } | undefined {
  const c = otel.getActiveSpan()?.spanContext()
  if (!c || !otel.isSpanContextValid(c)) return undefined
  return { trace_id: c.traceId, span_id: c.spanId }
}

export class TenbriCallbackHandler extends BaseCallbackHandler {
  name = 'TenbriCallbackHandler'
  readonly log: Tenbri
  readonly #o: TenbriCallbackHandlerOptions
  readonly #open = new Map<string, Entry>()
  /** Tool call id -> the approval entry that granted it, from resume(). */
  readonly #approved = new Map<string, Entry>()

  constructor(log: Tenbri, options: TenbriCallbackHandlerOptions = {}) {
    // raiseError: a failed intent stops the tool, and LangChain awaits the handler, so the intent
    // is durable before the tool runs.
    super({ raiseError: true })
    this.log = log
    this.#o = options
  }

  #selected(tool: string): boolean {
    const t = this.#o.tools
    return t === undefined || (typeof t === 'function' ? t(tool) : t.includes(tool))
  }

  #who(metadata?: Record<string, unknown>): Principal {
    if (this.#o.principal !== undefined) return this.#o.principal
    const name = metadata?.lc_agent_name
    return name ? `agent:${name}` : 'agent:langgraph'
  }

  #pins(tool: string, args: Args, call?: string): Input[] {
    const pins = (this.#o.inputs?.(tool, args) ?? []).map((i) =>
      'content' in i ? { ref: i.ref, version: i.version, digest: this.log.digest(i.content) } : i,
    )
    if (call) {
      try {
        pins.push({ ref: `langchain:tool_call/${call}`, version: 'args', digest: this.log.digest(canon(args)) })
      } catch (e) {
        if (!(e instanceof TenbriError)) throw e // no digestKey
      }
    }
    return pins
  }

  #draft(tool: string, args: Args, principal: Principal, ext: Record<string, string | undefined>, call?: string): Draft {
    const target = this.#o.target?.(tool, args)
    const langchain = Object.fromEntries(Object.entries(ext).filter(([, v]) => v))
    const d: Draft = { action: target === undefined ? { type: tool } : { type: tool, target }, principal, ext: { langchain } }
    const pins = this.#pins(tool, args, call)
    if (pins.length) d.inputs = pins
    const t = currentTrace()
    if (t) d.trace = t
    return d
  }

  async handleToolStart(
    tool: Serialized,
    input: string,
    runId: string,
    _parentRunId?: string,
    _tags?: string[],
    metadata?: Record<string, unknown>,
    runName?: string,
    toolCallId?: string,
  ): Promise<void> {
    const name = runName ?? (tool as { name?: string }).name ?? tool.id.at(-1) ?? 'tool'
    if (!this.#selected(name)) return
    let args: Args
    try {
      const parsed = JSON.parse(input)
      args = parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : { input: parsed }
    } catch {
      args = { input }
    }
    const ext = { run_id: runId, tool_call_id: toolCallId, thread_id: metadata?.thread_id as string | undefined }
    const draft = this.#draft(name, args, this.#who(metadata), ext, toolCallId)
    const a = toolCallId ? this.#approved.get(toolCallId) : undefined
    if (a) {
      this.#approved.delete(toolCallId!)
      draft.approval = { by: a.principal, entry: entryHash(a) }
    }
    try {
      this.#open.set(runId, await this.log.intent(draft))
    } catch (e) {
      if (!this.#o.failOpen || !(e instanceof TenbriError)) throw e
      console.warn(`tenbri: ${name} ran unrecorded (fail-open): ${e.message}`)
    }
  }

  async #close(runId: string, status: Status): Promise<void> {
    const intent = this.#open.get(runId)
    if (!intent) return
    this.#open.delete(runId)
    try {
      await this.log.outcome(intent, status)
    } catch (e) {
      // The tool has run: failing it now would only invite a retry. The intent stays open, and
      // the stream's next writer reconciles it as unknown.
      console.warn(`tenbri: outcome of ${intent.id} not recorded: ${(e as Error).message}`)
    }
  }

  async handleToolEnd(output: unknown, runId: string): Promise<void> {
    // A ToolMessage with status "error" is an error the tool handled itself.
    await this.#close(runId, (output as { status?: string } | null)?.status === 'error' ? 'error' : 'ok')
  }

  async handleToolError(err: unknown, runId: string): Promise<void> {
    await this.#close(runId, statusOf(err))
  }

  /** Records that `by` approved a call of `tool`: an `approval` entry. When that call runs (by
   * `toolCallId`), its intent names the approval. For interrupts of your own; `resume()` calls
   * it for LangChain's `humanInTheLoopMiddleware`. */
  async approve(tool: string, args: Args, o: ApproveOptions): Promise<Entry> {
    const ext = { tool_call_id: o.toolCallId, thread_id: o.threadId, checkpoint_id: o.checkpointId }
    const entry = await this.log.append({ ...this.#draft(tool, args, o.by, ext, o.toolCallId), kind: 'approval' })
    if (o.toolCallId) this.#approved.set(o.toolCallId, entry)
    return entry
  }

  /** Records a person's answer to the graph's pending `humanInTheLoopMiddleware` interrupts, then
   * returns `new Command({ resume })` to invoke the graph with.
   *
   * `approve` and `edit` write an approval entry, named by the call's intent when it runs; `reject`
   * writes the call's intent and a `refused` outcome, since it never runs; `respond` writes a
   * note. `resume` is what you would pass to `Command({ resume })`: `{ decisions: [...] }` or a
   * single decision, or an object of interrupt ids to those. Other interrupts are left to
   * `approve()`. */
  async resume(graph: Graph, config: any, resume: any, { by }: { by: Principal }): Promise<Command> {
    const snap = await graph.getState(config)
    const pending = new Map((snap.tasks ?? []).flatMap((t) => t.interrupts ?? []).map((i) => [i.id ?? '', i.value]))
    let answers: Map<string, any>
    if (resume && typeof resume === 'object' && Object.keys(resume).length && Object.keys(resume).every((k) => pending.has(k))) {
      answers = new Map(Object.entries(resume))
    } else if (pending.size === 1) {
      answers = new Map([[[...pending.keys()][0], resume]])
    } else {
      throw new Error('several interrupts are pending: key the answers by interrupt id')
    }
    const conf = snap.config?.configurable ?? {}
    const where = { threadId: conf.thread_id, checkpointId: conf.checkpoint_id }
    const agent = this.#who((graph.graph ?? graph).config?.metadata)
    for (const [id, answer] of answers) {
      const value = pending.get(id)
      if (!value || typeof value !== 'object') continue
      let calls: Array<[string | undefined, string, Args, Decision]>
      if (value.type === 'tool_approval') {
        calls = [[value.tool_call_id, value.name, value.args, answer]]
      } else if (Array.isArray(value.actionRequests)) {
        const ids = callIds(snap.values, value.actionRequests)
        calls = value.actionRequests.map((r: { name: string; args: Args }, i: number) => [ids[i], r.name, r.args, answer.decisions[i]])
      } else {
        continue
      }
      for (const [call, tool, args, decision] of calls) await this.#record(decision, tool, args, by, agent, call, where)
    }
    return new Command({ resume })
  }

  async #record(
    decision: Decision,
    tool: string,
    args: Args,
    by: Principal,
    agent: Principal,
    call: string | undefined,
    where: { threadId?: string; checkpointId?: string },
  ): Promise<void> {
    if (decision.type === 'approve' || decision.type === 'edit') {
      const a = decision.type === 'edit' ? (decision.editedAction?.args ?? args) : args
      await this.approve(tool, a, { by, toolCallId: call, ...where })
      return
    }
    const reviewer = typeof by === 'string' ? by : `${by.kind}:${by.id}`
    const ext = { tool_call_id: call, thread_id: where.threadId, checkpoint_id: where.checkpointId, decision: decision.type, reviewer }
    if (decision.type === 'reject') {
      const intent = await this.log.intent(this.#draft(tool, args, agent, ext, call))
      await this.log.outcome(intent, 'refused')
    } else if (decision.type === 'respond') {
      await this.log.append({ ...this.#draft(tool, args, by, ext, call), kind: 'note' })
    }
  }
}

/** The tool call ids of a batched HITL request, from the last AI message: its action requests are
 * its gated calls, in order, with the same name and arguments. */
function callIds(values: any, requests: Array<{ name: string; args: Args }>): Array<string | undefined> {
  const messages: any[] = values?.messages ?? []
  const left: Array<{ id?: string; name: string; args: Args }> = [
    ...([...messages].reverse().find((m) => m?.tool_calls?.length)?.tool_calls ?? []),
  ]
  return requests.map((r) => {
    const i = left.findIndex((c) => c.name === r.name && canon(c.args) === canon(r.args))
    return i < 0 ? undefined : left.splice(i, 1)[0].id
  })
}
