// Tenbri for the Claude Agent SDK: every tool call the agent makes is a signed decision.
//
// Before a tool runs, its intent is durable in the stream; after, its outcome follows (`ok`,
// `error`, `refused`, or `unknown` when interrupted). A tool approved through the SDK's
// `canUseTool` is recorded as an `approval` entry, which the outcome names.
//
//   import { init } from 'tenbri'
//   import { instrumentClaudeAgentSdk } from '@tenbri/claude-agent-sdk'
//
//   init({ agent: 'agent:support' })
//   for await (const m of query({ prompt, options: instrumentClaudeAgentSdk({ ...options }) })) …
//
// `TenbriHooks` is the lower level: one session's hooks, on a stream you opened.
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import type {
  CanUseTool,
  HookCallback,
  HookCallbackMatcher,
  HookEvent,
  HookJSONOutput,
  Options,
} from '@anthropic-ai/claude-agent-sdk'
import {
  TenbriError,
  approverOf,
  defaultStream,
  describe as describeAction,
  who,
  type Actions,
  type Draft,
  type Entry,
  type Input,
  type Principal,
  type Status,
  type Tenbri,
} from 'tenbri'

type Otel = typeof import('@opentelemetry/api')
let otel: Otel | undefined
try {
  otel = createRequire(import.meta.url)('@opentelemetry/api') as Otel
} catch {
  // OpenTelemetry is optional: without it, entries carry no trace.
}

type ToolInput = Record<string, unknown>
type PermissionOptions = Parameters<CanUseTool>[2]

/** The fields of a tool call's intent. `action` renames the action (the tool name by default). */
export interface Description {
  action?: string
  target?: string
  inputs?: Input[]
  rule?: { ref: string; version: string; result: string }
  subject?: string
}

export interface TenbriHooksOptions {
  /** The agent: `'agent:support'`, or a function returning it when a tool is called. */
  principal: Principal | (() => Principal)
  /** The tools to record: names, or a predicate of the name. All by default. */
  tools?: string[] | ((tool: string) => boolean)
  /** Maps a tool call to its intent's fields; the default records the target of file and web tools. */
  describe?: (tool: string, input: ToolInput) => Description | undefined
  /** Who approves through `canUseTool`: a principal (`'person:alice'`), or a function of the call
   * returning one, or nothing when no person approved (your own policy decided). */
  approver?: Principal | ((tool: string, input: ToolInput, options: PermissionOptions) => Principal | undefined)
  /** Run tools whose intent could not be recorded (unrecorded, with a warning). Default: deny them. */
  failOpen?: boolean
  /** How long an intent may take to be durable before the tool fails closed or open, in ms. */
  timeout?: number
}

const TARGETS = ['file_path', 'notebook_path', 'path', 'url']

/** The target of the built-in file and web tools; nothing else. Commands, prompts and contents
 * stay out of the log. */
export function defaultDescribe(_tool: string, input: ToolInput): Description | undefined {
  for (const k of TARGETS) {
    const v = input[k]
    if (typeof v === 'string' && v) return { target: v }
  }
  return undefined
}

// RFC 8785 for what an entry holds (objects, arrays, strings, integers): sorted keys, no whitespace.
// Entry keys are ASCII, so code point order is UTF-16 order.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

/** The entry hash of an entry as stored (what `approval.entry` names): SHA-256 of `0x00` and its
 * canonical bytes. */
export function entryHash(entry: Entry): string {
  return 'sha256:' + createHash('sha256').update(Buffer.from([0])).update(canonical(entry)).digest('hex')
}

function traced<T extends object>(draft: T): T & { trace?: { trace_id: string; span_id: string } } {
  const c = otel?.trace.getActiveSpan()?.spanContext()
  if (!c || !otel?.isSpanContextValid(c)) return draft
  return { ...draft, trace: { trace_id: c.traceId, span_id: c.spanId } }
}

function within<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`not durable within ${ms} ms`)), ms)
  })
  return Promise.race([p, late]).finally(() => clearTimeout(timer))
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e))

/** Records the tool calls of a Claude Agent SDK session in a Tenbri stream. */
export class TenbriHooks {
  readonly #log: Tenbri | (() => Promise<Tenbri>)
  readonly #o: TenbriHooksOptions
  readonly #selected: (tool: string) => boolean
  readonly #open = new Map<string, Entry>()
  readonly #approvals = new Map<string, { by: Entry['principal']; entry: string }>()

  /** `log` is the stream, or a function returning it when a tool is called. */
  constructor(log: Tenbri | (() => Promise<Tenbri>), options: TenbriHooksOptions) {
    this.#log = log
    this.#o = options
    const t = options.tools
    this.#selected = typeof t === 'function' ? t : t ? (tool) => t.includes(tool) : () => true
  }

  /** `options` with Tenbri's hooks added to its own, and its `canUseTool` (if any) wrapped to record
   * approvals and refusals. */
  instrument(options: Options): Options {
    const hooks: Partial<Record<HookEvent, HookCallbackMatcher[]>> = { ...options.hooks }
    const add = (event: string, fn: HookCallback) => {
      const e = event as HookEvent // PermissionDenied is newer than some supported SDKs' types
      hooks[e] = [...(hooks[e] ?? []), { hooks: [fn] }]
    }
    add('PreToolUse', (i, id) => this.#pre(i, id))
    add('PostToolUse', (i, id) => this.#closing(i, id, 'ok'))
    // Interrupted: whether the action ran is not known.
    add('PostToolUseFailure', (i, id) =>
      this.#closing(i, id, 'is_interrupt' in i && i.is_interrupt ? 'unknown' : 'error'),
    )
    add('PermissionDenied', (i, id) => this.#closing(i, id, 'refused'))
    const canUseTool = options.canUseTool && this.canUseTool(options.canUseTool)
    return { ...options, hooks, ...(canUseTool && { canUseTool }) }
  }

  /** Wraps a `canUseTool` callback: a denial is the call's `refused` outcome, an allowance by an
   * `approver` an `approval` entry. */
  canUseTool(fn: CanUseTool): CanUseTool {
    return async (tool, input, options) => {
      const result = await fn(tool, input, options)
      const id = options.toolUseID
      const intent = this.#open.get(id)
      if (!result || !intent) return result // null: no answer from this callback
      if (result.behavior === 'deny') {
        await this.#close(id, 'refused')
        return result
      }
      const a = this.#o.approver
      const by = typeof a === 'function' ? a(tool, input, options) : a
      if (by === undefined) return result
      try {
        const draft = traced({ kind: 'approval' as const, principal: by, action: intent.action })
        const entry = await within((await this.#stream()).append(draft), this.#o.timeout ?? 2000)
        this.#approvals.set(id, { by: entry.principal, entry: entryHash(entry) })
        return result
      } catch (e) {
        if (this.#o.failOpen) {
          console.warn(`tenbri: approval of ${id} not recorded: ${message(e)}`)
          return result
        }
        await this.#close(id, 'refused')
        return { behavior: 'deny', message: `Tenbri could not record the approval: ${message(e)}` }
      }
    }
  }

  #stream(): Promise<Tenbri> {
    return typeof this.#log === 'function' ? this.#log() : Promise.resolve(this.#log)
  }

  #draft(log: Tenbri, tool: string, input: ToolInput, id: string): Draft {
    const { action, target, inputs = [], ...fields } = (this.#o.describe ?? defaultDescribe)(tool, input) ?? {}
    const pinned = [...inputs]
    try {
      pinned.push({ ref: 'claude:tool_input', version: id, digest: log.digest(canonical(input), { subject: fields.subject }) })
    } catch (e) {
      if (!(e instanceof TenbriError)) throw e // no key to digest with here: the intent says why
    }
    const p = this.#o.principal
    return traced({
      ...fields,
      action: { type: action ?? tool, ...(target !== undefined && { target }) },
      principal: typeof p === 'function' ? p() : p,
      ...(pinned.length > 0 && { inputs: pinned }),
    })
  }

  async #pre(i: Parameters<HookCallback>[0], toolUseID: string | undefined): Promise<HookJSONOutput> {
    if (i.hook_event_name !== 'PreToolUse' || !this.#selected(i.tool_name)) return {}
    const id = i.tool_use_id ?? toolUseID
    try {
      const log = await within(this.#stream(), this.#o.timeout ?? 2000)
      const draft = this.#draft(log, i.tool_name, (i.tool_input ?? {}) as ToolInput, id)
      this.#open.set(id, await within(log.intent(draft), this.#o.timeout ?? 2000))
      return {}
    } catch (e) {
      if (this.#o.failOpen) {
        console.warn(`tenbri: ${i.tool_name} runs unrecorded (fail-open): ${message(e)}`)
        return {}
      }
      return {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `Tenbri could not record the intent, so ${i.tool_name} is blocked: ${message(e)}`,
        },
      }
    }
  }

  async #closing(i: Parameters<HookCallback>[0], toolUseID: string | undefined, status: Status) {
    const id = ('tool_use_id' in i && typeof i.tool_use_id === 'string' && i.tool_use_id) || toolUseID
    if (id) await this.#close(id, status)
    return {}
  }

  async #close(id: string, status: Status): Promise<void> {
    const intent = this.#open.get(id)
    if (!intent) return
    this.#open.delete(id)
    const approval = this.#approvals.get(id)
    this.#approvals.delete(id)
    try {
      await (await this.#stream()).outcome(intent, status, traced(approval ? { approval } : {}))
    } catch (e) {
      // The action already ran; the open intent is reconciled as unknown later.
      console.error(`tenbri: the ${status} outcome of ${id} was not recorded: ${message(e)}`)
    }
  }
}

export interface InstrumentOptions {
  /** Per tool name, over the action schemas of tenbri.toml: `{ mcp__billing__issue_refund: {
   * action: 'issue_refund', target: 'stripe:{charge}', policy: 'policy:refund@14' } }`. */
  actions?: Actions
  /** Who acts; default the `agent()` scope this is called in, else `init({ agent })`. */
  agent?: Principal
  /** Who allows a tool through `canUseTool`; default `init({ approver })` or TENBRI_APPROVER. */
  approver?: TenbriHooksOptions['approver']
  tools?: TenbriHooksOptions['tools']
  /** Default `init({ failOpen })`. */
  failOpen?: boolean
  timeout?: number
}

/**
 * `options` recorded on the stream `init()` opened: every tool call a decision, every approval
 * through `canUseTool` an approval entry. Each tool is the action of its name, or of the action
 * schema in tenbri.toml it ends with (`mcp__billing__issue_refund` is `issue_refund`): the
 * schema's `target` (`stripe:{charge}`) is filled from the tool's input and its `policy` is the
 * rule. `actions` overrides that per tool name. File and web tools record their path or URL.
 *
 *   query({ prompt, options: instrumentClaudeAgentSdk({ mcpServers, canUseTool }) })
 */
export function instrumentClaudeAgentSdk(options: Options = {}, o: InstrumentOptions = {}): Options {
  const agent = o.agent ?? (() => {
    try {
      return who()
    } catch {
      return undefined // the default is still opening: resolved when a tool is called
    }
  })()
  let failOpen = o.failOpen ?? false
  const hooks = new TenbriHooks(
    async () => {
      const d = await defaultStream()
      failOpen = o.failOpen ?? d.failOpen
      return d
    },
    {
      principal: () => who(agent),
      tools: o.tools,
      describe: (tool, input) => ({ ...defaultDescribe(tool, input), ...describeAction(tool, input, o.actions) }),
      approver: (tool, input, opts) => approverOf(o.approver, tool, input, opts),
      get failOpen() {
        return failOpen
      },
      timeout: o.timeout,
    },
  )
  return hooks.instrument(options)
}
