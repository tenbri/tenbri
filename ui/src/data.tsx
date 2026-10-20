import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react"
import { toast } from "sonner"

import type { Api, AsOf, Entry, Queried, Verified } from "@/api"

export type Range = "1h" | "24h" | "7d" | "30d" | "all"
export const RANGES: { value: Range; label: string }[] = [
  { value: "1h", label: "Past hour" },
  { value: "24h", label: "Past 24 hours" },
  { value: "7d", label: "Past 7 days" },
  { value: "30d", label: "Past 30 days" },
  { value: "all", label: "All time" },
]

export type Status = NonNullable<Entry["status"]> | "pending"

/** A decision: an intent joined with its outcome and the approvals it cites. */
export type Decision = {
  id: string
  intent?: Queried
  outcome?: Queried
  approvals: Queried[]
  ts: string
  seq: number
  action: string
  target?: string
  principal: string
  subject?: string
  status: Status
  latencyMs?: number
  rule?: string
  inputs: string[]
  traceId?: string
  verified: boolean
}

// ponytail: the whole range is read into the browser (at most CAP entries); server-side
// aggregation queries when streams outgrow that.
const CAP = 20_000

type StreamState = {
  api: Api
  range: Range
  setRange: (r: Range) => void
  entries: Queried[]
  decisions: Decision[]
  byId: Map<string, Queried>
  asOf: AsOf | null
  truncated: boolean
  loading: boolean
  reload: () => void
  verified: Verified | null
  verify: () => void
  live: boolean
  setLive: (on: boolean) => void
}

const Ctx = createContext<StreamState | null>(null)
export const useStream = () => useContext(Ctx)!

export function StreamProvider({ api, children }: { api: Api; children: React.ReactNode }) {
  const [range, setRange] = useState<Range>(() => (localStorage.getItem("tenbri.range") as Range) || "7d")
  const [entries, setEntries] = useState<Queried[]>([])
  const [asOf, setAsOf] = useState<AsOf | null>(null)
  const [truncated, setTruncated] = useState(false)
  const [loading, setLoading] = useState(true)
  const [verified, setVerified] = useState<Verified | null>(null)
  const [live, setLive] = useState(false)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    try {
      localStorage.setItem("tenbri.range", range)
    } catch {
      /* not remembered */
    }
    let stop = false
    setLoading(true)
    ;(async () => {
      const out: Queried[] = []
      let after: number | undefined
      try {
        for (;;) {
          const p = new URLSearchParams({ limit: "1000" })
          if (range !== "all") p.set("since", range)
          if (after != null) p.set("after_seq", String(after))
          const page = await api.query(p)
          if (stop) return
          out.push(...page.entries)
          setAsOf(page.as_of)
          after = page.next_after_seq
          if (after == null || out.length >= CAP) break
        }
        setTruncated(after != null)
        setEntries(out)
      } catch (e) {
        toast.error("Could not read the stream", { description: (e as Error).message })
      } finally {
        if (!stop) setLoading(false)
      }
    })()
    return () => {
      stop = true
    }
  }, [api, range, tick])

  const verify = useCallback(() => {
    setVerified(null)
    api
      .verify()
      .then(setVerified)
      .catch((e) => toast.error("Verification failed", { description: e.message }))
  }, [api])
  useEffect(verify, [verify])

  const entriesRef = useRef(entries)
  entriesRef.current = entries
  useEffect(() => {
    if (!live) return
    const ctl = new AbortController()
    const after = entriesRef.current.at(-1)?.seq ?? asOf?.seq ?? 0
    api
      .tail(
        after,
        (q) => {
          setEntries((r) => (r.length && r[r.length - 1].seq >= q.seq ? r : [...r, q]))
          setAsOf((a) => (a && q.seq > a.seq ? { ...a, seq: q.seq, hash: q.hash } : a))
        },
        ctl.signal,
      )
      .catch((e) => e.name !== "AbortError" && toast.error("Live tail stopped", { description: e.message }))
      .finally(() => !ctl.signal.aborted && setLive(false))
    return () => ctl.abort()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, api])

  const byId = useMemo(() => new Map(entries.map((q) => [q.entry.id, q])), [entries])
  const decisions = useMemo(() => join(entries), [entries])

  const value: StreamState = {
    api,
    range,
    setRange,
    entries,
    decisions,
    byId,
    asOf,
    truncated,
    loading,
    reload: () => setTick((t) => t + 1),
    verified,
    verify,
    live,
    setLive,
  }
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export const principalOf = (e: Entry) => (e.principal ? `${e.principal.kind}:${e.principal.id}` : "—")
export const actionOf = (e: Entry) => e.action?.type ?? (e.key ? `key ${e.key.op}` : e.kind)

function join(entries: Queried[]): Decision[] {
  const byHash = new Map(entries.map((q) => [q.hash, q]))
  const ids = new Set(entries.map((q) => q.entry.id))
  const outcomes = new Map<string, Queried>()
  for (const q of entries) if (q.entry.phase === "outcome" && q.entry.intent) outcomes.set(q.entry.intent, q)
  const out: Decision[] = []
  for (const q of entries) {
    const e = q.entry
    if (e.kind !== "decision") continue
    if (e.phase === "outcome" && e.intent && ids.has(e.intent)) continue
    const intent = e.phase === "intent" ? q : undefined
    const outcome = intent ? outcomes.get(e.id) : q
    const first = intent ?? outcome!
    const approval = first.entry.approval && byHash.get(first.entry.approval.entry)
    const r = first.entry.rule
    out.push({
      id: first.entry.id,
      intent,
      outcome,
      approvals: approval ? [approval] : [],
      ts: first.entry.ts,
      seq: first.seq,
      action: actionOf(first.entry),
      target: first.entry.action?.target,
      principal: principalOf(first.entry),
      subject: first.entry.subject,
      status: outcome?.entry.status ?? "pending",
      latencyMs: intent && outcome ? Date.parse(outcome.entry.ts) - Date.parse(intent.entry.ts) : undefined,
      rule: r && `${r.ref}@${r.version}`,
      inputs: (first.entry.inputs ?? []).map((i) => `${i.ref}@${i.version}`),
      traceId: first.entry.trace?.trace_id,
      verified: [intent, outcome, approval].every((x) => !x || x.verification === "verified"),
    })
  }
  return out.reverse()
}

export function percentile(xs: number[], p: number) {
  if (!xs.length) return undefined
  const s = [...xs].sort((a, b) => a - b)
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))]
}

export function duration(ms?: number) {
  if (ms == null) return "—"
  if (ms < 1000) return `${Math.round(ms)}ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)}s`
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
  return `${(ms / 3_600_000).toFixed(1)}h`
}

export function ago(ts: string) {
  const s = (Date.now() - Date.parse(ts)) / 1000
  if (!Number.isFinite(s)) return ts
  if (s < 60) return "just now"
  const units: [number, string][] = [
    [86400 * 365, "y"],
    [86400 * 30, "mo"],
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
  ]
  const [n, u] = units.find(([n]) => s >= n)!
  return `${Math.floor(s / n)}${u} ago`
}

/** Counts per time bucket, for charts. */
export function buckets<T extends { ts: string }>(rows: T[], range: Range, key: (r: T) => string, keys: string[]) {
  const now = Date.now()
  const spans: Record<Range, [number, number]> = {
    "1h": [3_600_000, 60_000],
    "24h": [86_400_000, 3_600_000],
    "7d": [7 * 86_400_000, 6 * 3_600_000],
    "30d": [30 * 86_400_000, 86_400_000],
    all: [0, 0],
  }
  let [span, step] = spans[range]
  if (range === "all") {
    const first = rows.length ? Math.min(...rows.map((r) => Date.parse(r.ts))) : now - 86_400_000
    span = Math.max(now - first, 3_600_000)
    step = Math.ceil(span / 40)
  }
  const start = Math.floor((now - span) / step) * step
  const n = Math.ceil((now - start) / step)
  const out = Array.from({ length: n }, (_, i) => ({ t: start + i * step, ...Object.fromEntries(keys.map((k) => [k, 0])) })) as ({
    t: number
  } & Record<string, number>)[]
  for (const r of rows) {
    const i = Math.floor((Date.parse(r.ts) - start) / step)
    const k = key(r)
    if (out[i] && k in out[i]) out[i][k]++
  }
  return { data: out, step }
}

export function countBy<T>(rows: T[], key: (r: T) => string | undefined, top = 8) {
  const m = new Map<string, number>()
  for (const r of rows) {
    const k = key(r)
    if (k) m.set(k, (m.get(k) ?? 0) + 1)
  }
  return [...m].sort((a, b) => b[1] - a[1]).slice(0, top)
}
