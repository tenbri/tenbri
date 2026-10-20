import { useEffect, useState } from "react"
import { CheckIcon, CopyIcon, ShieldAlertIcon, ShieldCheckIcon } from "lucide-react"

import type { Entry, Queried } from "@/api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { actionOf, ago, duration, principalOf, type Status as S } from "@/data"
import { cn } from "@/lib/utils"
import mascot from "@/assets/mascot.webp?inline"

/** The Tenbri pangolin, on the case. */
export function Mascot({ className }: { className?: string }) {
  return <img src={mascot} alt="" className={cn("shrink-0 object-contain", className)} />
}

// --- routing: #/page/param?query ---

export type Route = { page: string; param?: string; query: URLSearchParams }

function parse(): Route {
  const [path, q] = location.hash.replace(/^#\/?/, "").split("?")
  const [page, ...rest] = path.split("/")
  return { page: page || "overview", param: rest.length ? decodeURIComponent(rest.join("/")) : undefined, query: new URLSearchParams(q) }
}

export function useRoute() {
  const [r, setR] = useState(parse)
  useEffect(() => {
    const on = () => setR(parse())
    addEventListener("hashchange", on)
    return () => removeEventListener("hashchange", on)
  }, [])
  return r
}

export function href(page: string, param?: string, query?: Record<string, string>) {
  const q = query && Object.keys(query).length ? `?${new URLSearchParams(query)}` : ""
  return `#/${page}${param ? `/${encodeURIComponent(param)}` : ""}${q}`
}
export const go = (page: string, param?: string, query?: Record<string, string>) => (location.hash = href(page, param, query))

// --- badges ---

export const STATUS_COLOR: Record<S, string> = {
  ok: "var(--chart-ok)",
  error: "var(--chart-error)",
  refused: "var(--chart-refused)",
  unknown: "var(--chart-unknown)",
  pending: "var(--chart-pending)",
}

const STATUS_CLASS: Record<S, string> = {
  ok: "border-emerald-600/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  error: "border-red-600/30 bg-red-500/10 text-red-700 dark:text-red-400",
  refused: "border-amber-600/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  unknown: "border-zinc-500/30 bg-zinc-500/10 text-zinc-600 dark:text-zinc-400",
  pending: "border-sky-600/30 bg-sky-500/10 text-sky-700 dark:text-sky-400",
}

export function Status({ s }: { s?: S }) {
  if (!s) return null
  return (
    <Badge variant="outline" className={STATUS_CLASS[s]}>
      {s}
    </Badge>
  )
}

export function Kind({ e }: { e: Entry }) {
  return (
    <Badge variant="secondary" className="font-normal">
      {e.kind}
      {e.phase && <span className="text-muted-foreground">· {e.phase}</span>}
    </Badge>
  )
}

export function VerifiedIcon({ ok, label }: { ok: boolean; label?: boolean }) {
  const Icon = ok ? ShieldCheckIcon : ShieldAlertIcon
  return (
    <span
      className={cn("inline-flex items-center gap-1 text-xs", ok ? "text-emerald-600 dark:text-emerald-400" : "text-destructive")}
      title={ok ? "Verified from the pinned key" : "At or after a break in the chain"}
    >
      <Icon className="size-4" />
      {label && (ok ? "verified" : "broken")}
    </span>
  )
}

export function Time({ ts }: { ts: string }) {
  return (
    <Tooltip>
      <TooltipTrigger className="whitespace-nowrap">{ago(ts)}</TooltipTrigger>
      <TooltipContent className="font-mono">{ts}</TooltipContent>
    </Tooltip>
  )
}

export const short = (v: string, n = 22) => (v.length > n ? `${v.slice(0, n)}…` : v)

// --- detail fields ---

export function Section({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <section className={cn("flex flex-col gap-2", className)}>
      <h3 className="text-xs font-medium tracking-wide text-muted-foreground uppercase">{title}</h3>
      <dl className="flex flex-col divide-y rounded-lg border bg-card">{children}</dl>
    </section>
  )
}

export function Field({ k, v, mono, copy }: { k: string; v?: React.ReactNode; mono?: boolean; copy?: boolean }) {
  if (v == null || v === "") return null
  return (
    <div className="grid grid-cols-[7.5rem_1fr_auto] items-center gap-2 px-3 py-2 text-sm">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className={cn("min-w-0 break-all", mono && "font-mono text-xs")}>{v}</dd>
      {copy && typeof v === "string" ? <Copy value={v} /> : <span />}
    </div>
  )
}

export function Copy({ value }: { value: string }) {
  const [done, setDone] = useState(false)
  return (
    <Button
      variant="ghost"
      size="icon"
      className="size-7"
      aria-label="Copy"
      onClick={() => navigator.clipboard.writeText(value).then(() => (setDone(true), setTimeout(() => setDone(false), 1200)))}
    >
      {done ? <CheckIcon /> : <CopyIcon />}
    </Button>
  )
}

// --- the timeline: entries as rows with bars on a shared time axis (Langfuse's trace tree) ---

export type Node = { q: Queried; depth: number; end?: Queried }

export function Timeline({ nodes, selected, onSelect }: { nodes: Node[]; selected?: number; onSelect: (q: Queried) => void }) {
  const times = nodes.flatMap((n) => [Date.parse(n.q.entry.ts), n.end ? Date.parse(n.end.entry.ts) : Date.parse(n.q.entry.ts)])
  const t0 = Math.min(...times)
  const span = Math.max(Math.max(...times) - t0, 1)
  return (
    <div className="flex flex-col">
      <div className="grid grid-cols-[minmax(0,3fr)_minmax(0,2fr)] border-b px-3 py-1.5 text-xs text-muted-foreground">
        <span>Entry</span>
        <span className="flex justify-between">
          <span>0</span>
          <span>{duration(span)}</span>
        </span>
      </div>
      {nodes.map(({ q, depth, end }) => {
        const start = Date.parse(q.entry.ts) - t0
        const width = end ? Date.parse(end.entry.ts) - Date.parse(q.entry.ts) : 0
        const s = (end?.entry.status ?? q.entry.status ?? (q.entry.phase === "intent" ? "pending" : undefined)) as S | undefined
        return (
          <button
            key={q.seq}
            onClick={() => onSelect(q)}
            className={cn(
              "grid grid-cols-[minmax(0,3fr)_minmax(0,2fr)] items-center gap-3 border-b px-3 py-2 text-left text-sm hover:bg-muted/60",
              selected === q.seq && "bg-muted",
            )}
          >
            <span className="flex min-w-0 items-center gap-2" style={{ paddingLeft: depth * 16 }}>
              {depth > 0 && <span className="h-4 w-2 shrink-0 border-b border-l border-muted-foreground/40" />}
              <Kind e={q.entry} />
              <span className="truncate font-medium">{actionOf(q.entry)}</span>
              <span className="ml-auto shrink-0 text-xs text-muted-foreground">{end ? duration(width) : ""}</span>
            </span>
            <span className="relative h-5">
              <span
                className="absolute top-1/2 h-2.5 min-w-1.5 -translate-y-1/2 rounded-sm"
                style={{
                  left: `${(start / span) * 100}%`,
                  width: `${(width / span) * 100}%`,
                  background: s ? STATUS_COLOR[s] : "var(--muted-foreground)",
                }}
              />
            </span>
          </button>
        )
      })}
    </div>
  )
}

/** Entry detail with tabs, shared by the decision and trace views. */
export function principalLink(e: Entry) {
  const p = principalOf(e)
  return p === "—" ? p : <a className="underline-offset-4 hover:underline" href={href("decisions", undefined, { principal: p })}>{p}</a>
}
