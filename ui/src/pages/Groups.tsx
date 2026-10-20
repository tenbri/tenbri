import { useMemo } from "react"
import { SearchXIcon } from "lucide-react"

import { Time, go, href } from "@/components/common"
import { Card } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { countBy, duration, percentile, useStream, type Decision } from "@/data"

type Group = { key: string; rows: Decision[] }

function group(decisions: Decision[], key: (d: Decision) => string | undefined): Group[] {
  const m = new Map<string, Decision[]>()
  for (const d of decisions) {
    const k = key(d)
    if (k) m.set(k, [...(m.get(k) ?? []), d])
  }
  // decisions are newest first, so rows[0] is the latest
  return [...m].map(([key, rows]) => ({ key, rows })).sort((a, b) => b.rows[0].seq - a.rows[0].seq)
}

const rate = (g: Group, s: Decision["status"]) => g.rows.filter((d) => d.status === s).length

/** Langfuse "Sessions": decisions grouped by their OpenTelemetry trace. */
export function Traces() {
  const { decisions, loading } = useStream()
  const groups = useMemo(() => group(decisions, (d) => d.traceId), [decisions])
  return (
    <GroupTable
      loading={loading}
      empty="No decisions carry an OpenTelemetry trace in this range. Instrument with tenbri-otlp or send a traceparent header."
      head={["Trace", "Started", "Duration", "Decisions", "Principals", "Actions", "Errors"]}
      rows={groups.map((g) => {
        const ts = g.rows.flatMap((d) => [Date.parse(d.ts), d.outcome ? Date.parse(d.outcome.entry.ts) : Date.parse(d.ts)])
        return {
          key: g.key,
          open: () => go("trace", g.key),
          cells: [
            <span className="font-mono text-xs">{g.key.slice(0, 16)}…</span>,
            <Time ts={g.rows.at(-1)!.ts} />,
            duration(Math.max(...ts) - Math.min(...ts)),
            g.rows.length,
            new Set(g.rows.map((d) => d.principal)).size,
            <span className="text-xs">{[...new Set(g.rows.map((d) => d.action))].join(", ")}</span>,
            <Errors n={rate(g, "error")} />,
          ],
        }
      })}
    />
  )
}

/** Langfuse "Users": who acted, how often and how well. */
export function Principals() {
  const { decisions, loading } = useStream()
  const groups = useMemo(() => group(decisions, (d) => d.principal), [decisions])
  return (
    <GroupTable
      loading={loading}
      empty="No decisions in this range."
      head={["Principal", "Last seen", "Decisions", "Error rate", "Refused", "p95 latency", "Top action"]}
      rows={groups.map((g) => ({
        key: g.key,
        open: () => go("decisions", undefined, { principal: g.key }),
        cells: [
          <span className="font-mono text-xs">{g.key}</span>,
          <Time ts={g.rows[0].ts} />,
          g.rows.length,
          <Errors n={rate(g, "error")} of={g.rows.length} />,
          rate(g, "refused"),
          duration(percentile(g.rows.flatMap((d) => (d.latencyMs != null ? [d.latencyMs] : [])), 95)),
          <a className="hover:underline" href={href("decisions", undefined, { principal: g.key, action: countBy(g.rows, (d) => d.action, 1)[0][0] })} onClick={(e) => e.stopPropagation()}>
            {countBy(g.rows, (d) => d.action, 1)[0][0]}
          </a>,
        ],
      }))}
    />
  )
}

/** Data subjects: what was decided about whom (erasure works per subject). */
export function Subjects() {
  const { decisions, loading } = useStream()
  const groups = useMemo(() => group(decisions, (d) => d.subject), [decisions])
  return (
    <GroupTable
      loading={loading}
      empty="No decisions name a subject in this range."
      head={["Subject", "Last decision", "Decisions", "Principals", "Errors"]}
      rows={groups.map((g) => ({
        key: g.key,
        open: () => go("decisions", undefined, { subject: g.key }),
        cells: [<span className="font-mono text-xs">{g.key}</span>, <Time ts={g.rows[0].ts} />, g.rows.length, new Set(g.rows.map((d) => d.principal)).size, <Errors n={rate(g, "error")} />],
      }))}
    />
  )
}

function Errors({ n, of }: { n: number; of?: number }) {
  const label = of ? `${((n / of) * 100).toFixed(1)}%` : String(n)
  return <span className={n ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}>{label}</span>
}

function GroupTable({
  head,
  rows,
  loading,
  empty,
}: {
  head: string[]
  rows: { key: string; open: () => void; cells: React.ReactNode[] }[]
  loading: boolean
  empty: string
}) {
  return (
    <Card className="gap-0 overflow-hidden py-0">
      <Table>
        <TableHeader className="bg-muted/50">
          <TableRow>
            {head.map((h) => (
              <TableHead key={h} className="first:pl-4 last:pr-4">
                {h}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading
            ? Array.from({ length: 6 }, (_, i) => (
                <TableRow key={i}>
                  <TableCell colSpan={head.length} className="px-4">
                    <Skeleton className="h-5 w-full" />
                  </TableCell>
                </TableRow>
              ))
            : rows.map((r) => (
                <TableRow key={r.key} className="cursor-pointer" onClick={r.open}>
                  {r.cells.map((c, i) => (
                    <TableCell key={i} className="tabular-nums first:pl-4 last:pr-4">
                      {c}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
        </TableBody>
      </Table>
      {!loading && rows.length === 0 && (
        <div className="flex flex-col items-center gap-2 px-4 py-16 text-center text-sm text-muted-foreground">
          <SearchXIcon className="size-8" />
          {empty}
        </div>
      )}
    </Card>
  )
}
