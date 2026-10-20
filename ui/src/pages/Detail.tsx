import { useMemo, useState } from "react"
import { toast } from "sonner"
import { ArrowLeftIcon, DownloadIcon, WaypointsIcon } from "lucide-react"

import type { Queried } from "@/api"
import { Field, Kind, Section, Status, Timeline, VerifiedIcon, href, principalLink, type Node, type Route } from "@/components/common"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { actionOf, duration, useStream, type Decision } from "@/data"

/** One decision: its approval, intent and outcome on a timeline. */
export function DecisionView({ route }: { route: Route }) {
  const { decisions, loading, setRange } = useStream()
  const d = decisions.find((x) => x.id === route.param)
  if (!d) return <Missing loading={loading} onAll={() => setRange("all")} />
  const nodes: Node[] = [
    ...d.approvals.map((q) => ({ q, depth: 0 })),
    ...(d.intent ? [{ q: d.intent, depth: 0, end: d.outcome }] : []),
    ...(d.outcome ? [{ q: d.outcome, depth: d.intent ? 1 : 0 }] : []),
  ]
  return (
    <Layout
      title={d.action}
      sub={<Summary d={d} />}
      nodes={nodes}
      initial={d.outcome ?? d.intent!}
      extra={
        d.traceId && (
          <Button variant="outline" size="sm" asChild>
            <a href={href("trace", d.traceId)}>
              <WaypointsIcon /> Whole trace
            </a>
          </Button>
        )
      }
    />
  )
}

/** Every decision written under one OpenTelemetry trace. */
export function TraceView({ route }: { route: Route }) {
  const { decisions, entries, loading, setRange } = useStream()
  const id = route.param!
  const nodes = useMemo(() => {
    const ds = decisions.filter((d) => d.traceId === id).reverse()
    const used = new Set(ds.flatMap((d) => [d.intent?.seq, d.outcome?.seq]))
    const out: Node[] = ds.flatMap((d) => [
      ...(d.intent ? [{ q: d.intent, depth: 0, end: d.outcome }] : []),
      ...(d.outcome ? [{ q: d.outcome, depth: d.intent ? 1 : 0 }] : []),
    ])
    // Approvals and notes under the same trace.
    for (const q of entries) if (q.entry.trace?.trace_id === id && !used.has(q.seq)) out.push({ q, depth: 0 })
    return out.sort((a, b) => a.q.seq - b.q.seq)
  }, [decisions, entries, id])
  if (!nodes.length) return <Missing loading={loading} onAll={() => setRange("all")} />
  const ts = nodes.map((n) => Date.parse(n.q.entry.ts))
  return (
    <Layout
      title={`Trace ${id.slice(0, 12)}…`}
      sub={
        <span className="text-sm text-muted-foreground">
          {nodes.filter((n) => n.q.entry.phase === "intent").length} decisions · {duration(Math.max(...ts) - Math.min(...ts))} · <span className="font-mono">{id}</span>
        </span>
      }
      nodes={nodes}
      initial={nodes[0].q}
    />
  )
}

function Summary({ d }: { d: Decision }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
      <Status s={d.status} />
      <VerifiedIcon ok={d.verified} label />
      <span>·</span>
      <span className="font-mono text-xs">{d.principal}</span>
      {d.target && (
        <>
          <span>→</span>
          <span className="font-mono text-xs">{d.target}</span>
        </>
      )}
      <span>·</span>
      <span>latency {duration(d.latencyMs)}</span>
    </div>
  )
}

function Layout({ title, sub, nodes, initial, extra }: { title: string; sub: React.ReactNode; nodes: Node[]; initial: Queried; extra?: React.ReactNode }) {
  const [sel, setSel] = useState<Queried>(initial)
  const current = nodes.find((n) => n.q.seq === sel.seq)?.q ?? initial
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start gap-3">
        <Button variant="ghost" size="icon" onClick={() => history.back()} aria-label="Back">
          <ArrowLeftIcon />
        </Button>
        <div className="flex min-w-0 flex-col gap-1">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {sub}
        </div>
        <div className="ml-auto">{extra}</div>
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,5fr)_minmax(0,6fr)]">
        <Card className="gap-0 self-start overflow-hidden py-0">
          <CardHeader className="border-b py-3">
            <CardTitle className="text-sm">Timeline</CardTitle>
          </CardHeader>
          <Timeline nodes={nodes} selected={current.seq} onSelect={setSel} />
        </Card>
        <EntryPanel q={current} />
      </div>
    </div>
  )
}

export function EntryPanel({ q }: { q: Queried }) {
  const { api } = useStream()
  const e = q.entry
  const receipt = async () => {
    try {
      const url = URL.createObjectURL(await api.receipt(e.id))
      Object.assign(document.createElement("a"), { href: url, download: `${e.id}.receipt.json` }).click()
      URL.revokeObjectURL(url)
      toast.success("Receipt downloaded", { description: "Check it offline: tenbri receipt verify" })
    } catch (err) {
      toast.error("No receipt", { description: (err as Error).message })
    }
  }
  return (
    <Card className="gap-0 py-0">
      <CardHeader className="flex flex-row flex-wrap items-center gap-2 border-b py-3">
        <Kind e={e} />
        <CardTitle className="text-sm">{actionOf(e)}</CardTitle>
        <span className="font-mono text-xs text-muted-foreground">#{q.seq}</span>
        <Status s={e.status} />
        <span className="ml-auto">
          <Button size="sm" variant="outline" onClick={receipt}>
            <DownloadIcon /> Receipt
          </Button>
        </span>
      </CardHeader>
      <CardContent className="p-4">
        <Tabs defaultValue="overview">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="chain">Chain</TabsTrigger>
            <TabsTrigger value="json">JSON</TabsTrigger>
          </TabsList>
          <TabsContent value="overview" className="mt-3 flex flex-col gap-4">
            <Section title="Decision">
              <Field k="Time" v={e.ts} mono />
              <Field k="Principal" v={principalLink(e)} mono />
              <Field k="Action" v={e.action?.type} />
              <Field k="Target" v={e.action?.target} mono copy />
              <Field k="Subject" v={e.subject && <a className="hover:underline" href={href("decisions", undefined, { subject: e.subject })}>{e.subject}</a>} mono />
              <Field k="Status" v={e.status && <Status s={e.status} />} />
              <Field k="Source" v={e.source && `${e.source}${e.degraded ? " (degraded: fail-open)" : ""}`} />
              <Field k="Durability" v={e.durability as string | undefined} />
              {e.key && <Field k="Key event" v={`${e.key.op} ${e.key.id}${e.key.role ? ` (${e.key.role})` : ""}`} mono />}
            </Section>
            {(e.rule || e.inputs?.length || e.approval) && (
              <Section title="Why">
                <Field k="Rule" v={e.rule && `${e.rule.ref}@${e.rule.version} → ${e.rule.result}`} mono />
                {e.inputs?.map((i) => <Field key={i.ref} k="Input" v={<span>{i.ref}@{i.version} <span className="text-muted-foreground">{i.digest.slice(0, 24)}…</span></span>} mono />)}
                <Field k="Approved by" v={e.approval && `${e.approval.by.kind}:${e.approval.by.id}`} mono />
              </Section>
            )}
            {e.trace && (
              <Section title="OpenTelemetry">
                <Field k="Trace id" v={<a className="hover:underline" href={href("trace", e.trace.trace_id)}>{e.trace.trace_id}</a>} mono />
                <Field k="Span id" v={e.trace.span_id} mono />
              </Section>
            )}
          </TabsContent>
          <TabsContent value="chain" className="mt-3 flex flex-col gap-4">
            <Section title="Integrity">
              <Field k="Verification" v={<VerifiedIcon ok={q.verification === "verified"} label />} />
              <Field k="Sequence" v={String(q.seq)} mono />
              <Field k="Entry id" v={e.id} mono copy />
              <Field k="Entry hash" v={q.hash} mono copy />
              <Field k="Previous" v={e.prev} mono copy />
              <Field k="Signer" v={e.signer} mono />
              <Field k="Signature" v={e.sig} mono copy />
            </Section>
            <p className="text-xs text-muted-foreground">
              Each entry is signed and carries the hash of the one before it. A receipt bundles this entry with a signed checkpoint and its inclusion proof, checkable
              offline against the pinned key.
            </p>
          </TabsContent>
          <TabsContent value="json" className="mt-3">
            <pre className="max-h-[60vh] overflow-auto rounded-md bg-muted p-3 font-mono text-xs leading-relaxed">{JSON.stringify(e, null, 2)}</pre>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  )
}

function Missing({ loading, onAll }: { loading: boolean; onAll: () => void }) {
  if (loading) return <p className="text-sm text-muted-foreground">Loading…</p>
  return (
    <div className="flex flex-col items-start gap-3 text-sm text-muted-foreground">
      Not in the selected time range.
      <Button variant="outline" size="sm" onClick={onAll}>
        Search all time
      </Button>
    </div>
  )
}
