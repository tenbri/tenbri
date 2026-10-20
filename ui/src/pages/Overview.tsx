import { useMemo } from "react"
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Line, LineChart, XAxis, YAxis } from "recharts"
import { ActivityIcon, CircleAlertIcon, HourglassIcon, OctagonXIcon, TimerIcon } from "lucide-react"

import { STATUS_COLOR, href } from "@/components/common"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart"
import { Skeleton } from "@/components/ui/skeleton"
import { buckets, countBy, duration, percentile, useStream, type Status } from "@/data"

const STATUSES: Status[] = ["ok", "error", "refused", "unknown", "pending"]
const statusConfig = Object.fromEntries(STATUSES.map((s) => [s, { label: s, color: STATUS_COLOR[s] }])) satisfies ChartConfig

export function Overview() {
  const { decisions, range, loading } = useStream()

  const stats = useMemo(() => {
    const n = decisions.length
    const c = (s: Status) => decisions.filter((d) => d.status === s).length
    const lat = decisions.flatMap((d) => (d.latencyMs != null ? [d.latencyMs] : []))
    return {
      n,
      error: c("error"),
      refused: c("refused"),
      pending: c("pending"),
      p50: percentile(lat, 50),
      p95: percentile(lat, 95),
    }
  }, [decisions])

  const volume = useMemo(() => buckets(decisions, range, (d) => d.status, STATUSES), [decisions, range])
  const latency = useMemo(() => {
    const { data, step } = buckets(decisions, range, () => "_", ["_"])
    const t0 = data[0]?.t ?? 0
    const groups = data.map(() => [] as number[])
    for (const d of decisions) {
      const i = Math.floor((Date.parse(d.ts) - t0) / step)
      if (d.latencyMs != null && groups[i]) groups[i].push(d.latencyMs)
    }
    return data.map((b, i) => ({ t: b.t, p50: percentile(groups[i], 50) ?? null, p95: percentile(groups[i], 95) ?? null }))
  }, [decisions, range])
  const actions = useMemo(() => countBy(decisions, (d) => d.action).map(([name, n]) => ({ name, n })), [decisions])
  const principals = useMemo(() => countBy(decisions, (d) => d.principal).map(([name, n]) => ({ name, n })), [decisions])

  const pct = (x: number) => (stats.n ? `${((x / stats.n) * 100).toFixed(1)}%` : "—")
  const tick = (t: number) => {
    const d = new Date(t)
    return range === "1h" || range === "24h" ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : d.toLocaleDateString([], { month: "short", day: "numeric" })
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Kpi label="Decisions" icon={<ActivityIcon />} value={stats.n.toLocaleString()} sub={`${stats.pending} pending`} loading={loading} to={href("decisions")} />
        <Kpi label="Error rate" icon={<CircleAlertIcon />} value={pct(stats.error)} sub={`${stats.error} errors`} loading={loading} to={href("decisions", undefined, { status: "error" })} />
        <Kpi label="Refused" icon={<OctagonXIcon />} value={pct(stats.refused)} sub={`${stats.refused} refused`} loading={loading} to={href("decisions", undefined, { status: "refused" })} />
        <Kpi label="Latency p50" icon={<TimerIcon />} value={duration(stats.p50)} sub="intent → outcome" loading={loading} />
        <Kpi label="Latency p95" icon={<HourglassIcon />} value={duration(stats.p95)} sub="intent → outcome" loading={loading} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Decisions over time</CardTitle>
            <CardDescription>By outcome status</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={statusConfig} className="aspect-auto h-64 w-full">
              <BarChart data={volume.data}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="t" tickFormatter={tick} tickLine={false} axisLine={false} minTickGap={32} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={32} />
                <ChartTooltip content={<ChartTooltipContent labelFormatter={(_, p) => new Date(p[0]?.payload.t).toLocaleString()} />} />
                <ChartLegend content={<ChartLegendContent />} />
                {STATUSES.map((s, i) => (
                  <Bar key={s} dataKey={s} stackId="a" fill={`var(--color-${s})`} radius={i === STATUSES.length - 1 ? [3, 3, 0, 0] : 0} />
                ))}
              </BarChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <TopList title="Top actions" rows={actions} link={(name) => href("decisions", undefined, { action: name })} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Latency</CardTitle>
            <CardDescription>Intent to outcome, p50 and p95</CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer
              config={{ p50: { label: "p50", color: "var(--chart-accent)" }, p95: { label: "p95", color: "var(--chart-refused)" } }}
              className="aspect-auto h-56 w-full"
            >
              <LineChart data={latency}>
                <CartesianGrid vertical={false} />
                <XAxis dataKey="t" tickFormatter={tick} tickLine={false} axisLine={false} minTickGap={32} />
                <YAxis tickFormatter={(v) => duration(v)} tickLine={false} axisLine={false} width={48} />
                <ChartTooltip
                  content={
                    <ChartTooltipContent
                      labelFormatter={(_, p) => new Date(p[0]?.payload.t).toLocaleString()}
                      formatter={(v, name) => `${name} ${duration(Number(v))}`}
                    />
                  }
                />
                <Line dataKey="p50" stroke="var(--color-p50)" strokeWidth={2} dot={false} connectNulls />
                <Line dataKey="p95" stroke="var(--color-p95)" strokeWidth={2} dot={false} connectNulls />
              </LineChart>
            </ChartContainer>
          </CardContent>
        </Card>
        <TopList title="Top principals" rows={principals} link={(name) => href("decisions", undefined, { principal: name })} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Errors and refusals</CardTitle>
          <CardDescription>Decisions that did not end ok</CardDescription>
        </CardHeader>
        <CardContent>
          <ChartContainer config={statusConfig} className="aspect-auto h-40 w-full">
            <AreaChart data={volume.data}>
              <CartesianGrid vertical={false} />
              <XAxis dataKey="t" tickFormatter={tick} tickLine={false} axisLine={false} minTickGap={32} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={32} />
              <ChartTooltip content={<ChartTooltipContent labelFormatter={(_, p) => new Date(p[0]?.payload.t).toLocaleString()} />} />
              <Area dataKey="error" stackId="a" type="monotone" stroke="var(--color-error)" fill="var(--color-error)" fillOpacity={0.25} />
              <Area dataKey="refused" stackId="a" type="monotone" stroke="var(--color-refused)" fill="var(--color-refused)" fillOpacity={0.25} />
            </AreaChart>
          </ChartContainer>
        </CardContent>
      </Card>
    </div>
  )
}

function Kpi({ label, icon, value, sub, loading, to }: { label: string; icon: React.ReactNode; value: string; sub: string; loading: boolean; to?: string }) {
  const body = (
    <Card className="h-full gap-1 py-4 transition-colors hover:border-foreground/20">
      <CardHeader className="flex flex-row items-center justify-between px-4 text-sm text-muted-foreground [&_svg]:size-4">
        {label}
        {icon}
      </CardHeader>
      <CardContent className="px-4">
        {loading ? <Skeleton className="h-8 w-20" /> : <div className="text-2xl font-semibold tracking-tight tabular-nums">{value}</div>}
        <div className="mt-1 text-xs text-muted-foreground">{sub}</div>
      </CardContent>
    </Card>
  )
  return to ? <a href={to}>{body}</a> : body
}

function TopList({ title, rows, link }: { title: string; rows: { name: string; n: number }[]; link: (name: string) => string }) {
  const max = Math.max(1, ...rows.map((r) => r.n))
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>By number of decisions</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1">
        {rows.length === 0 && <p className="text-sm text-muted-foreground">Nothing in this range.</p>}
        {rows.map((r) => (
          <a key={r.name} href={link(r.name)} className="group relative flex items-center justify-between rounded-md px-2 py-1.5 text-sm">
            <span className="absolute inset-y-0 left-0 rounded-md bg-muted transition-colors group-hover:bg-accent" style={{ width: `${(r.n / max) * 100}%` }} />
            <span className="relative truncate font-mono text-xs">{r.name}</span>
            <span className="relative tabular-nums text-muted-foreground">{r.n}</span>
          </a>
        ))}
      </CardContent>
    </Card>
  )
}
