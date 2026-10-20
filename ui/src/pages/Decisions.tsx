import { useMemo, useState } from "react"
import { ArrowDownIcon, ArrowUpIcon, ChevronLeftIcon, ChevronRightIcon, Columns3Icon, PlusCircleIcon, SearchIcon, XIcon } from "lucide-react"

import { Mascot, Status, Time, VerifiedIcon, go, href, short, type Route } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { duration, useStream, type Decision } from "@/data"
import { cn } from "@/lib/utils"

type Col = {
  id: string
  label: string
  cell: (d: Decision) => React.ReactNode
  sort?: (d: Decision) => number | string
  hidden?: boolean
  className?: string
}

const COLS: Col[] = [
  { id: "time", label: "Time", cell: (d) => <Time ts={d.ts} />, sort: (d) => d.seq },
  { id: "action", label: "Action", cell: (d) => <span className="font-medium">{d.action}</span>, sort: (d) => d.action },
  { id: "principal", label: "Principal", cell: (d) => <span className="font-mono text-xs">{d.principal}</span>, sort: (d) => d.principal },
  { id: "target", label: "Target", cell: (d) => <span className="font-mono text-xs text-muted-foreground">{d.target && short(d.target, 32)}</span>, className: "max-w-64 truncate" },
  { id: "status", label: "Status", cell: (d) => <Status s={d.status} />, sort: (d) => d.status },
  { id: "latency", label: "Latency", cell: (d) => <span className="tabular-nums">{duration(d.latencyMs)}</span>, sort: (d) => d.latencyMs ?? -1, className: "text-right" },
  { id: "rule", label: "Rule", cell: (d) => <span className="font-mono text-xs">{d.rule}</span> },
  { id: "inputs", label: "Inputs", cell: (d) => <span className="font-mono text-xs">{d.inputs.join(", ")}</span>, hidden: true },
  { id: "subject", label: "Subject", cell: (d) => <span className="font-mono text-xs">{d.subject}</span>, hidden: true },
  { id: "approval", label: "Approved by", cell: (d) => <span className="font-mono text-xs">{d.intent?.entry.approval && `${d.intent.entry.approval.by.kind}:${d.intent.entry.approval.by.id}`}</span>, hidden: true },
  { id: "trace", label: "Trace", cell: (d) => d.traceId && <a className="font-mono text-xs underline-offset-4 hover:underline" href={href("trace", d.traceId)} onClick={(e) => e.stopPropagation()}>{d.traceId.slice(0, 8)}</a>, hidden: true },
  { id: "seq", label: "Seq", cell: (d) => <span className="font-mono text-xs text-muted-foreground">{d.seq}</span>, sort: (d) => d.seq, hidden: true },
  { id: "verified", label: "Verified", cell: (d) => <VerifiedIcon ok={d.verified} />, className: "w-10" },
]

const FACETS = ["status", "action", "principal"] as const
const PAGE = 50

export function Decisions({ route }: { route: Route }) {
  const { decisions, loading, truncated } = useStream()
  const q = route.query
  const [search, setSearch] = useState(q.get("q") ?? "")
  const [shown, setShown] = useState(() => {
    try {
      const saved = JSON.parse(localStorage.getItem("tenbri.columns") ?? "null")
      if (Array.isArray(saved)) return new Set<string>(saved)
    } catch {
      /* defaults */
    }
    return new Set(COLS.filter((c) => !c.hidden).map((c) => c.id))
  })
  const [sort, setSort] = useState<{ id: string; desc: boolean }>({ id: "time", desc: true })
  const [page, setPage] = useState(0)

  const facet = (k: string) => q.getAll(k)
  const setFacet = (k: string, values: string[]) => {
    const p = new URLSearchParams(q)
    p.delete(k)
    for (const v of values) p.append(k, v)
    setPage(0)
    location.hash = `#/decisions${p.size ? `?${p}` : ""}`
  }

  const options = useMemo(() => {
    const o: Record<string, Map<string, number>> = { status: new Map(), action: new Map(), principal: new Map() }
    for (const d of decisions) for (const k of FACETS) o[k].set(d[k], (o[k].get(d[k]) ?? 0) + 1)
    return o
  }, [decisions])

  const rows = useMemo(() => {
    const s = search.trim().toLowerCase()
    const out = decisions.filter(
      (d) =>
        FACETS.every((k) => !q.getAll(k).length || q.getAll(k).includes(d[k])) &&
        (!q.get("subject") || d.subject === q.get("subject")) &&
        (!s || [d.action, d.principal, d.target, d.subject, d.rule, d.id, d.traceId, ...d.inputs].some((v) => v?.toLowerCase().includes(s))),
    )
    const col = COLS.find((c) => c.id === sort.id)
    if (col?.sort) {
      const k = col.sort
      out.sort((a, b) => {
        const x = k(a)
        const y = k(b)
        return (x < y ? -1 : x > y ? 1 : 0) * (sort.desc ? -1 : 1)
      })
    }
    return out
  }, [decisions, q, search, sort])

  const cols = COLS.filter((c) => shown.has(c.id))
  const pages = Math.max(1, Math.ceil(rows.length / PAGE))
  const view = rows.slice(page * PAGE, (page + 1) * PAGE)
  const active = FACETS.some((k) => facet(k).length) || !!q.get("subject") || !!search

  const toggleCol = (id: string) => {
    const next = new Set(shown)
    next.has(id) ? next.delete(id) : next.add(id)
    setShown(next)
    try {
      localStorage.setItem("tenbri.columns", JSON.stringify([...next]))
    } catch {
      /* not remembered */
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search action, target, subject, id…"
            className="pl-8"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value)
              setPage(0)
            }}
          />
        </div>
        {FACETS.map((k) => (
          <Facet key={k} title={k} options={options[k]} selected={facet(k)} onChange={(v) => setFacet(k, v)} />
        ))}
        {q.get("subject") && (
          <Badge variant="secondary" className="h-8 gap-1 font-mono">
            subject {q.get("subject")}
            <button onClick={() => setFacet("subject", [])} aria-label="Remove subject filter">
              <XIcon className="size-3" />
            </button>
          </Badge>
        )}
        {active && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch("")
              location.hash = "#/decisions"
            }}
          >
            Reset <XIcon />
          </Button>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="ml-auto">
              <Columns3Icon /> Columns
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-44">
            <DropdownMenuLabel>Show columns</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {COLS.map((c) => (
              <DropdownMenuCheckboxItem key={c.id} checked={shown.has(c.id)} onCheckedChange={() => toggleCol(c.id)} onSelect={(e) => e.preventDefault()}>
                {c.label}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <Card className="gap-0 overflow-hidden py-0">
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              {cols.map((c) => (
                <TableHead key={c.id} className={cn("first:pl-4 last:pr-4", c.className)}>
                  {c.sort ? (
                    <button
                      className="inline-flex items-center gap-1 hover:text-foreground"
                      onClick={() => setSort({ id: c.id, desc: sort.id === c.id ? !sort.desc : true })}
                    >
                      {c.label}
                      {sort.id === c.id && (sort.desc ? <ArrowDownIcon className="size-3" /> : <ArrowUpIcon className="size-3" />)}
                    </button>
                  ) : (
                    c.id !== "verified" && c.label
                  )}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading
              ? Array.from({ length: 8 }, (_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={cols.length} className="px-4">
                      <Skeleton className="h-5 w-full" />
                    </TableCell>
                  </TableRow>
                ))
              : view.map((d) => (
                  <TableRow key={d.id} className="cursor-pointer" onClick={() => go("decision", d.id)}>
                    {cols.map((c) => (
                      <TableCell key={c.id} className={cn("first:pl-4 last:pr-4", c.className)}>
                        {c.cell(d)}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
          </TableBody>
        </Table>
        {!loading && rows.length === 0 && (
          <div className="flex flex-col items-center gap-2 py-16 text-sm text-muted-foreground">
            <Mascot className="size-20 opacity-90" />
            Nothing turned up. Try a wider time range or fewer filters.
          </div>
        )}
        <div className="flex items-center justify-between border-t px-4 py-2 text-sm text-muted-foreground">
          <span>
            {rows.length.toLocaleString()} of {decisions.length.toLocaleString()} decisions
            {truncated && " (range truncated to the first 20,000 entries)"}
          </span>
          <span className="flex items-center gap-2">
            Page {page + 1} of {pages}
            <Button variant="outline" size="icon" className="size-8" disabled={page === 0} onClick={() => setPage(page - 1)} aria-label="Previous page">
              <ChevronLeftIcon />
            </Button>
            <Button variant="outline" size="icon" className="size-8" disabled={page >= pages - 1} onClick={() => setPage(page + 1)} aria-label="Next page">
              <ChevronRightIcon />
            </Button>
          </span>
        </div>
      </Card>
    </div>
  )
}

function Facet({ title, options, selected, onChange }: { title: string; options: Map<string, number>; selected: string[]; onChange: (v: string[]) => void }) {
  const set = new Set(selected)
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="border-dashed capitalize">
          <PlusCircleIcon />
          {title}
          {set.size > 0 && (
            <>
              <Separator orientation="vertical" className="mx-1 h-4" />
              {set.size > 2 ? (
                <Badge variant="secondary" className="rounded-sm px-1 font-normal">
                  {set.size} selected
                </Badge>
              ) : (
                selected.map((v) => (
                  <Badge key={v} variant="secondary" className="rounded-sm px-1 font-normal normal-case">
                    {v}
                  </Badge>
                ))
              )}
            </>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-60 p-0" align="start">
        <Command>
          <CommandInput placeholder={title} />
          <CommandList>
            <CommandEmpty>No results.</CommandEmpty>
            <CommandGroup>
              {[...options].sort((a, b) => b[1] - a[1]).map(([v, n]) => (
                <CommandItem
                  key={v}
                  onSelect={() => {
                    set.has(v) ? set.delete(v) : set.add(v)
                    onChange([...set])
                  }}
                >
                  <span className={cn("flex size-4 items-center justify-center rounded-sm border", set.has(v) ? "border-primary bg-primary text-primary-foreground" : "opacity-50")}>
                    {set.has(v) && "✓"}
                  </span>
                  <span className="truncate font-mono text-xs">{v}</span>
                  <span className="ml-auto font-mono text-xs text-muted-foreground">{n}</span>
                </CommandItem>
              ))}
            </CommandGroup>
            {set.size > 0 && (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem onSelect={() => onChange([])} className="justify-center">
                    Clear filter
                  </CommandItem>
                </CommandGroup>
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
