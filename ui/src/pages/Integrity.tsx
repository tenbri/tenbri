import { useMemo } from "react"
import { RefreshCwIcon, ShieldAlertIcon, ShieldCheckIcon } from "lucide-react"

import { Field, Section, Time } from "@/components/common"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useStream } from "@/data"
import { cn } from "@/lib/utils"

export function Integrity() {
  const { verified, verify, asOf, entries } = useStream()
  const keys = useMemo(() => entries.filter((q) => q.entry.kind === "key"), [entries])
  const broken = entries.filter((q) => q.verification === "broken").length
  const ok = verified && !verified.broken

  return (
    <div className="flex flex-col gap-4">
      <Card className={cn(verified && (ok ? "border-emerald-600/40" : "border-destructive/50"))}>
        <CardHeader className="flex flex-row items-start gap-4">
          {!verified ? (
            <Skeleton className="size-10 rounded-full" />
          ) : ok ? (
            <ShieldCheckIcon className="size-10 text-emerald-600 dark:text-emerald-400" />
          ) : (
            <ShieldAlertIcon className="size-10 text-destructive" />
          )}
          <div className="flex flex-col gap-1">
            <CardTitle className="text-lg">
              {!verified ? "Verifying…" : ok ? "The stream verifies" : `The chain breaks at entry ${verified.broken!.seq}`}
            </CardTitle>
            <CardDescription>
              {!verified
                ? "Reading every entry from storage."
                : ok
                  ? `All ${verified.entries.toLocaleString()} entries: canonical bytes, hash chain, signatures, key events and HEAD, checked against the pinned key.`
                  : `${verified.broken!.code}: ${verified.broken!.message}. ${verified.entries} entries verify before it.`}
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" className="ml-auto" onClick={verify} disabled={!verified}>
            <RefreshCwIcon /> Re-verify
          </Button>
        </CardHeader>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Trust root">
          <Field k="Stream id" v={asOf?.stream} mono copy />
          <Field k="Pinned key" v={verified?.pinned_key} mono copy />
        </Section>
        <Section title="Head">
          <Field k="Sequence" v={asOf && String(asOf.seq)} mono />
          <Field k="Entry hash" v={asOf?.hash} mono copy />
          <Field k="Checkpoint" v={asOf && (asOf.checkpoint != null ? `covers ${asOf.checkpoint} entries` : "none yet: a receipt request seals one")} />
          <Field k="Broken in view" v={String(broken)} />
        </Section>
      </div>

      <Card className="gap-0 overflow-hidden py-0">
        <CardHeader className="border-b py-4">
          <CardTitle className="text-sm">Key events</CardTitle>
          <CardDescription>Certifications, rotations and revocations in the selected range</CardDescription>
        </CardHeader>
        <Table>
          <TableHeader className="bg-muted/50">
            <TableRow>
              <TableHead className="pl-4">Seq</TableHead>
              <TableHead>Time</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>Key</TableHead>
              <TableHead className="pr-4">Signed by</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map((q) => (
              <TableRow key={q.seq}>
                <TableCell className="pl-4 font-mono text-xs">{q.seq}</TableCell>
                <TableCell>
                  <Time ts={q.entry.ts} />
                </TableCell>
                <TableCell>
                  {q.entry.key?.op}
                  {q.entry.key?.role && <span className="text-muted-foreground"> · {q.entry.key.role}</span>}
                </TableCell>
                <TableCell className="font-mono text-xs">{q.entry.key?.id}</TableCell>
                <TableCell className="pr-4 font-mono text-xs text-muted-foreground">{q.entry.signer}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {keys.length === 0 && <CardContent className="py-8 text-center text-sm text-muted-foreground">No key events in this range.</CardContent>}
      </Card>
    </div>
  )
}
