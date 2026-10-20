import { useState } from "react"
import { useTheme } from "next-themes"
import { toast } from "sonner"
import {
  ActivityIcon,
  ArrowRightIcon,
  ChevronsUpDownIcon,
  LayoutDashboardIcon,
  ListIcon,
  LogOutIcon,
  MoonIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldCheckIcon,
  SunIcon,
  UserRoundIcon,
  UsersIcon,
  WaypointsIcon,
} from "lucide-react"

import { Api } from "@/api"
import { Mascot, href, useRoute, type Route } from "@/components/common"
import { Badge } from "@/components/ui/badge"
import { Breadcrumb, BreadcrumbItem, BreadcrumbLink, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from "@/components/ui/breadcrumb"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { RANGES, StreamProvider, useStream, type Range } from "@/data"
import { DecisionView, TraceView } from "@/pages/Detail"
import { Decisions } from "@/pages/Decisions"
import { Principals, Subjects, Traces } from "@/pages/Groups"
import { Integrity } from "@/pages/Integrity"
import { Overview } from "@/pages/Overview"

const store = {
  get(s: Storage, k: string) {
    try {
      return s.getItem(k) ?? ""
    } catch {
      return ""
    }
  },
  set(s: Storage, k: string, v: string) {
    try {
      v ? s.setItem(k, v) : s.removeItem(k)
    } catch {
      /* private mode: nothing remembered */
    }
  },
}
const savedStreams = (): string[] => {
  try {
    return JSON.parse(store.get(localStorage, "tenbri.streams") || "[]")
  } catch {
    return []
  }
}

export default function App() {
  const [api, setApi] = useState<Api | null>(() => {
    // The token stays in this tab only; stream names are remembered.
    const t = store.get(sessionStorage, "tenbri.token")
    const s = store.get(localStorage, "tenbri.stream")
    return t && s ? new Api(t, s) : null
  })
  const [adding, setAdding] = useState(false)
  const connect = (a: Api | null) => {
    store.set(sessionStorage, "tenbri.token", a?.token ?? "")
    if (a) {
      store.set(localStorage, "tenbri.stream", a.stream)
      store.set(localStorage, "tenbri.streams", JSON.stringify([...new Set([a.stream, ...savedStreams()])].slice(0, 12)))
    }
    setAdding(false)
    setApi(a)
  }
  if (!api || adding) return <Connect token={api?.token} onConnect={connect} onCancel={api ? () => setAdding(false) : undefined} />
  return (
    <StreamProvider key={api.stream} api={api}>
      <Shell onSwitch={(s) => connect(new Api(api.token, s))} onAdd={() => setAdding(true)} onLeave={() => connect(null)} />
    </StreamProvider>
  )
}

function Connect({ token: known, onConnect, onCancel }: { token?: string; onConnect: (a: Api) => void; onCancel?: () => void }) {
  const [token, setToken] = useState(known ?? "")
  const [stream, setStream] = useState(() => (known ? "" : store.get(localStorage, "tenbri.stream")))
  const [busy, setBusy] = useState(false)
  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    const a = new Api(token.trim(), stream.trim())
    setBusy(true)
    try {
      await a.query(new URLSearchParams({ limit: "1" }))
      onConnect(a)
    } catch (err) {
      toast.error("Could not open the stream", { description: (err as Error).message })
    } finally {
      setBusy(false)
    }
  }
  return (
    <main className="flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <Mascot className="mx-auto mb-1 size-28" />
          <CardTitle className="text-center text-xl">Tenbri UI</CardTitle>
          <CardDescription className="text-center">The Agent Decision Record of what your agents decided. Read-only: nothing here can write.</CardDescription>
        </CardHeader>
        <form onSubmit={submit}>
          <CardContent className="flex flex-col gap-4">
            <div className="grid gap-2">
              <Label htmlFor="stream">Stream</Label>
              <Input id="stream" placeholder="support or tnb1:…" value={stream} onChange={(e) => setStream(e.target.value)} required autoFocus />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="token">Bearer token</Label>
              <Input id="token" type="password" autoComplete="off" placeholder="tnbt_…" value={token} onChange={(e) => setToken(e.target.value)} required />
              <p className="text-xs text-muted-foreground">
                Kept in this tab only. Make one with <code>tenbrid token</code>.
              </p>
            </div>
          </CardContent>
          <CardFooter className="mt-6 flex gap-2">
            {onCancel && (
              <Button type="button" variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
            )}
            <Button className="flex-1" disabled={busy}>
              {busy ? "Opening…" : "Open stream"} <ArrowRightIcon />
            </Button>
          </CardFooter>
        </form>
      </Card>
    </main>
  )
}

const NAV = [
  {
    label: "Observe",
    items: [
      { page: "overview", title: "Overview", icon: LayoutDashboardIcon },
      { page: "decisions", title: "Decisions", icon: ListIcon },
      { page: "traces", title: "Traces", icon: WaypointsIcon },
    ],
  },
  {
    label: "Who",
    items: [
      { page: "principals", title: "Principals", icon: UsersIcon },
      { page: "subjects", title: "Subjects", icon: UserRoundIcon },
    ],
  },
  { label: "Prove", items: [{ page: "integrity", title: "Integrity", icon: ShieldCheckIcon }] },
]
const TITLES: Record<string, [string, string?]> = {
  overview: ["Overview"],
  decisions: ["Decisions"],
  decision: ["Decision", "decisions"],
  traces: ["Traces"],
  trace: ["Trace", "traces"],
  principals: ["Principals"],
  subjects: ["Subjects"],
  integrity: ["Integrity"],
}

function Shell({ onSwitch, onAdd, onLeave }: { onSwitch: (s: string) => void; onAdd: () => void; onLeave: () => void }) {
  const route = useRoute()
  const s = useStream()
  const [title, parent] = TITLES[route.page] ?? ["Not found"]
  const active = route.page === "decision" ? "decisions" : route.page === "trace" ? "traces" : route.page
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <StreamSwitcher onSwitch={onSwitch} onAdd={onAdd} />
        </SidebarHeader>
        <SidebarContent>
          {NAV.map((g) => (
            <SidebarGroup key={g.label}>
              <SidebarGroupLabel>{g.label}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {g.items.map((i) => (
                    <SidebarMenuItem key={i.page}>
                      <SidebarMenuButton asChild isActive={active === i.page} tooltip={i.title}>
                        <a href={href(i.page)}>
                          <i.icon />
                          <span>{i.title}</span>
                        </a>
                      </SidebarMenuButton>
                      {i.page === "decisions" && !s.loading && <SidebarMenuBadge>{s.decisions.length}</SidebarMenuBadge>}
                      {i.page === "integrity" && s.verified && (
                        <SidebarMenuBadge>
                          <span className={s.verified.broken ? "size-2 rounded-full bg-destructive" : "size-2 rounded-full bg-emerald-500"} />
                        </SidebarMenuBadge>
                      )}
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <ThemeItem />
            <SidebarMenuItem>
              <SidebarMenuButton onClick={onLeave} tooltip="Sign out">
                <LogOutIcon />
                <span>Sign out</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 h-4" />
          <Breadcrumb className="min-w-0">
            <BreadcrumbList>
              <BreadcrumbItem className="hidden sm:block">
                <BreadcrumbLink href={href("overview")}>{s.api.stream}</BreadcrumbLink>
              </BreadcrumbItem>
              <BreadcrumbSeparator className="hidden sm:block" />
              {parent && (
                <>
                  <BreadcrumbItem>
                    <BreadcrumbLink href={href(parent)}>{TITLES[parent][0]}</BreadcrumbLink>
                  </BreadcrumbItem>
                  <BreadcrumbSeparator />
                </>
              )}
              <BreadcrumbItem>
                <BreadcrumbPage>{title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <div className="ml-auto flex items-center gap-2">
            <Label className="flex cursor-pointer items-center gap-2 text-sm font-normal">
              {s.live && <span className="size-2 animate-pulse rounded-full bg-emerald-500" />}
              <span className="hidden md:inline">Live</span>
              <Switch checked={s.live} onCheckedChange={s.setLive} aria-label="Live tail" />
            </Label>
            <Select value={s.range} onValueChange={(v) => s.setRange(v as Range)}>
              <SelectTrigger size="sm" className="w-36" aria-label="Time range">
                <SelectValue />
              </SelectTrigger>
              <SelectContent align="end">
                {RANGES.map((r) => (
                  <SelectItem key={r.value} value={r.value}>
                    {r.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="outline" size="icon" className="size-8" onClick={s.reload} aria-label="Refresh">
                  <RefreshCwIcon className={s.loading ? "animate-spin" : ""} />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Refresh</TooltipContent>
            </Tooltip>
          </div>
        </header>
        <main className="flex flex-col gap-4 p-4 md:p-6">
          {!parent && (
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
              {route.page === "overview" && <VerifyBadge />}
            </div>
          )}
          <Page route={route} />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}

function Page({ route }: { route: Route }) {
  switch (route.page) {
    case "overview":
      return <Overview />
    case "decisions":
      return <Decisions key={route.query.toString()} route={route} />
    case "decision":
      return <DecisionView key={route.param} route={route} />
    case "traces":
      return <Traces />
    case "trace":
      return <TraceView key={route.param} route={route} />
    case "principals":
      return <Principals />
    case "subjects":
      return <Subjects />
    case "integrity":
      return <Integrity />
    default:
      return <p className="text-sm text-muted-foreground">No such page.</p>
  }
}

function StreamSwitcher({ onSwitch, onAdd }: { onSwitch: (s: string) => void; onAdd: () => void }) {
  const { api, asOf } = useStream()
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton size="lg" className="data-[state=open]:bg-sidebar-accent" tooltip={api.stream}>
              <Mascot className="size-8" />
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-semibold">{api.stream}</span>
                <span className="truncate font-mono text-xs text-muted-foreground">{asOf?.stream ?? "Tenbri"}</span>
              </div>
              <ChevronsUpDownIcon className="ml-auto" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="w-60" align="start" side="bottom">
            <DropdownMenuLabel className="text-xs text-muted-foreground">Streams</DropdownMenuLabel>
            {savedStreams().map((name) => (
              <DropdownMenuItem key={name} onSelect={() => name !== api.stream && onSwitch(name)}>
                <ActivityIcon />
                {name}
                {name === api.stream && <Badge variant="secondary" className="ml-auto">open</Badge>}
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={onAdd}>
              <PlusIcon /> Open another stream
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  )
}

function ThemeItem() {
  const { resolvedTheme, setTheme } = useTheme()
  const dark = resolvedTheme === "dark"
  return (
    <SidebarMenuItem>
      <SidebarMenuButton onClick={() => setTheme(dark ? "light" : "dark")} tooltip="Theme">
        {dark ? <SunIcon /> : <MoonIcon />}
        <span>{dark ? "Light mode" : "Dark mode"}</span>
      </SidebarMenuButton>
    </SidebarMenuItem>
  )
}

function VerifyBadge() {
  const { verified } = useStream()
  if (!verified) return <Badge variant="outline">Verifying…</Badge>
  return verified.broken ? (
    <Badge variant="destructive" asChild>
      <a href={href("integrity")}>Broken at seq {verified.broken.seq}</a>
    </Badge>
  ) : (
    <Badge variant="outline" className="border-emerald-600/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400" asChild>
      <a href={href("integrity")}>
        <ShieldCheckIcon /> {verified.entries.toLocaleString()} entries verified
      </a>
    </Badge>
  )
}
