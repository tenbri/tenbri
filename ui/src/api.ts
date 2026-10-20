// The tenbrid REST API (contract/openapi.v1.yaml), read-only.

export type Principal = { kind: string; id: string }
export type Entry = {
  id: string
  stream: string
  seq: number
  ts: string
  kind: "decision" | "approval" | "key" | "reconcile" | "note"
  phase?: "intent" | "outcome"
  intent?: string
  status?: "ok" | "error" | "refused" | "unknown"
  source?: string
  degraded?: boolean
  principal?: Principal
  action?: { type: string; target?: string }
  subject?: string
  inputs?: { ref: string; version: string; digest: string }[]
  rule?: { ref: string; version: string; result: string }
  approval?: { by: Principal; entry: string }
  trace?: { trace_id: string; span_id: string }
  key?: { op: string; id: string; role?: string }
  prev?: string
  signer: string
  sig: string
  [k: string]: unknown
}
export type Queried = { verification: "verified" | "broken"; entry: Entry; seq: number; hash: string }
export type AsOf = { stream: string; seq: number; hash: string; checkpoint?: number }
export type Page = { entries: Queried[]; next_after_seq?: number; as_of: AsOf }
export type Verified = {
  stream: string
  entries: number
  pinned_key: string
  broken?: { seq: number; code: string; message: string }
}

export class Api {
  constructor(
    readonly token: string,
    readonly stream: string,
  ) {}

  private url(path: string, params?: URLSearchParams) {
    const q = params?.size ? `?${params}` : ""
    return `/v1/streams/${encodeURIComponent(this.stream)}${path}${q}`
  }

  private async fetch(path: string, params?: URLSearchParams, signal?: AbortSignal) {
    const r = await fetch(this.url(path, params), {
      headers: { Authorization: `Bearer ${this.token}` },
      signal,
    })
    if (!r.ok) {
      const b = await r.json().catch(() => null)
      throw new Error(b?.error ? `${b.error.message} (${b.error.code})` : `HTTP ${r.status}`)
    }
    return r
  }

  async query(params: URLSearchParams): Promise<Page> {
    return (await this.fetch("/entries", params)).json()
  }
  async entry(id: string): Promise<Queried> {
    return (await this.fetch(`/entries/${encodeURIComponent(id)}`)).json()
  }
  async verify(): Promise<Verified> {
    return (await this.fetch("/verify")).json()
  }
  async receipt(id: string): Promise<Blob> {
    return (await this.fetch(`/entries/${encodeURIComponent(id)}/receipt`)).blob()
  }

  /** Server-sent events, read with fetch: EventSource cannot send Authorization. */
  async tail(after: number, onEntry: (q: Queried) => void, signal: AbortSignal) {
    const r = await this.fetch("/tail", new URLSearchParams({ after_seq: String(after) }), signal)
    const reader = r.body!.pipeThrough(new TextDecoderStream()).getReader()
    let buf = ""
    for (;;) {
      const { value, done } = await reader.read()
      if (done) return
      buf += value
      let i
      while ((i = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, i)
        buf = buf.slice(i + 2)
        let event = "message"
        let data = ""
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim()
          else if (line.startsWith("data:")) data += line.slice(5).replace(/^ /, "")
        }
        if (event === "entry") onEntry(JSON.parse(data))
        else if (event === "error") throw new Error(JSON.parse(data).error.message)
      }
    }
  }
}
