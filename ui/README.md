# Tenbri UI

The read-only web UI that `tenbrid` serves at `/`: React, Tailwind and
[shadcn/ui](https://ui.shadcn.com), built into one self-contained HTML file,
`crates/tenbri-server/src/ui/index.html`, which `tenbrid` embeds. Building `tenbrid` does not need
Node; that file is checked in.

It only reads the REST API (`contract/openapi.v1.yaml`) with the bearer token its user types in,
which stays in the browser tab's `sessionStorage`.

## Develop

Run `tenbrid` on `127.0.0.1:7070`, then:

```sh
pnpm --dir ui install
pnpm --dir ui dev     # http://localhost:5173, /v1 proxied to tenbrid
```

## Build

After changing anything here, rebuild the embedded page and commit it with the change:

```sh
pnpm --dir ui build   # writes crates/tenbri-server/src/ui/index.html
cargo build -p tenbri-server
```

## Layout

| Path | What |
|---|---|
| `src/api.ts` | The REST client: query, entry, receipt, verify, and the SSE tail read with `fetch` |
| `src/data.tsx` | Loads the selected time range once and joins intents, outcomes and approvals into decisions |
| `src/pages/` | Overview, Decisions, decision and trace views, Principals, Subjects, Integrity |
| `src/components/common.tsx` | Routing, badges, fields and the timeline |
| `src/components/ui/` | shadcn/ui components (`pnpm dlx shadcn@latest add <name>`) |

The UI reads at most 20,000 entries of the selected range and aggregates them in the browser.
