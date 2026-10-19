# Tenbri

**A flight recorder for AI agents: every decision signed, chained and provable.**

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/tenbri/tenbri/badge)](https://scorecard.dev/viewer/?uri=github.com/tenbri/tenbri)
[![CI](https://github.com/tenbri/tenbri/actions/workflows/ci.yml/badge.svg)](https://github.com/tenbri/tenbri/actions/workflows/ci.yml)

Tenbri is an open-source, tamper-evident log of what AI agents decided: who acted, under which rule
and policy version, from which inputs, and who approved. It is written in Rust, stores plain files
on a local disk or an object store, and verifies offline against a trust root the verifier controls.
It works on its own, with any agent framework, from Rust, Python, Node, the browser (WASM), the
`tenbri` CLI or the `tenbrid` REST and gRPC API.

## Status

**Pre-release. Nothing is published yet and nothing here is usable.** This repository holds the
workspace, the release pipeline and the contributor workflow; the code lands crate by crate on the
way to v0.1.0, through `0.1.0-alpha`, `-beta` and `-rc` pre-releases
([CONTRIBUTING.md](CONTRIBUTING.md#releases)). Logs written by pre-releases are not covered by the
format promise: the format is provisional until its external review ends ([spec/](spec/README.md)).

v0.1.0 ships every feature below, each labelled:

- **Stable**: covered by the format promise and the 0.x API policy.
- **Experimental**: behind a Cargo feature or an experimental module, documented and tested, free
  to change in a 0.x minor release.

| Area | Stable | Experimental |
|---|---|---|
| Format and integrity | Entry format v1, canonical bytes, hash chain, signatures, Merkle checkpoints, receipts, links | |
| Keys | Stream and session keys, rotation, revocation, key file, OS keychain | PKCS#11, cloud KMS, passkey attestations |
| Storage | Local disk, AWS S3, Cloudflare R2, MinIO | Google Cloud Storage, Azure Blob, Postgres |
| Anchoring | Checkpoint publishing to auditors, RFC 3161 timestamps | Sigstore Rekor, witnesses |
| Privacy | Blob encryption, per-subject keyed digests and erasure, local key store | |
| Query | SQLite or Parquet index | `--as-of` time travel, Iceberg index |
| CLI | init, append, verify, query, receipt, checkpoint, keys, erase, gc, tail | export, mcp, proxy, ingest |
| Bindings | Rust, Python, Node, WASM verifier | |
| Adapters | Claude Agent SDK, OpenAI Agents SDK, LangGraph and LangChain | Pydantic AI, Vercel AI SDK, Mastra, Google ADK, AWS Strands, Microsoft Agent Framework, CrewAI, LlamaIndex, A2A |
| APIs and tooling | tenbrid REST and gRPC, OpenTelemetry correlation, action schemas, webhook and OTLP streaming, test kit, C2SP tiles and witness protocol | Generated Go, Java and .NET clients, Kafka, read-only viewer, OpenLineage and W3C PROV exports |

## Non-goals

Multi-writer consensus, a blockchain or token, a general-purpose database, storing raw telemetry or
full prompts by default, judging whether a decision was correct, telemetry of any kind, and a hosted
service.

## Layout

| Path | What |
|---|---|
| `crates/tenbri` | The facade crate users depend on |
| `crates/tenbri-*` | Core, merkle, keys, store, writer, crypt, index, anchor, export, macros, mcp, proxy, otlp, server (`tenbrid`), stream, schema, tiles, testkit, cli (`tenbri`) |
| `bindings/python`, `bindings/node`, `bindings/wasm` | The `tenbri` wheel, the `tenbri` npm package, `@tenbri/wasm` |
| `spec/` | The format specification and its test vectors |

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md),
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security reports: [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). The test vectors in `spec/vectors/` are [CC0](spec/vectors/README.md).
