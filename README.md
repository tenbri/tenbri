<p align="center">
  <img src="docs/assets/mascot.webp" width="220" alt="Tenbri's mascot: a pangolin detective in a deerstalker, holding a magnifying glass and a notebook">
</p>

<h1 align="center">Tenbri</h1>

<p align="center"><strong>Audit trail for AI agents: every decision signed, chained and provable.</strong></p>

<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/tenbri/tenbri"><img src="https://api.scorecard.dev/projects/github.com/tenbri/tenbri/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/tenbri/tenbri/actions/workflows/ci.yml"><img src="https://github.com/tenbri/tenbri/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

Tenbri is an open-source, tamper-evident log of what AI agents decided: who acted, under which rule
and policy version, from which inputs, and who approved. It is written in Rust, stores plain files
on a local disk or an object store, and verifies offline against a trust root the verifier controls.
It works on its own, with any agent framework, from Rust, Python, Node, the browser (WASM), the
`tenbri` CLI or the `tenbrid` REST and gRPC API.

## The problem

Companies now give agents real authority: refunds, payments, account changes, production deploys,
security responses. Afterwards they cannot prove what an agent did, what it saw, which rule allowed
it, or who signed off.

- **A customer disputes a refusal.** Support can show the reply, but not which policy version,
  contract clause and permission produced it.
- **An incident happens**: a wrong payment, a deleted record, an account disabled by mistake.
  Engineers rebuild the story from logs in five services, each editable by the people being
  investigated.
- **A policy changes.** Nobody can list the decisions made under the old wording, so nobody can
  review them.
- **An auditor asks for evidence.** Teams send screenshots and CSV exports that prove nothing about
  integrity.
- **A prompt injection makes an agent act.** There is no record of what the agent read that led to
  the action.

Regulation is moving the same way: the EU AI Act (Article 12) asks for automatic record-keeping for
high-risk systems, GDPR Article 22 for human review of automated decisions, and DORA, NIS2, SOC 2 and
ISO 27001 for evidence of control.

## Why not just logs?

Logs tell operators what happened. Tenbri gives anyone, including someone who does not trust the
operator, proof of what an agent decided and why.

| | Application logs | Tenbri |
|---|---|---|
| Integrity | Editable, rotated, deleted | Hash-chained and signed; any change fails verification |
| Who acted | A shared service account | The specific agent, person or service, with its own key |
| What it saw | Free text, if anything | Inputs pinned by reference, version and content hash |
| Why it was allowed | Rarely recorded | The rule or grant that allowed or refused it |
| Human oversight | A Slack thread, if anything | The approval, as its own signed entry |
| Timing | After the fact | The intent before the action, the outcome after |
| Sharing with an auditor | Give them access to your systems | A receipt that verifies on its own, offline |
| Personal data | Copied into log lines | Only hashes in the chain; bodies encrypted and erasable |

Tenbri does not replace logs, traces or observability tools: it records decisions and links to the
trace that produced them (OpenTelemetry trace and span ids).

## Where it fits

Anywhere an agent takes an action that someone may later need to justify: an action with
consequences, a rule that allowed it, and a person who may have to answer for it.

| Domain | The agent… | The question asked later | What Tenbri records |
|---|---|---|---|
| Customer support | Replies, refunds, issues credits | "Why did we refuse this customer's refund?" | Ticket, policy version, contract clause, rule, reply |
| Finance operations | Pays invoices, approves expenses | "Who approved this payment, and on what basis?" | Invoice, purchase order, threshold, approver |
| Security operations | Triages alerts, isolates hosts, disables accounts | "Why was this alert closed as harmless?" | Alert, enrichment, playbook version, action, analyst approval |
| Software engineering | Merges changes, runs migrations, changes infrastructure | "Which agent changed production, from which instruction?" | Task, diff hash, checks run, approval, deploy |
| IT and people operations | Grants and revokes access | "Who gave this person admin access?" | Request, access policy version, approver |
| Banking and insurance | KYC checks, claims triage, credit pre-screening | "Why was this claim flagged?" | Documents read (hashed), rule and model versions, human reviewer |
| Healthcare administration | Prior authorisation, scheduling, billing codes | "Which guideline version did the agent apply?" | Request, guideline version, outcome, clinician sign-off |
| Legal and procurement | Reviews and redlines contracts | "Which clauses did the agent change, under which playbook?" | Document hash, playbook version, edits, approver |
| Data and analytics | Queries sensitive data | "Who queried personal data, and why?" | Query hash, datasets touched, stated purpose, requester |
| Multi-agent systems | Hands tasks to other agents | "Which agent in the chain made the call?" | Each hand-off and each agent's decision, linked across streams |

**Not the right tool for** raw telemetry and traces (use OpenTelemetry), millions of events per
second on one stream, or archiving every full prompt.

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
