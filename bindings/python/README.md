# tenbri (Python)

Python bindings for [Tenbri](https://github.com/tenbri/tenbri). The open-source Agent
Decision Record: every decision signed, chained and provable. The same Rust core as the `tenbri` CLI and tenbrid,
as an abi3 wheel for Python 3.10 and later.

```sh
pip install --pre tenbri
```

## Quick start

```python
import tenbri

tenbri.init()  # TENBRI_STREAM, TENBRI_AGENT...: see below


@tenbri.decision("issue_refund", target="stripe:{charge}", policy="policy:refund@14")
def refund(charge: str, amount: int) -> None:
    if amount > 500:
        raise tenbri.Refused("over the ceiling")  # recorded as refused
    ...  # issue the refund
```

Each call of `refund` is a decision: its intent is durable before the function runs (if it cannot
be written, the function does not run), then its outcome follows: `ok`, `refused` when it raises
`tenbri.Refused`, `error` for any other exception (which propagates), `unknown` when cancelled.
Sync and async functions alike.

- `target` and `subject` are templates of the function's arguments (`"stripe:{charge}"`,
  `"{order.id}"`) or functions of them; `policy` (`"ref@version"`) is the rule that allowed it;
  `inputs` pins what the decision relied on, `(ref, version, content)` tuples or a function of the
  arguments returning them, by keyed digest.
- Who acts: `principal=`, else the innermost `with tenbri.agent("agent:billing"):`, else
  `init(agent=...)`. Nothing is guessed: with none, the call raises.
- With an agent framework, one more line records every tool call:
  `tenbri.instrument_claude_agent_sdk()`, `tenbri.instrument_openai_agents()` or
  `tenbri.instrument_langchain()` (install `tenbri-claude-agent-sdk`, `tenbri-openai-agents` or
  `tenbri-langgraph`).

`init()` opens the process's default stream, creating it and its keys on first use, and closes it
(flushing) at exit; `with tenbri.init(...):` scopes it to a block. Creating a stream (here or with
`Tenbri.open(..., create=True)`) records its pin in `<keys>/pins`, as `tenbri init` does, so
`tenbri verify <stream>` on this machine needs no `--key`. Every argument defaults to an
environment variable:

| Argument | Variable | |
| --- | --- | --- |
| `stream` | `TENBRI_STREAM` | A directory, `file://...`, `s3://bucket/prefix` or `r2://bucket/prefix` |
| `keys` | `TENBRI_KEYS` | The keys directory, apart from the stream; default `~/.config/tenbri/keys` |
| `agent` | `TENBRI_AGENT` | Who acts when nothing narrower says: `agent:support` |
| `approver` | `TENBRI_APPROVER` | Who answers the frameworks' approval prompts: `person:alice` |
| `schema` | `TENBRI_SCHEMA` | The action schemas; default `./tenbri.toml` when there is one |
| `fail_open` | | Run actions, unrecorded and with a warning, when their intent cannot be written. Default: block them |

Input digests are keyed by the stream's local key store (per subject, so erasing a subject's key
leaves its digests unconfirmable): no secret in code. `digest_key=` keys them yourself instead.

## Advanced: the stream itself

`init()` and `@decision` are built on this; use it to hold several streams, or to see every call.

```python
from tenbri import Refused, Tenbri

# A directory, file://..., s3://bucket/prefix or r2://bucket/prefix. create=True makes the stream
# and its keys (in $TENBRI_KEYS, else ~/.config/tenbri/keys) when there is none.
log = Tenbri.open("./audit/support", create=True)
print("pin this:", log.fingerprint)

with log.run("agent:support-assistant") as run:
    # Reads are pinned to the next decision's inputs, with a keyed digest of what was read.
    run.read("policy:refund", "14", b"refunds under 50 EUR are automatic")
    # The intent is durable before the block runs; the outcome follows: ok, refused or error.
    with run.decision("issue_refund", "stripe:ch_123"):
        pass  # issue the refund here; raise Refused(...) when your policy says no

report = log.verify(log.fingerprint)
print(report.ok, report.entries)
for m in log.query(inputs=["policy:refund@14"]):
    print(m.verification, m.entry["action"])
log.close()
```

`log.decision` is also a decorator; `target` may be computed from the arguments:

```python
@log.decision("issue_refund", target=lambda charge, amount: f"stripe:{charge}", principal="agent:billing")
def refund(charge: str, amount: int) -> None: ...
```

With asyncio, `AsyncTenbri` has the same methods as coroutines, `async with` decisions and
decorators of async functions. Nothing blocks the event loop, and concurrent appends share one
group commit.

```python
from tenbri import AsyncTenbri

async with await AsyncTenbri.open("s3://acme-audit/tenbri/support") as log:
    intent = await log.intent(action={"type": "reply_ticket"}, principal="agent:support")
    await log.outcome(intent, "ok")
```

- **Low level**: `log.intent(draft, **fields)`, `log.outcome(intent, status, **fields)` and
  `log.append(entry)` take format v1 drafts as dicts and return entries as stored.
- **Idempotent retries**: give a draft an `id` (`tenbri.new_id()`); appending the same entry again
  returns the original. Every write error carries the `id` it was writing.
- **Errors** are typed, one per stable code shared with tenbrid: `TenbriError` and its
  subclasses (`StoreUnavailableError` is `TENBRI_STORE_UNAVAILABLE`, ...), with `.code`,
  `.reason` (the format's error code) and `.id`.
- **Read-only**: without the stream's keys, a stream opens read-only; `verify` and `query` work,
  writes raise `NoSessionKeyError`.
- `verify(key)` is only `ok` against a pinned key: without one it shows that the stream agrees
  with its own genesis key, which proves nothing about who wrote it.
