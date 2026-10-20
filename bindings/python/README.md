# tenbri (Python)

Python bindings for [Tenbri](https://github.com/tenbri/tenbri). Audit trail for AI agents:
every decision signed, chained and provable. The same Rust core as the `tenbri` CLI and tenbrid,
as an abi3 wheel for Python 3.10 and later.

```sh
pip install --pre tenbri
```

```python
from tenbri import Refused, Tenbri

# A directory, file://..., s3://bucket/prefix or r2://bucket/prefix. create=True makes the stream
# and its keys (in $TENBRI_KEYS, else ~/.config/tenbri/keys) when there is none.
log = Tenbri.open("./audit/support", create=True, digest_key=b"a 32-byte secret, kept apart....")
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

`decision` is also a decorator; `target` may be computed from the arguments:

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
