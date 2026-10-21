# Witnesses (Experimental)

A witness is an independent server that holds your stream's latest checkpoint and cosigns a new
one only if it is consistent with it. Receipts carry the cosignatures, and `tenbri receipt verify
--witness` can require them, so a rewritten or forked stream is caught even if the operator's
host and every key on it are compromised. Tenbri speaks the C2SP protocols
([tlog-witness](https://c2sp.org/tlog-witness),
[tlog-cosignature](https://c2sp.org/tlog-cosignature)), so it works with the public witnesses
below at no cost. The format is in [spec/checkpoints.md](../spec/checkpoints.md), section 6.

Status: **Experimental**, behind the Cargo feature `witness` of `tenbri-server` (tenbrid) and
`tenbri-cli`. Build with it:

```bash
cargo install --path crates/tenbri-server --features witness
```

```bash
cargo install --path crates/tenbri-cli --features witness
```

## 1. Configure tenbrid

```toml
[witness]
every_s = 300   # how often the latest checkpoint is sent to each witness (default 5 minutes)
witnesses = [
  { url = "https://witness.stagemole.eu/", vkey = "witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv" },
  { url = "https://witness.navigli.sunlight.geomys.org/", vkey = "witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G" },
]
```

`url` is the witness's submission prefix: tenbrid posts to `<url>/add-checkpoint`. On first start,
tenbrid creates each stream's **checkpoint key** (`checkpoint.secret` in the stream's key
directory), certifies it with the stream key in the stream itself, and prints the key witnesses
must be given:

```
tenbrid: stream support: witnesses verify its checkpoints with tnb1:170241c12e8724974ea3b10fe536b7d8+bb83202d+Af39…
```

That line is the stream's **vkey**. Its origin is the stream id. Back up `checkpoint.secret` with
the stream key: witnesses never change the key they hold for a log, so losing it means
registering the stream again under a new key. If the secret is missing once the stream has certified a
checkpoint key, tenbrid and `tenbri` refuse to write to the stream until you restore it; neither
makes a replacement. The CLI never makes a checkpoint key; it signs with one tenbrid certified.

A witness that refuses a checkpoint as inconsistent with one it cosigned is logged as
`tenbrid: stream <name>: FORK: …`: the stream was rewritten or truncated, or another history was
shown to that witness. Investigate before anything else.

Cosignatures are stored next to the checkpoint, as `cosignatures/<size>/<witness key ID>.sig`, and
go into every receipt made from that checkpoint.

## 2. Verify receipts against witnesses

```bash
tenbri receipt verify receipt.json --key sha256:… \
  --witness 'witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv' \
  --witness 'witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G' \
  --witnesses 1
```

`--witnesses N` is how many of the pinned witnesses must have cosigned (all of them by default).
Witnesses count by name: one pinned twice counts once. Too few, or a cosignature that does not
verify, fails with `unwitnessed` and exit code 1.

## 3. Register with public witnesses (free)

Every Tenbri stream is a separate log for a witness: register each stream you want witnessed.
Witnesses keep a log's key forever, so register the vkey you will keep.

### witness-network.org (recommended)

[witness-network.org](https://witness-network.org) is a free, community-run list of logs that the
participating witnesses (Geomys, Mullvad, TrustFabric, IPng, Markovian, GDB Security and others)
all accept. It has a **testing** list and **staging** lists; there is no production list yet.

1. Start with the testing list, `lists/testing/log-list.1`, then ask for
   `lists/staging/log-list-10qps-4klogs.1` once it works. A log goes on one list only.
2. Add an entry, keys in this order:

   ```
   vkey tnb1:170241c12e8724974ea3b10fe536b7d8+bb83202d+Af39…
   qpd 288
   contact ops@example.org
   ```

   Leave `origin` out: it defaults to the vkey's name, the stream id. `qpd` is add-checkpoint
   requests per day: 86400 / `every_s` (288 for the default 5 minutes). A low rate is approved
   more easily; going over it can get the log rate-limited or blocked.
3. Open a pull request on [transparency-dev/witness-network](https://github.com/transparency-dev/witness-network)
   appending the entry (it needs Google's CLA), or email the same details to
   `participate (at) lists.witness-network.org`.
4. Witnesses pick the list up within minutes to an hour after it is merged. Until then they answer
   `404` (unknown log), which tenbrid logs and retries on the next round.

Witnesses on the lists, with their submission prefix and vkey, as published by their operators in
October 2026:

| Witness | `url` | `vkey` |
| --- | --- | --- |
| Mullvad | `https://witness.stagemole.eu/` | `witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv` |
| Geomys | `https://witness.navigli.sunlight.geomys.org/` | `witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G` |
| TrustFabric (staging) | `https://staging.witness.transparency.goog/ring-any-bells/` | `staging.witness.transparency.goog/ring-any-bells+2e1a8dc9+BG5JTpLc3FJtwzgh1Uv+Qelz9qeOH2bfWjS1s0s+y4rL` |
| Markovian | `https://witness.markovianprotocol.com/` | `markovianprotocol.com/witness+41b8827f+BJKLl8rBYM0oUxSaWh9rjTldTprEpYj/SWVIGgacA9XC` |
| GDB Security (staging only) | `https://witness.gdbsecurity.com/` | `witness.gdbsecurity.com+a1398f73+BAbIijGonVIk3ikDac+KKlSm1ELHOzcddhjjB6zB4BNf` |

Check each operator's page before relying on a key: witnesses rotate keys (IPng yearly, for
example), and a witness may publish an ML-DSA key too. Tenbri verifies Ed25519 (`cosignature/v1`)
cosignatures; vkeys starting with `B` after the second `+` are those.

### witness.glasklar.is

Glasklar Teknik runs a free witness (vkey
`witness.glasklar.is+90ad80e6+BLIQbbkGXsl/JeCcGIOSFnUabibY7YtB5IWlY9PRSYU2`) and registers logs by
email to `witness-registry (at) glasklarteknik (dot) se`: send the vkey, the rate, contact
details, the [https-bastion](https://c2sp.org/https-bastion) host it can be reached through, and
proof that you control the log's name. Glasklar asks for a domain you control as the name, so a
stream id is unlikely to qualify until Tenbri lets you choose the origin; prefer witness-network.org.

## 4. Testing without a network

`tenbri_anchor::test_witness::TestWitness` (feature `test-witness`) is a witness in memory that
follows the same protocol, with a seeded key. tenbrid's and the CLI's tests use it; never use it in
production.

## Limits

- A stream never sent to a witness is not protected by it, and neither are entries after the last
  checkpoint it cosigned.
- `N` witnesses that collude with the operator can cosign a fork: pin witnesses run by independent
  organisations.
- The cosignature time is the witness's claim, not an RFC 3161 timestamp.
