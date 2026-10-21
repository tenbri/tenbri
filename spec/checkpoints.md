# Tenbri checkpoints

**Status: provisional.** Part of [format v1](format-v1.md), shipped with 0.1.0-alpha.2, and
provisional with it until the external cryptography review ends. Logs written by pre-releases are
not covered by the compatibility promise ([README](README.md#versioning)).

A checkpoint is a signed statement of a stream's size and the Merkle root of its entries at that
size. Held by someone outside the operator (an auditor, a witness, a verifier that saw it before),
it is a trust root: the stream must still hold exactly the entries it covers, so truncating the
tail or rewriting history behind it is detected, even by a key holder who re-signs everything.
Checkpoints are [C2SP signed notes](https://c2sp.org/signed-note) in the
[C2SP checkpoint format](https://c2sp.org/tlog-checkpoint), so existing transparency-log tools can
read and verify them.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. The
[test vectors](vectors/README.md) (`merkle.json`, `checkpoints.json`, and `witness.json` for
section 6) are normative examples.

## 1. The Merkle tree

The tree is the RFC 6962 Merkle hash tree, as RFC 9162 section 2.1 defines it, over the stream's
entry hashes in sequence order. The entry hash (format v1, section 6.2) is already the RFC 6962
leaf hash `SHA-256(0x00 || line)`, so it is the leaf unchanged: entry `seq` is leaf `seq - 1`.

```
MTH({})           = SHA-256()                      the empty tree
MTH({d0})         = d0                             d0 is an entry hash
MTH(D[n]), n > 1  = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                    k the largest power of two smaller than n
```

- An **inclusion proof** for leaf `i` in a tree of size `n` is RFC 9162's `PATH(i, D[n])`, leaf side
  first; it verifies by RFC 9162 section 2.1.3.2.
- A **consistency proof** from size `m` to size `n` is RFC 9162's `PROOF(m, D[n])`; it verifies by
  RFC 9162 section 2.1.4.2. For `m = n` the proof is empty and the roots MUST be equal; for `m = 0`
  the proof is empty and always verifies; for `0 < m < n` an empty proof fails.

The sizes a proof states are only meaningful when a signed checkpoint binds them: a valid proof for
a size its root was not signed for proves nothing.

## 2. The checkpoint note

A checkpoint is a signed note whose text is exactly three lines, each ending in a line feed:

```
tnb1:170241c12e8724974ea3b10fe536b7d8
10
PJ1DOrIgPq0x8PnBw1kFhcgQyqffH+G6SS74egRynLc=

— tnb1:170241c12e8724974ea3b10fe536b7d8 r5sy+qOhNW1qndpyoPlxADaZ7v5a4Jj43yp/4ToQO0AF/Ec5ETPVqg9orX8JUg4SKEYrrr9by/xEzv3YFTV1BpVChAQ=
```

| Line | Rule |
| --- | --- |
| Origin | The stream id, `tnb1:` and 32 lowercase hex digits |
| Size | The number of entries covered, in decimal without leading zeros (`0` alone for zero), at most 2^53 - 1 |
| Root | The Merkle tree hash of entries 1 to size (section 1), 32 bytes in base64 |

Format v1 checkpoints have no extension lines. The text is followed by one empty line and one or
more signature lines: `—` (U+2014), a space, the key name, a space, and the base64 of the 4-byte key
ID followed by the signature, then a line feed.

**The stream's signature.** The key name is the origin. The key is the session key the writer held
when it wrote the checkpoint (format v1, section 5); the stream key never signs checkpoints, so it
can stay offline. The key ID is C2SP's for Ed25519:

```
key ID    = SHA-256(origin || 0x0A || 0x01 || 32-byte Ed25519 public key)[0:4]
signature = Ed25519-Sign(session key, note text)
```

The note text is the three lines with their line feeds, without the empty line. Verifiers MUST use
strict verification, as for entries.

**Domain separation.** This is C2SP's Ed25519 log signature, unchanged, so witnesses and C2SP
libraries verify it. It needs no `tenbri/…` prefix to stay apart from the other messages a session
key signs: an entry, attestation or HEAD message begins with `tenbri/` and contains a 0x00 byte; a
note text begins with `tnb1:` and contains no control character other than the line feed. No byte
string is both.

**Parsing.** A verifier MUST reject (`bad_checkpoint`) a note that is not UTF-8, contains a control
character other than the line feed (so no carriage returns), has no empty line before the
signatures, a text that is not exactly the three lines above, a size or root that breaks its rule,
a signature line that is not of the form above, a key name that is empty or contains a space or
`+`, base64 that is not canonical (RFC 4648 section 3.5: padded, no unused bits set), a signature
of 4 bytes or fewer, or more than 64 signature lines. Text and signatures are split at the last
empty line.

**Other signatures.** Signature lines whose key name and key ID match no key the verifier knows are
ignored, so witnesses and auditors can add cosignatures (c2sp.org/tlog-cosignature) to the same
note. A line that matches a known key MUST verify.

## 3. Writing checkpoints

- The writer writes a checkpoint after advancing HEAD (format v1, section 8, step 4) whenever
  1,000 entries have been added since the last checkpoint, or at least one entry has been added and
  60 seconds have passed since it, whichever comes first. The size is HEAD's `seq`.
- It is stored as `checkpoints/` and the size, in decimal zero-padded to at least 12 digits, with
  `.note`: `checkpoints/000000002000.note`. It is written with put-if-absent and never rewritten.
  A checkpoint is not needed to read or verify a stream; one that is missing changes nothing.
- A writer MUST NOT sign a checkpoint that is inconsistent with one it signed before.
- The HEAD floor: a writer keeps the latest checkpoint it wrote outside the store (the reference
  writer: `checkpoint.note` in the stream's key directory) and refuses to open a stream that fails
  against it, or against the stream's own latest checkpoint, as section 4 checks. An older HEAD
  put back by someone with access to the store fails with `truncated`; one put back after the
  latest checkpoint is not detected.
- `tenbri verify` checks the stream against its own latest checkpoint, as section 4, when it has
  one.
- Checkpoints only protect what they cover once someone outside the operator holds them: export
  them to auditors, or submit them to witnesses.

## 4. Verifying a stream against a checkpoint

A verifier holding a checkpoint first verifies the stream (format v1, section 9). If that fails,
that failure is the result. Otherwise it checks the checkpoint against the stream in this order and
reports the first failure, with this sequence number:

| Check | Fails with | At seq |
| --- | --- | --- |
| The origin is the stream's id | `wrong_stream` | 1 |
| The stream has at least `size` entries | `truncated` | the stream's entry count + 1, the first missing entry |
| A signature line under the origin's name matches a key the stream certified: none matches | `unknown_signer` | size |
| That key is a session key | `signer_not_allowed` | size |
| It was certified at or before seq `size` | `signer_not_allowed` | size |
| It is not revoked from seq `size` or earlier | `key_revoked` | size |
| Its signature verifies | `bad_checkpoint` | size |
| A consistency proof from the checkpoint's size and root to the stream's current tree verifies | `fork` | size |

If one matching key passes every signer check the signature is accepted. A `fork` means entries 1
to `size` are not the ones the checkpoint covers: the stream was rewritten at or before that seq;
the root alone cannot say where. Session-key expiry is not checked, since a log signature carries
no time; a stolen session key is handled by revocation, which reaches checkpoints as it reaches
entries.

The signer must be certified within the entries the checkpoint covers, so the checkpoint and those
entries verify without anything after them, as a receipt needs.

A checkpoint is a trust root in addition to the pinned stream key, not instead of it: the origin
binds the genesis key only through the stream id's 128 bits. `tenbri verify --checkpoint` without
`--key` still reports the stream as not pinned.

**Detected**, for the entries a held checkpoint covers: any edit, insertion, deletion or reorder,
even one a key holder re-signs so the stream verifies on its own; truncation behind it; a different
history shown to another holder of a checkpoint (their checkpoints are not consistent).
**Not detected** by that checkpoint: anything after its size, including truncation back to it. A
later checkpoint held outside the operator moves the line.

## 5. Error codes

Added to format v1's table (format-v1.md, section 10); `wrong_stream`, `unknown_signer`,
`signer_not_allowed` and `key_revoked` are reused with the meanings above.

| Code | Meaning |
| --- | --- |
| `bad_checkpoint` | A checkpoint that is malformed, or whose signature by a matching key does not verify |
| `truncated` | The stream has fewer entries than a checkpoint it is checked against covers |
| `fork` | The stream's first entries do not have the root a checkpoint signed for them |

## 6. Witnesses (Experimental)

**Status: Experimental** (Cargo feature `witness`), and its data lives under `ext`: it may change
before it is promoted to a format version. A witness (c2sp.org/tlog-witness) holds a log's latest
checkpoint and cosigns a new one only if it is consistent with it. Checkpoints held by
independent witnesses catch a rewrite, a truncation behind them, or a different history shown to
someone else, even when the operator's host and all its keys are compromised.

**The checkpoint key.** A C2SP witness is configured with one verifier key per log and keeps it for
the life of the log, but session keys sign for at most 24 hours. So a witnessed stream has a
checkpoint key: a long-lived Ed25519 key, certified by the stream key, that signs checkpoint notes
and nothing else (no entry, attestation or HEAD).

- **Certification.** A `key` entry, signed by the stream key as every key entry is, whose `ext`
  holds `checkpoint_key`, the key as `ed25519:` and 64 lowercase hex digits:
  `"ext": {"checkpoint_key": "ed25519:…"}`. The reference writer puts it on the `certify` of a new
  session key. The checkpoint key in force at seq `n` is the one the last such entry at or before
  `n` names; certifying another replaces it. A writer makes and certifies a checkpoint key only
  when told to witness the stream (tenbrid's `[witness]`); once one is certified, a writer that
  cannot load it MUST fail rather than make another, since witnesses know only that key.
- **Signing.** A witnessed stream's checkpoint carries two signature lines under the origin's name,
  in this order: the session key's (section 2, which every format v1 verifier requires) and the
  checkpoint key's, the same C2SP Ed25519 signature (type `0x01`). A verifier that does not know
  the checkpoint key ignores its line (section 2, other signatures); one that read it from the key
  history MUST verify it (`bad_checkpoint`).
- **The verifier key** an operator registers with witnesses: the origin, the key ID in 8 lowercase
  hex digits and the base64 of `0x01` and the public key, joined by `+`
  (c2sp.org/signed-note): `tnb1:170241c12e8724974ea3b10fe536b7d8+bb83202d+Af39…`. tenbrid prints it
  when it starts with `[witness]`.

Why this and not the alternatives:

- **Not the stream key.** It would have to be online to sign every checkpoint, and rotating it
  (format v1, section 5) would change the log's key at every witness, which C2SP witnesses never do.
- **Not session keys that witnesses learn from the stream.** No C2SP witness reads Tenbri key
  entries; a witness that did would be Tenbri-specific, and public witnesses would not run it.
- **Why `ext`.** Format v1's key roles are closed (`stream`, `session`): a `role: checkpoint` is a
  field change, which only a new format version may make (CONTRIBUTING.md, "Format changes"). The
  role replaces `ext.checkpoint_key` when witnesses leave Experimental.

A thief holding the checkpoint key can sign checkpoints but no entries, and witnesses still refuse
one that contradicts what they cosigned. A thief holding the stream key can certify another
checkpoint key, but witnesses keep verifying with the one registered with them.

**Submitting.** The writer sends a checkpoint to each witness as c2sp.org/tlog-witness says:
`POST <prefix>/add-checkpoint` with the body `old <size>`, the consistency proof (section 1) from
that size to the checkpoint's, one base64 hash per line, an empty line, and the signed note, each
line ending in a line feed. `old` is the size the witness last cosigned for this stream (0 for
none). A `409` answer carries the witness's size (`text/x.tlog.size`): the writer sends again from
it, unless it is above the checkpoint's size, which means a fork or a truncated stream. A `422`
means the checkpoint is inconsistent with one the witness cosigned: a fork, reported and never
retried. A `200` answer holds signature lines; the writer keeps the one by the witness's pinned
key that verifies. tenbrid's `[witness]` sends the latest checkpoint every 5 minutes by default.

**Storage.** A cosignature line is stored next to its checkpoint as
`cosignatures/` + the size zero-padded to 12 digits + `/` + the witness's key ID in hex + `.sig`:
`cosignatures/000000002000/1a2b3c4d.sig`, with put-if-absent. A receipt (receipts.md) carries the
cosignatures as extra signature lines of its `checkpoint` note, so the receipt format does not
change; its issuer picks a cosigned checkpoint as it picks a timestamped one.

**Cosignatures.** A witness's cosignature is c2sp.org/tlog-cosignature's Ed25519 `cosignature/v1`
(type `0x04`):

```
message   = "cosignature/v1\n" || "time " || T || "\n" || note text
key ID    = SHA-256(witness name || 0x0A || 0x04 || 32-byte Ed25519 public key)[0:4]
signature = key ID || T as 8 bytes, big-endian || Ed25519-Sign(witness key, message)
```

`T` is the witness's time in seconds since the Unix epoch, in decimal in the message. The line is
`—`, a space, the witness's name, a space and the base64 of the signature. A witness's verifier key
is its name, its key ID in hex and the base64 of `0x04` and its public key, joined by `+`.

**Verifying.** A verifier that wants independent witnessing pins witnesses by their verifier keys
and a number `N`. After the checkpoint's own checks (section 4, or receipts.md, section 3):

| Check | Fails with |
| --- | --- |
| A signature line by the checkpoint key in force at `size` verifies, if the note has one | `bad_checkpoint` |
| Every cosignature line whose name and key ID match a pinned witness verifies (strictly) | `unwitnessed` |
| At least `N` distinct pinned witnesses cosigned; a witness is its name, so one pinned twice, or with an old and a new key, counts once | `unwitnessed` |

`T` is the witness's claim, signed by it; a verifier shows it as the witness's time, never as the
writer's or a TSA's.

**Detected**, with `N` honest witnesses among those pinned: a checkpoint, and so a receipt, for a
history other than the one those witnesses saw: a rewrite, a truncation behind their last
cosignature, or a split view. **Not detected**: a stream never sent to them, `N` witnesses that
collude with the operator, and entries after the last cosigned checkpoint.

| Code | Meaning |
| --- | --- |
| `unwitnessed` | A checkpoint without the cosignatures from pinned witnesses a verifier requires, or with one that does not verify (Experimental) |

## 7. Open points

- **Witnesses and rotating session keys.** Decided: a long-lived checkpoint key certified by the
  stream key (section 6).
- **Timestamps.** C2SP's timestamped cosignature (type `0x04`) would give checkpoints a signed time;
  format v1 uses the plain Ed25519 log signature, which has none.
