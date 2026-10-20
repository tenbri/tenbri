# Tenbri format v1

**Status: provisional.** This is the draft of format v1 shipped with 0.1.0-alpha.1. It may change
until the external cryptography review ends, before the last 0.1.0 release candidate; logs written
by pre-releases are not covered by the compatibility promise ([README](README.md#versioning)).
Sections marked *reserved* are defined by a later pre-release.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. The
[test vectors](vectors/README.md) are normative examples: where this text and a vector disagree,
that is a bug to report.

## 1. Concepts

| Term | Meaning |
| --- | --- |
| Entry | One signed record: a decision's intent or outcome, an approval, a key event, a reconcile or a note |
| Stream | An ordered sequence of entries with one writer at a time |
| Batch | An immutable file holding consecutive entries, named by its first sequence number |
| HEAD | A small signed object naming the latest sequence number and entry hash |
| Stream key | The long-lived Ed25519 key that identifies a stream and signs its key events |
| Session key | A short-lived Ed25519 key, certified by the stream key, that signs everything else |
| Trust root | What a verifier trusts before reading anything; in format v1 a pinned stream key fingerprint, and any [checkpoint](checkpoints.md) it saw before |

## 2. Encodings

| Value | Encoding |
| --- | --- |
| Hash | `sha256:` followed by 64 lowercase hex digits |
| Public key | `ed25519:` followed by the 32-byte key (RFC 8032) as 64 lowercase hex digits |
| Signature | `ed25519:` followed by the 64-byte signature as 128 lowercase hex digits |
| Key fingerprint | `sha256:` followed by the lowercase hex SHA-256 of the 32-byte public key |
| Stream id | `tnb1:` followed by the first 32 hex digits of the genesis stream key's fingerprint |
| Entry id | A ULID: 26 characters of Crockford base32, uppercase, first character `0` to `7` |
| Timestamp | `YYYY-MM-DDTHH:MM:SS.mmmZ`: UTC, exactly three fraction digits, a valid calendar date |
| Key id | 1 to 128 characters from `A-Z a-z 0-9 . _ : -` |
| Body address | `blob:ct-sha256:` followed by 64 lowercase hex digits |
| Input digest | `hmac-sha256:` followed by 64 lowercase hex digits |

Every encoding has exactly one spelling: uppercase hex, a lowercase ULID or a timestamp without its
milliseconds is invalid, not an alternative form.

## 3. Canonical bytes

Every stored entry and every HEAD is one JSON object in its canonical form, as defined by
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON Canonicalization Scheme), restricted as
follows:

1. **The byte-for-byte rule.** A stored line MUST equal the RFC 8785 canonical serialisation of its
   own parse, byte for byte. A verifier parses the line, serialises the result canonically and
   compares; any difference fails with `not_canonical`. Whitespace, key order, escape spelling and
   number spelling changes are therefore all detected, even where the parsed value is the same.
2. **No duplicate keys.** An object with two members of the same name fails with `duplicate_key`,
   at any depth.
3. **Integers only.** A number with a fraction, an exponent, or a negative zero (`1.0`, `1e2`,
   `-0`) fails with `not_integer`. Integers MUST satisfy -(2^53 - 1) <= n <= 2^53 - 1, otherwise
   `integer_range`.
4. **Valid UTF-8, valid Unicode.** Invalid UTF-8, a lone surrogate escape, a leading byte order
   mark, or anything but whitespace after the value fail with `parse` (and trailing whitespace
   fails the byte-for-byte rule).

For the values format v1 allows, RFC 8785 reduces to:

- no whitespace outside strings;
- object members sorted by the UTF-16 code units of their names (not by UTF-8 bytes or code
  points: `"😀"` sorts before `"דּ"`);
- strings in double quotes, escaping only `"` as `\"`, `\` as `\\`, U+0008 `\b`, U+0009 `\t`,
  U+000A `\n`, U+000C `\f`, U+000D `\r`, and the other code points below U+0020 as `\u00xx` with
  lowercase hex; every other character, including `/`, U+007F and U+2028, is written as itself;
- integers in plain decimal, `-` only for negatives, no leading zeros;
- `true`, `false`, `null`.

A writer canonicalises before it signs. A tool that accepts JSON from a user (`tenbri append`)
canonicalises it; duplicate keys and non-integers are rejected there too, never repaired.

## 4. Entries

### 4.1 Fields

An entry is a JSON object with these members. Any other top-level member fails with
`unknown_field`; any other member inside the objects below fails with `invalid_field`. An optional
member that is `null` is the same as an absent one; writers omit it.

| Field | Required | Rule |
| --- | --- | --- |
| `v` | yes | Format version, the integer `1` |
| `id` | yes | Entry id (ULID), unique within the stream |
| `stream` | yes | Stream id: `tnb1:` and the first 32 hex digits of SHA-256 of the genesis stream key. Human names are labels in config, never identity. Also the [checkpoint](checkpoints.md) origin |
| `seq` | yes | Starts at 1 and increases by exactly 1; at most 2^53 - 1 |
| `ts` | yes | Timestamp claimed by the writer, not proven |
| `hlc` | no | Hybrid logical clock `{wall, count}`: `wall` milliseconds since the Unix epoch, `count` a counter, both non-negative integers. Within a stream, entries that carry `hlc` never decrease in (`wall`, `count`) order |
| `trace` | no | `{trace_id, span_id}` of the OpenTelemetry span active when the entry was written: 32 and 16 lowercase hex digits |
| `durability` | no | `local`, `replicated` or `postgres`: the promise that applied when the intent was acknowledged |
| `group` | no | Only on the genesis entry (`seq` 1): the stream group the lane belongs to (*group keys reserved*) |
| `kind` | yes | `decision`, `approval`, `key`, `reconcile` or `note` |
| `phase` | per kind | `intent` or `outcome`; see 4.2 |
| `intent` | per kind | The `id` of the intent entry an outcome or reconcile closes |
| `status` | per kind | `ok`, `error`, `refused` or `unknown` |
| `source` | per kind | `sdk`, `proxy` or `ingest` |
| `degraded` | no | `true` when written in fail-open mode |
| `principal` | per kind | `{kind, id}` of whoever acted; `kind` is `agent`, `person` or `service` |
| `action` | per kind | `{type, target}`; `target` is optional and is a reference, documented as possibly personal data |
| `subject` | no | Pseudonymous handle selecting the per-subject keys used for erasure |
| `inputs` | no | Array of `{ref, version, digest}`: `ref` and `version` plaintext, `digest` keyed ([privacy.md](privacy.md), section 3) |
| `rule` | no | `{ref, version, result}`; MUST be absent when `source` is `proxy` or `ingest` |
| `approval` | no | `{by, entry}`: the approver (a principal object) and the entry hash of the `approval` entry in this stream that granted it |
| `links` | no | Array of `{stream, seq, hash, rel}` naming entries in other streams; `rel` is optional, one of `cause`, `handoff`, `approval`. Checked for shape only; following a link needs the linked stream's trust root (*reserved*) |
| `body` | no | Body address of the encrypted body ([privacy.md](privacy.md), section 2) |
| `attestations` | no | Array of `{key, sig}`: extra signatures by the principal or an approver; see 6.3 |
| `ext` | no | Object reserved for Experimental features. Hashed and signed like everything else, readable forever; its meaning may change while a feature is Experimental |
| `key` | per kind | The key event of a `key` entry; see 5 |
| `prev` | per seq | Entry hash of the previous entry. Absent on `seq` 1, required on every other |
| `signer` | yes | Key id of the key that signed the entry |
| `sig` | yes | Signature; see 6.1 |

All strings named above (ids, refs, versions, types, targets, handles) MUST be non-empty. Arrays
MAY be empty. Values inside `ext` are free, within the canonical-bytes rules.

### 4.2 Rules per kind

| Kind | Requires | Forbids |
| --- | --- | --- |
| `decision`, phase `intent` | `phase`, `source`, `principal`, `action` | `intent`, `status`, `key`; `source: ingest` |
| `decision`, phase `outcome` | `phase`, `source`, `principal`, `action`, `status`; `intent` unless `source` is `ingest` | `key`; `intent` when `source` is `ingest` |
| `approval` | `principal` (the approver), `action` (what is approved) | `phase`, `intent`, `status`, `key` |
| `key` | `key` | `phase`, `intent`, `status` |
| `reconcile` | `intent`, `status: unknown` | `phase`, `key` |
| `note` | nothing | `phase`, `intent`, `status`, `key` |

### 4.3 Intents, outcomes and reconciles

An intent is written, and durable, before its action runs. Every intent ends in exactly one
outcome:

- An outcome names its intent by `id`. The intent MUST appear earlier in the same stream and MUST
  NOT already have an outcome; otherwise `bad_intent`.
- When no outcome arrives within a timeout (default 1 hour), the next writer session writes a
  `reconcile` entry for the intent with `status: unknown`. A reconcile MUST name an earlier intent
  that has neither an outcome nor a reconcile (`bad_intent`).
- An outcome that arrives after a reconcile is still accepted and supersedes it.
- `ingest` entries record what happened elsewhere: they are outcomes with no intent.
- An `approval` member MUST name the entry hash of an earlier `approval` entry in the stream
  (`bad_approval`).

Every intent therefore ends in an outcome or a reconcile; a verifier can list the open intents at
any sequence number.

## 5. Keys and trust

A log cannot vouch for itself. The verifier holds the trust root: the fingerprint of the stream's
genesis key, printed by `tenbri init` and passed as `tenbri verify --key`.

Key events are `key` entries whose `key` member is one of:

| `op` | Members | Signed by | Effect |
| --- | --- | --- | --- |
| `certify` | `id`, `pub`, `role` (`stream` or `session`), `not_after` (sessions only) | The current stream key | Adds a key. `role: stream` only in the genesis entry, which the new key signs itself |
| `rotate` | `id`, `pub` | The current stream key | The new key becomes the current stream key; the old one signs nothing more |
| `revoke` | `id`, `from` (a sequence number, >= 1) | The current stream key | Entries signed by key `id` at `from` or later fail with `key_revoked` |

Rules, checked in stream order:

1. **Genesis.** Entry 1 MUST be a `certify` of `role: stream`, signed by that key (`signer` equal
   to its `id`). Its `stream` MUST be the stream id derived from its `pub`; otherwise `bad_genesis`.
   If the verifier pinned a fingerprint, it MUST equal the fingerprint of this key
   (`untrusted_root`). Every entry's `stream` MUST equal the genesis stream id (`wrong_stream`).
2. **Who signs what.** `key` entries are signed by the current stream key. Every other entry is
   signed by a session key. Anything else fails with `signer_not_allowed`. A `signer` that no
   earlier entry certified fails with `unknown_signer`.
3. **Ids are unique.** A `certify` or `rotate` MUST introduce a key id not used before, and a public
   key not used before (`bad_key_event`).
4. **Sessions expire.** A session key's `not_after` is a timestamp; an entry signed by it with a
   `ts` later than `not_after` fails with `key_expired`. Writers certify sessions for 24 hours by
   default.
5. **Revocation reaches back.** A `revoke` names a key certified earlier other than the current
   stream key (`bad_key_event`). Entries signed by the revoked key at `from` or later fail with
   `key_revoked`, including entries that came before the revocation: the revocation makes them
   invalid retroactively, and a verifier reports the earliest such entry as the first broken one.
   This is how an operator marks the window in which a stolen session key was used.
6. **Rotation.** Session keys certified by an earlier stream key stay valid until they expire or are
   revoked. A thief holding the stream key can sign a competing rotation; only checkpoints held
   outside the operator reveal the fork (*reserved*).

Keys never live under the stream's directory or bucket prefix.

## 6. Signatures and hashes

### 6.1 Entry signature

```
message = "tenbri/entry/v1" || 0x00 || canonical(entry without the "sig" member)
sig     = Ed25519-Sign(signer's private key, message)
```

Verifiers MUST use strict verification (RFC 8032 section 5.1.7, rejecting a non-canonical `S` and
small-order points); a failure is `bad_signature`.

### 6.2 Entry hash

```
entry hash = SHA-256(0x00 || the stored line, including "sig", without the line feed)
```

This is the RFC 6962 leaf hash, so a later Merkle tree uses entry hashes as leaves unchanged. It is
used by `prev`, `approval.entry`, `links`, HEAD and receipts. A `prev` that is not the hash of the
previous entry fails with `bad_prev`; a `seq` that is not the previous plus one fails with `bad_seq`.

### 6.3 Attestations

An attestation is `{key, sig}`: `key` a public key, `sig` its signature over

```
"tenbri/attestation/v1" || 0x00 || canonical(entry without "seq", "prev", "signer", "sig" and "attestations")
```

The attestation leaves out what the writer fills in, so a principal or approver signs the draft
(its `id`, `ts` and `stream` already set) before a writer places it in the stream. The writer's own
signature covers the attestations. Format v1 checks each attestation's signature (`bad_signature`);
whom an attesting key belongs to is for the verifier to decide.

### 6.4 HEAD

HEAD is one canonical JSON object, stored without a trailing line feed:

| Field | Rule |
| --- | --- |
| `v` | `1` |
| `stream` | The stream id |
| `seq` | The latest sequence number |
| `hash` | The entry hash of entry `seq` |
| `counter` | Increases by at least 1 at every HEAD write; a reader that has seen a counter rejects a lower one (`bad_head`) |
| `batch` | The first sequence number of the batch holding entry `seq` |
| `signer` | A key valid at `seq`: the current stream key or an unrevoked session key |
| `sig` | Ed25519 over `"tenbri/head/v1" \|\| 0x00 \|\| canonical(HEAD without "sig")` |

Any other member fails with `unknown_field`. A HEAD whose `hash`, `batch` or signature does not
match the stream fails with `bad_head`. The prefixes keep an entry signature from ever verifying as a
HEAD signature, and the reverse.

## 7. Storage layout

```
<stream>/
  HEAD                              compare-and-swap
  batches/000000000001.jsonl        named by first seq; written once, never rewritten
  checkpoints/000000002000.note     checkpoints.md, section 3
  anchors/000000002000.tsr          reserved
  blobs/ct-sha256/ab/cd…            privacy.md, section 2
```

- A batch file is named by its first sequence number, in decimal, zero-padded to at least 12
  digits, with `.jsonl`. It holds one or more entries with consecutive sequence numbers, each line
  an entry's canonical bytes followed by one line feed (0x0A). No empty lines, no carriage returns,
  no missing final line feed (`bad_batch`).
- Readers follow HEAD, never directory listings: they read `batches/000000000001.jsonl`, then the
  batch named one past its last entry, and so on until entry `HEAD.seq`, which MUST be the last
  entry of a batch. A batch that HEAD needs but the store lacks fails with `missing_batch` at its
  first sequence number. A batch beyond HEAD is invisible to readers.
- Files whose names start with `.` are temporary and never part of the stream.

## 8. Write protocol

A writer:

1. Reads HEAD, verifies the stream up to it, and checks HEAD's signature, hash and counter.
2. Writes the next batch as `batches/<first seq>.jsonl` with put-if-absent (create-exclusive on a
   local disk: a temporary file, synced, then linked to its name, which fails if the name exists,
   then a directory sync). The batch is durable once written: it is signed and chains from HEAD.
3. If the name already exists, reads that batch. If it is valid and chains from HEAD, a writer
   crashed before step 4: the writer rolls forward (advances HEAD to it) and retries its own
   entries after it. If it does not chain, the writer stops and reports a conflict.
4. Advances HEAD by compare-and-swap to the batch's last entry. Anyone can finish this step for a
   valid batch, so a crash never blocks the stream.
5. `gc` deletes only batches that do not chain from HEAD and are older than an hour, and stale
   temporary files, so it never races a live writer.

An intent is acknowledged only after step 4. Put-if-absent fences writers; no clock or lease
decides who may write.

## 9. Verification

A verifier reads the stream as in section 7. For each entry, in stream order, it runs these checks
in this order and reports the first that fails, with the entry's sequence number:

1. canonical bytes (section 3);
2. top-level members, then the fields and kind rules (4.1, 4.2);
3. `seq` (6.2);
4. for entry 1, the genesis rules and the pin (5, rule 1); for the others, `stream`, then `prev`;
5. `id` uniqueness;
6. the signer: certified, allowed for this kind, not revoked, not expired (5, rules 2, 4, 5);
7. the signature, then each attestation (6.1, 6.3);
8. `hlc`;
9. intents, reconciles and approvals (4.3), then key events (5, rules 3 and 5).

After the last entry it checks HEAD (6.4). A revocation that reaches back (5, rule 5) is reported
at the earliest entry it invalidates, once the whole stream is read; an earlier failure wins. The
verifier reports success or the first broken sequence number and its error code.
Without a pinned fingerprint it can only say that the stream is consistent with its own genesis
key, which proves nothing about who wrote it, and it says so.

Detected: any edit, including whitespace; reordering, insertion and deletion before HEAD; forged
entries; entries signed by an expired, revoked, uncertified or wrong key. Not detected in format v1
without checkpoints: truncation of the tail together with a rewritten HEAD by a key holder, and a
full rewrite by the stream key holder. [Checkpoints](checkpoints.md) held outside the operator
close that gap for the entries they cover (*reserved*: receipts, anchors).

## 10. Error codes

| Code | Meaning |
| --- | --- |
| `parse` | Not a single valid JSON value in valid UTF-8 |
| `duplicate_key` | An object member name appears twice |
| `not_integer` | A number with a fraction, an exponent, or a negative zero |
| `integer_range` | An integer outside ±(2^53 - 1); a literal too large for 64 bits MAY be reported as `not_integer` |
| `not_canonical` | The stored bytes differ from the canonical form of their parse |
| `unknown_field` | A top-level member format v1 does not define |
| `invalid_field` | A member missing, of the wrong type or encoding, or breaking a kind rule |
| `bad_signature` | A signature, or an attestation, that does not verify |
| `unknown_signer` | A signer no earlier key event certified |
| `signer_not_allowed` | A key signing what its role does not allow |
| `key_expired` | An entry dated after its session key's `not_after` |
| `key_revoked` | An entry signed by a key revoked from its sequence number |
| `bad_key_event` | A key event that reuses a key, revokes an unknown or the current stream key |
| `bad_genesis` | Entry 1 is not a self-signed stream key certification for this stream id |
| `untrusted_root` | The genesis key is not the pinned one |
| `wrong_stream` | An entry or HEAD of another stream |
| `bad_seq` | A sequence number that is not the previous plus one |
| `bad_prev` | A `prev` that is not the previous entry's hash |
| `duplicate_id` | An entry id used before in the stream |
| `bad_intent` | An outcome or reconcile with no open intent to close |
| `bad_approval` | An `approval.entry` that is not an earlier approval entry |
| `bad_hlc` | A hybrid logical clock that went backwards |
| `bad_head` | HEAD malformed, unsigned, rolled back, or not matching the stream |
| `bad_batch` | A batch file that breaks the layout rules |
| `missing_batch` | A batch HEAD needs is absent |
| `bad_checkpoint`, `truncated`, `fork` | A checkpoint's failures ([checkpoints.md](checkpoints.md#5-error-codes)) |
