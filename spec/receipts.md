# Tenbri receipts

**Status: provisional.** Part of [format v1](format-v1.md), shipped with 0.1.0-beta.1, and
provisional with it until the external cryptography review ends. Logs written by pre-releases are
not covered by the compatibility promise ([README](README.md#versioning)).

A receipt is a self-contained file that proves one or more entries are in a stream: the entries,
the stream's key history, a signed [checkpoint](checkpoints.md) that covers them, an inclusion proof
for each, and optionally RFC 3161 timestamp tokens over the checkpoint. A verifier checks it with no
network and no access to the stream, against a trust root it holds: the fingerprint of the stream's
genesis key and, if it wants independent time, the root certificates of the timestamp authorities
it trusts. Keys inside the receipt are only ever checked against that pin; a receipt that brings
its own unpinned key proves nothing.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. The
[test vectors](vectors/README.md) (`receipts.json`) are normative examples.

## 1. The receipt file

A receipt is one JSON object, in UTF-8. Writers emit its canonical form (format v1, section 3)
followed by a line feed and name the file `*.json`; verifiers accept any JSON text that parses to
the same value, so a receipt that went through a pretty-printer still verifies. The parse follows
format v1's rules (no duplicate keys, integers only); a failure is `bad_receipt`.

| Member | Required | Rule |
| --- | --- | --- |
| `v` | yes | The receipt format version, the integer `1` |
| `checkpoint` | yes | The signed checkpoint note (checkpoints.md, section 2), as a string, signature lines included |
| `entries` | yes | A non-empty array of `{entry, proof}`, in strictly increasing `seq` |
| `rfc3161` | no | A non-empty array of RFC 3161 responses over the checkpoint (section 5), each the standard base64 (padded) of a DER `TimeStampResp` |

Any other member fails with `bad_receipt`.

Each item of `entries` has exactly two members:

| Member | Rule |
| --- | --- |
| `entry` | A stored entry as a JSON object. Its stored line is the canonical serialisation of this object (format v1, section 3), so the entry hash is computed from that |
| `proof` | The inclusion proof of the entry in the checkpoint's tree: RFC 9162's `PATH(seq - 1, D[size])` (checkpoints.md, section 1), leaf side first, each node hash as `sha256:` and 64 lowercase hex digits |

The entries are the ones the receipt is made for **and the stream's key history**: the first item
MUST be the genesis entry (seq 1), and the receipt MUST hold every `key` entry the stream has at or
before the checkpoint's size. The entries the receipt is made for are its entries that are not
`key` entries (or all of them, for a receipt about key entries alone).

## 2. Example

```json
{
  "checkpoint": "tnb1:170241c12e8724974ea3b10fe536b7d8\n9\nhJsj…Regs=\n\n— tnb1:170241c12e8724974ea3b10fe536b7d8 r5sy…7g0=\n",
  "entries": [
    {"entry": {"id": "01M4XRC0000000000000000001", "kind": "key", "seq": 1, …}, "proof": ["sha256:…", "sha256:…", "sha256:…", "sha256:…"]},
    {"entry": {"id": "01M4XRC0000000000000000002", "kind": "key", "seq": 2, …}, "proof": […]},
    {"entry": {"id": "01M4XRC0000000000000000004", "kind": "decision", "phase": "outcome", "seq": 4, …}, "proof": […]},
    {"entry": {"id": "01M4XRC0000000000000000005", "kind": "key", "seq": 5, …}, "proof": […]}
  ],
  "rfc3161": ["MIIE…"],
  "v": 1
}
```

## 3. Verifying a receipt

The verifier holds `pin`, the fingerprint of the stream's genesis key (format v1, section 5), and
optionally a set of TSA root certificates. It runs these checks in this order and reports the
first that fails, naming the entry's seq where there is one:

| # | Check | Fails with |
| --- | --- | --- |
| 1 | The file is a JSON object with the members of section 1, `v` is 1, `entries`, its items and `rfc3161` are well formed | `bad_receipt` |
| 2 | `checkpoint` parses as a checkpoint note (checkpoints.md, section 2) | `bad_checkpoint` |
| 3 | The first entry is seq 1 | `bad_receipt` |
| 4 | For each entry, in order, a to c: | |
| 4a | Its `seq` is above the previous entry's, and the entry rules of format v1, section 9, steps 1, 2, 4, 6, 7 and the key events of step 9 hold, with the keys of the receipt's earlier key entries | `bad_seq`, or that rule's code (`bad_signature`, `untrusted_root`, `unknown_signer`, `key_expired`...) |
| 4b | For the genesis entry: its `stream` is the checkpoint's origin | `wrong_stream` |
| 4c | Its proof verifies its entry hash at leaf `seq - 1` of a tree of the checkpoint's size with the checkpoint's root (RFC 9162, section 2.1.3.2); an entry beyond the size fails | `bad_proof` |
| 7 | No key entry in the receipt revokes the signer of an entry at its seq or earlier (format v1, section 5, rule 5) | `key_revoked` |
| 8 | The checkpoint's signer rows (checkpoints.md, section 4): signed by a session key the receipt's key history certified at or before the checkpoint's size and had not revoked by then | `unknown_signer`, `signer_not_allowed`, `key_revoked`, `bad_checkpoint` |
| 9 | If the verifier pinned TSA roots: each token in `rfc3161` verifies over the checkpoint (section 5) | `bad_timestamp` |

Step 4a is format v1's verification of an entry without the rules that need every entry in between:
`prev` (step 4's second half), id uniqueness (step 5), `hlc` (step 8), and intents and approvals
(step 9's first half). The inclusion proofs stand in for them: the checkpoint's signer vouches for
the whole tree, which the stream's own verification checked when it was written.

A verifier that pinned no TSA roots does not check the tokens, and MUST NOT present the receipt's
time as independent: it reports the tokens as unchecked.

On success the verifier can state: under the pinned stream key, these entries are entries `seq` of
stream `origin`, among the first `size` entries the checkpoint covers, and (with a checked token)
that checkpoint existed by the token's time.

## 4. Making a receipt

The issuer reads the stream and verifies it (format v1, section 9), then picks a checkpoint whose
size is at least the largest seq to prove. It SHOULD pick the earliest such checkpoint that has an
RFC 3161 token, which gives the tightest independent time, and otherwise the latest checkpoint. It
writes the genesis entry, every key entry up to the checkpoint's size, and the entries to prove,
each with its inclusion proof in that checkpoint's tree, and the checkpoint's tokens.

The reference implementation is `tenbri receipt create <stream> --entry <seq|id>` and tenbrid's
`GET /v1/streams/{stream}/entries/{id}/receipt` (gRPC `GetReceipt`). A receipt is only possible
once a checkpoint covers the entry: the writer makes one within 60 seconds of a write
(checkpoints.md, section 3), `tenbri checkpoint` makes one at once, and tenbrid seals one when a
receipt is asked for an entry no checkpoint covers yet.

## 5. RFC 3161 timestamps

A checkpoint MAY be timestamped by an RFC 3161 timestamp authority (TSA) the operator names. The
token gives the checkpoint, and every entry it covers, an independent time: they existed by then.
It does not stop a rewrite, since the operator stores it (checkpoints held outside the operator
do that, checkpoints.md, section 4).

- **What is timestamped.** The message imprint is SHA-256 of the checkpoint's **note text**: the
  three lines with their line feeds, without the signatures (checkpoints.md, section 2). Cosignatures
  added later leave the token valid.
- **The request.** A `TimeStampReq` (RFC 3161, section 2.4.1) of version 1 with that imprint,
  `certReq` true so the token carries the TSA's certificate, and a random nonce, sent by HTTP POST as
  `application/timestamp-query` (section 3.4). The writer checks that the response is granted, has
  that imprint and echoes the nonce.
- **Storage.** The DER `TimeStampResp` (what `openssl ts -reply` writes) is stored next to the
  checkpoint, `anchors/` and the size zero-padded to 12 digits, with `.tsr`:
  `anchors/000000002000.tsr`, with put-if-absent. Timestamping is opt-in, hourly by default rather
  than per checkpoint: tenbrid's `[anchor]` timestamps the latest checkpoint every `every_s` seconds
  if it has no token; `tenbri checkpoint --tsa <url>` does it at once.
- **Verification.** A token verifies when, with no network:
  1. the response's status is granted (0 or 1) and it holds a CMS `SignedData` token whose content
     is a `TSTInfo` (RFC 3161, section 2.4.2);
  2. the `TSTInfo`'s message imprint is SHA-256, SHA-384 or SHA-512 of the note text;
  3. the token has exactly one signer, identified among the token's certificates by issuer and
     serial number or subject key identifier;
  4. its signed attributes name the `TSTInfo` content type, hold the `TSTInfo`'s digest, and hold
     an ESS signing-certificate attribute (RFC 2634 or RFC 5035) whose first certificate hash is
     the signer certificate's;
  5. the signature over the signed attributes verifies with the signer certificate's key: RSA
     PKCS #1 v1.5 or ECDSA on P-256 or P-384, with SHA-256, SHA-384 or SHA-512;
  6. the signer certificate's extended key usage includes `id-kp-timeStamping`;
  7. the signer certificate chains, through CA certificates the token carries, to a root the
     verifier pinned (a pinned certificate itself, or one that signed the last certificate), every
     certificate valid at `genTime`, at most 8 certificates long.

  Any failure is `bad_timestamp`. Revocation of TSA certificates (CRL, OCSP) is not checked: to
  stop trusting a TSA, unpin its root.
- **Time.** `genTime` is the TSA's time; the entries' `ts` stays the writer's claim. A verifier
  shows both and never one as the other.

## 6. Error codes

Added to format v1's table (format-v1.md, section 10); `bad_checkpoint`, `wrong_stream`,
`unknown_signer`, `signer_not_allowed`, `key_expired`, `key_revoked` and the entry codes are reused
with their meanings.

| Code | Meaning |
| --- | --- |
| `bad_receipt` | A receipt file that is malformed, of another version, or does not start with the genesis entry |
| `bad_proof` | An entry whose inclusion proof does not verify against the receipt's checkpoint: the entry or its proof was changed, the checkpoint is another one, or the entry is beyond it |
| `bad_timestamp` | An RFC 3161 token that is malformed, for other data, changed, not signed for time stamping, or not chaining to a pinned TSA root at its time |

## 7. What a receipt does not show

- **A revocation the issuer left out.** The verifier cannot tell that the key history is complete:
  an issuer that omits a `revoke` entry makes an entry signed by a revoked key look valid. The
  issuer is the operator, who holds the stream key anyway; against a thief holding only a session
  key, verify the stream itself (`tenbri verify --checkpoint`) against the same checkpoint.
- **Revocations after the checkpoint.** A key revoked later, from a seq at or before the entry,
  invalidates the entry in the stream but not in a receipt made before; a later receipt shows it.
- **Anything after the checkpoint**, and whether the stream still holds these entries: a receipt
  is about the checkpoint it carries. Held outside the operator, that checkpoint catches a later
  rewrite (checkpoints.md, section 4).
- **The content behind digests and bodies.** Input digests are keyed and bodies are encrypted
  blobs ([privacy.md](privacy.md)); a receipt carries them as they are. Disclosing the inputs and
  their digest key for one subject alongside a receipt is selective disclosure (*reserved*).

## 8. Open points

- **Proof size.** Each entry carries its own proof; a receipt for many entries could share nodes
  (a multiproof). Decided if receipts for large sets become common.
- **Sigstore Rekor** as a second anchor (Experimental), under `ext` or a new member.
