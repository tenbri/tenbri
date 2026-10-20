# Conformance test vectors

Shared vectors that every Tenbri implementation must agree on: the Rust crates, the Python and Node
bindings and the WASM verifier run all of them in CI, and any other implementation of the
[format](../README.md) can too. Once a vector is released it is frozen: a fix adds a new vector, it
never edits an old one.

**Draft.** These vectors go with the provisional [format v1](../format-v1.md) and may change until
the format is final; they are frozen at the v0.1.0 tag. They are made from fixed seeds by
`cargo run -p tenbri-core --example vectors -- spec/vectors`, except the canonical-JSON cases,
which are written by hand, and `merkle.json` and `checkpoints.json`, made from the `valid` stream of
`chains.json` by `cargo run -p tenbri-merkle --example merkle-vectors -- spec/vectors`, `privacy.json`,
made by `cargo run -p tenbri-crypt --example vectors -- spec/vectors`, and `receipts.json`, made
from the same seeds as `chains.json` and a test timestamp authority by
`cargo run -p tenbri-anchor --features test-tsa --example receipt-vectors -- spec/vectors`. Error
codes are the spec's (section 10).

| File | Each case | An implementation checks |
| --- | --- | --- |
| `keys.json` | An Ed25519 seed, its public key, fingerprint and stream id | That it derives the same three |
| `canonical.json` | `input` (or `input_hex`) and its `canonical` form, or the `error` | Canonicalisation, and that only the canonical form is a valid stored line |
| `entries.json` | `valid`: a stored `line`, its `signing_input`, `hash` and `signer_pub`; `invalid`: a `line`, optionally a `signer_pub`, and the `error` | One entry on its own: canonical bytes, fields, kind rules, signature |
| `chains.json` | A `pin` (or `null`), the stream's `lines` in order, and the `result`: `ok` with the entry count, or the first broken `seq` and its `error`. Cases with `skip` are placeholders for a later pre-release | A whole stream: chain, keys, rotation, revocation, intents |
| `heads.json` | A stored `head`, its `signer_pub`, and its `signing_input` or `error` | HEAD's form and signature |
| `streams.json` + `streams/<name>/` | A stream directory (HEAD and `batches/`), a `pin`, and the `result` | Reading the storage layout by following HEAD |
| `merkle.json` | The `leaves` (14 entry hashes), the tree `root` at every size 0 to 14, and `inclusion` and `consistency` proofs, each with `valid`: every proof of the 14-leaf tree's prefixes, and tampered ones | The Merkle tree hash and both proof verifications ([checkpoints.md](../checkpoints.md), section 1) |
| `checkpoints.json` | `notes`: a signed `note`, a `signer_pub`, and the parsed `origin`, `size`, `root` and `signed_by` (`true`, `false`, or `null` for no signature line by that key), or the `error`; `streams`: a `pin`, the `lines`, a `checkpoint`, and the `result`: `ok` with the entry count and current root, or the first broken `seq` and its `error` | Parsing and signing checkpoints, and a stream against one (sections 2 and 4) |
| `privacy.json` | `derivation`: a `data_key` and its `blob_key` and `digest_key`; `digests`: a `data_key`, a `content` and its `digest`; `blobs`: `valid` seals (`data_key`, `stream`, `nonce`, `plaintext`, the `blob` in hex, its `address` and storage `path`) and `invalid` ones with the `error` (`address_mismatch` or `not_opened`); `erased`: a stream (`pin`, `lines`) whose subject `cust_42` was erased, its `blobs` by address, the data `keys` still held, the `bodies` they open (`null`: erased) and the `inputs` whose digests they confirm, and the `result` | Key derivation, digests, sealing and opening, and that an erased subject's stream still verifies ([privacy.md](../privacy.md)) |
| `receipts.json` | `tsa_roots`: the PEM root of the test timestamp authority; `cases`: a `pin`, the `receipt` file's exact text, and the `result`: `proves` (the seqs of the non-key entries, or of all if there are none), the checkpoint `size` and the `timestamps` (`genTime` in Unix seconds) checked against `tsa_roots`, or the `error` | Receipts offline: entries, key history, proofs, the checkpoint's signer, RFC 3161 tokens ([receipts.md](../receipts.md), section 3) |

Every stream in `checkpoints.json` verifies on its own; only the checkpoint catches the change. Its
`truncation-behind-checkpoint` and `rewrite-behind-checkpoint` cases replace the placeholders of the
same name in `chains.json`. Merkle leaf indices start at 0: entry `seq` is leaf `seq - 1`.

Strings in the JSON files are the exact bytes, as UTF-8; `"\u0000"` in a `signing_input` is the
0x00 byte.

## License

To the extent possible under law, the Tenbri authors have waived all copyright and related or
neighboring rights to the files in this directory, under
[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/), so anyone can copy them into
another implementation's test suite without conditions.
