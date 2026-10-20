# Tenbri format specification

**Format v1: provisional.** The format is not final until its external cryptography review ends,
before the last 0.1.0 release candidate. Logs written by pre-releases (0.1.0-alpha to -rc) are not
covered by the promise below.

This directory is the definition of Tenbri's format; the Rust crates are the reference
implementation, not the definition. A tool that follows this spec can read and verify a Tenbri log
with no Tenbri binary at all.

- [format-v1.md](format-v1.md): entries, canonical bytes (RFC 8785), the hash chain, signatures
  with domain separation, keys, HEAD, the storage layout and the write protocol. Links land in a
  later pre-release.
- [checkpoints.md](checkpoints.md): the RFC 6962 Merkle tree over entry hashes, inclusion and
  consistency proofs, checkpoints as C2SP signed notes, and verifying a stream against one.
- [receipts.md](receipts.md): receipts, self-contained proofs that entries are in a stream,
  checked offline against a pinned key, and RFC 3161 timestamps of checkpoints.
- [vectors/](vectors/README.md): the conformance test vectors.

## Versioning

- The format version is a constant, changed only by hand, and checked by CI against this spec and
  the [test vectors](vectors/README.md). It is not the software version and never moves with a release.
- **Compatibility promise**: from the v0.1.0 tag, every later release reads and verifies every format
  version it ever accepted.
- **Changes**: fields can only be added in a new format version; v1 readers reject unknown top-level
  fields. Experimental features write only under `ext`, so they never break the promise.
- **Deprecation**: a format version found weak stays readable forever, but `tenbri verify` reports
  the weakness and the writer refuses to create new streams in it.
- **Breaking change**: a new stream whose first entry links to the last checkpoint of the old one;
  both stay verifiable.

## Changing the spec

Open a "Format or spec change" issue first. The pull request adds conformance vectors for every case
it introduces and, once there are two maintainers, needs both to approve it
([GOVERNANCE.md](../GOVERNANCE.md#the-format)).

The spec text is Apache-2.0, like the rest of the repository; the vectors are CC0.
