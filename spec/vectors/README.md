# Conformance test vectors

Shared vectors that every Tenbri implementation must agree on: the Rust crates, the Python and Node
bindings and the WASM verifier run all of them in CI, and any other implementation of the
[format](../README.md) can too. Once a vector is released it is frozen: a fix adds a new vector, it
never edits an old one.

Each vector will be a directory with its inputs (entries, keys, a stream on disk) and the expected
result (canonical bytes, hashes, signatures, proofs, or the exact verification error). The layout is
defined with the first vectors, before v0.1.0.

## License

To the extent possible under law, the Tenbri authors have waived all copyright and related or
neighboring rights to the files in this directory, under
[CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/), so anyone can copy them into
another implementation's test suite without conditions.
