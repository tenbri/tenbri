## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo nextest run --workspace` pass
- [ ] Non-trivial logic has a test that fails without the change
- [ ] Every commit is signed off (`git commit -s`, the DCO) and its subject is a Conventional Commit
- [ ] A format change (spec/) adds conformance vectors under `spec/vectors/` and bumps no existing format version
- [ ] A new public API is documented; an Experimental one sits behind a Cargo feature or an experimental module
- [ ] tenbrid's OpenAPI or protobuf contract only gains, never changes (contract/)
- [ ] Any deliberate shortcut carries a `ponytail:` comment naming its ceiling
