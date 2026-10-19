# Contributing

Thanks for looking. A short conversation before a large pull request saves us both time.

## Before you write code

- **Bug fix?** Open a pull request directly.
- **Anything larger?** Open an issue first.
- **A change to the format** (what a stream holds, how it is signed or verified)? Use the
  "Format or spec change" issue template: the format is a promise ([spec/](spec/README.md)).
- **Looking for a way in?** Issues labeled `good first issue` are small and well described;
  `help wanted` ones are accepted and nobody is on them. Say you're taking one. Who decides what is
  in [GOVERNANCE.md](GOVERNANCE.md).

## Setup

Rust 1.85 or later (the MSRV), and for the bindings Python 3.10+ with
[maturin](https://www.maturin.rs), Node 20+, and [wasm-pack](https://rustwasm.github.io/wasm-pack/).

```bash
cargo build --workspace
cargo nextest run --workspace     # or cargo test --workspace
```

The bindings:

```bash
pip install ./bindings/python && python bindings/python/tests/test_import.py
(cd bindings/node && npm ci && npx napi build --platform && npm test)
(cd bindings/wasm && wasm-pack build --target web --out-dir pkg --no-pack)
```

## Before you push

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo nextest run --workspace
cargo deny check
```

## House rules

1. **The core does no I/O.** `tenbri-core` compiles unchanged to native, Python, Node and WASM.
   Files, networks and clocks live in the store, the writer and the bindings.
2. **No unsafe code** in Tenbri's own crates (`unsafe_code = "forbid"` in the workspace). Only the
   binding crates, whose generated code needs it, are exempt.
3. **Prefer deleting to adding.** A new dependency needs to beat a few lines of standard library,
   and its license must be in `deny.toml`. A new abstraction needs a second caller.
4. **Non-trivial logic ships with a test** that fails without the change.
5. **Trust boundaries are never simplified.** Parsing, verification, key handling and tenbrid's
   inputs get the careful version, always.
6. **Experimental means gated.** An Experimental feature sits behind a Cargo feature or an
   experimental module (`tenbri.experimental` in Python), and its CLI command needs `--experimental`.
7. **Deliberate shortcuts get a `ponytail:` comment** naming the ceiling and the upgrade path.

## Format changes

The format version is a constant changed only by hand, never by a release. A pull request that
changes the format adds conformance vectors under [spec/vectors/](spec/vectors/README.md) for every
case it introduces, and CI runs them through Rust, Python, Node and WASM. Fields are only added in a
new format version; experimental data goes under `ext`.

## tenbrid's API contract

The OpenAPI and protobuf files under `contract/` are frozen per major API version. Add, never change:
a new optional field, a new response field, a new route. CI checks your branch against the base
branch's contract (oasdiff, buf breaking).

## Developer Certificate of Origin

Tenbri is under the [Apache License 2.0](LICENSE), and contributions come in under the same license.
There is no CLA. Instead, every commit carries a `Signed-off-by` line with your name and the
commit's author email, certifying the [Developer Certificate of Origin](https://developercertificate.org):
that you wrote the change, or otherwise have the right to submit it under the project's license.

```bash
git commit -s -m "fix(writer): retry the HEAD swap after a 412"
git rebase --signoff main   # sign commits you already made
```

pr.yml checks every commit in a pull request.

## Commits

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `chore:`; `feat!:` for a breaking
change), with an optional area as scope: `fix(writer): ...`. Keep the subject under 72 characters.
CI checks every commit, because the changelog and the next version are made from them: a `fix:` is a
patch, a `feat:` a minor, and before 1.0 a `feat!:` is a minor too (never a jump to 1.0). Pull
requests are squash-merged, so the title is the subject people read in the release notes: write it
for them.

## Releases

Nobody bumps a version or writes a changelog by hand. Each push to `main` updates one pull request,
`chore: release x.y.z`, maintained by [Release Please](https://github.com/googleapis/release-please):
the next version, `CHANGELOG.md`, the `[workspace.package]` version every crate inherits (and
`Cargo.lock`) and `bindings/wasm/package.json`. The Python package reads its version from Cargo and
the npm packages get theirs at publish time. Merging the pull request tags `vX.Y.Z` and creates the
GitHub release; [release.yml](.github/workflows/release.yml) then publishes the crates, the CLI
binaries, the wheels, the npm packages and the container from that tag.

All crates and packages share one version and one tag. Registries spell pre-releases differently:
`0.1.0-alpha.1` on crates.io and npm is `0.1.0a1` on PyPI.

### Getting to v0.1.0

Until 0.1.0 every release is a pre-release (`versioning: prerelease`, `prerelease: true`,
`prerelease-type: alpha` in `release-please-config.json`), starting at `initial-version`
(0.1.0-alpha.1). Each later stage is moved by a one-time
`Release-As:` footer on a commit that reaches `main` (an empty one is enough), never by a value
left in the config. Its subject must not look like the release pull request's (`chore: release ...`):

| Stage | How the release pull request gets its version |
|---|---|
| 0.1.0-alpha.1 | Automatic: `initial-version` in the config, used while no release exists yet |
| 0.1.0-alpha.2 and later | Automatic: each merge of the release pull request increments the counter |
| 0.1.0-beta.1 | Once the alpha gate passes: `git commit --allow-empty -s -m "chore: start 0.1.0-beta.1" -m "Release-As: 0.1.0-beta.1"` |
| 0.1.0-rc.1, -rc.2 | `git commit --allow-empty -s -m "chore: start 0.1.0-rc.1" -m "Release-As: 0.1.0-rc.1"`; later rcs increment automatically |
| 0.1.0 | Set `"prerelease": false` in `release-please-config.json` in a pull request whose squash commit carries the footer `Release-As: 0.1.0` |

Pre-releases publish to next channels only: npm dist-tag `next`, a PyPI pre-release, a crates.io
pre-release version, a GitHub pre-release, and only the exact container tag (`0.1.0-alpha.1`).

`release-please-config.json` is release-type `simple` with TOML `extra-files` for
`[workspace.package].version` and for the workspace's own entries in `Cargo.lock` (the ones with no
`source`): Release Please's `rust` type and `cargo-workspace` plugin reject inherited versions. To see
what the next release pull request would be:

```bash
npx release-please release-pr --dry-run --repo-url=tenbri/tenbri --token="$(gh auth token)"
```

release.yml does not build with `--locked`, so a lock file left behind would still publish the right
version.

### Stability

- **Format**: every format version ever accepted stays readable and verifiable by every later
  release, from the v0.1.0 tag ([spec/](spec/README.md)).
- **APIs**: the Rust, Python and TypeScript APIs may change in a 0.x minor release, always listed
  under breaking changes in the changelog; a patch release never breaks. Experimental features may
  change in any minor release.
- **CLI**: command names and exit codes are stable from v0.1.0; `--json` output is versioned.
- **MSRV**: 1.85. It moves at most once per minor release, never in a patch.
- **Platforms**: Linux x86_64 and arm64 (glibc and musl), macOS x86_64 and arm64, Windows x86_64;
  Python 3.10 and later; Node active LTS releases.

How versions and support work is also in [GOVERNANCE.md](GOVERNANCE.md#versions-and-releases).
