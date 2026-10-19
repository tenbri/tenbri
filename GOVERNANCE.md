# Governance

How Tenbri is run, who decides, and what you can count on.

## Who decides

Tenbri's maintainer, [@aminekaabachi](https://github.com/aminekaabachi), decides what lands, in what
order, and when it ships. That is said plainly so nobody has to guess. Contributors keep the
copyright in their work, which comes in under the Apache License 2.0 with a Developer Certificate of
Origin sign-off ([CONTRIBUTING.md](CONTRIBUTING.md#developer-certificate-of-origin)).

Decisions are made in the open, in issues and pull requests. What never breaks is written down: the
format promise ([spec/](spec/README.md)) and the stability policy
([CONTRIBUTING.md](CONTRIBUTING.md#stability)).

## The format

The spec in [spec/](spec/README.md) and its test vectors are the definition of Tenbri's format; the
Rust code is the reference implementation, not the definition. Once there are two maintainers, a
change under `spec/` needs both to approve it (CODEOWNERS). The aim is to move the spec to a
foundation once it has been externally reviewed.

## How work moves

1. **Issues** start at `needs-triage`. Triage gives each a type, an area and one of `accepted`,
   `needs-info`, `deferred` or `wontfix`, with a sentence saying why. `needs-info` closes itself
   after 14 days without an answer, and an answer reopens it.
2. **Accepted** issues are open to anyone; `help wanted` ones nobody is on, `good first issue` ones
   are small and well described. Say you're on one before starting.
3. **Pull requests** follow [CONTRIBUTING.md](CONTRIBUTING.md). CI checks the code, the MSRV, the
   supply chain, the bindings, tenbrid's API contract, commit subjects (Conventional Commits) and
   the DCO sign-off on every commit. A maintainer reviews every one.
4. **Releases** are cut by merging the release pull request, which collects what landed on `main`
   since the last one (below).

The maintainer aims to answer a new issue or pull request within a week, and a security report
within 72 hours ([SECURITY.md](SECURITY.md)).

## Versions and releases

- [Semantic versioning](https://semver.org). Before 1.0, a 0.x minor may break an API (listed under
  breaking changes in the changelog) but never the format; a patch never breaks.
- Versions are made from commit subjects: every push to `main` updates one pull request,
  `chore: release x.y.z`, with the next version and `CHANGELOG.md`. Merging it tags `vX.Y.Z` and
  publishes everything: crates, CLI binaries, wheels, npm packages and the container
  (`ghcr.io/tenbri/tenbri`).
- v0.1.0 is reached through pre-releases (alpha, beta, rc), each with a gate
  ([CONTRIBUTING.md](CONTRIBUTING.md#getting-to-v010)).
- The latest 0.x minor gets fixes ([SECURITY.md](SECURITY.md)).

## Changing this document

Like any decision: a pull request, said in the open. When Tenbri gains maintainers, this page says
who they are and how they decide together before anything else changes.
