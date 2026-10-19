# Security Policy

Tenbri exists to make agent decisions provable, so a flaw in how it signs, chains or verifies is
the most serious kind of bug it can have.

## Supported versions

| Version | Security fixes |
|---|---|
| Latest 0.x minor | Yes |
| Older 0.x minors | No: upgrade to the latest minor, which reads every format version they wrote |
| Pre-releases (0.1.0-alpha, -beta, -rc) | Only the newest; an older pre-release is unsupported once a newer one exists |

A fix never waits for a minor: it ships as a patch on the supported line.

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately through GitHub Security Advisories:
https://github.com/tenbri/tenbri/security/advisories/new

Include reproduction steps, the affected version or commit, and, for a verification flaw, a stream
or test vector that shows it. You'll get an acknowledgement within 72 hours and an assessment within
seven days. Credit is given unless you'd rather stay anonymous.

## Disclosure

We disclose 90 days after the report, or when a fix is released if that is sooner, and agree the
date with you. If a vulnerability is being exploited, we may disclose sooner, with mitigations.

## Scope

In scope:

- A stream, checkpoint, receipt or proof that verifies after it was altered, truncated, reordered or
  rewritten, or a forged signature that verifies;
- canonicalisation or parsing differences between the Rust, Python, Node and WASM verifiers;
- key material written where the documentation says it is not (under the log root, in logs, in the
  index), or a key that survives rotation or revocation;
- erasure that leaves recoverable content or digests behind;
- two writers both succeeding on one lane;
- tenbrid authentication, authorisation, quota bypass, or denial of service from an unauthenticated
  client;
- the release pipeline: a published artifact whose provenance attestation does not match its source.

Out of scope: an attacker who holds the stream's signing key and the verifier's trust root (Tenbri
proves who signed, not that the signer was right), rewrites that only a checkpoint held outside the
operator's control can catch when no such checkpoint was kept, and issues in a deployment's own
infrastructure.
