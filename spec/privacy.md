# Tenbri privacy: blobs, keyed digests and erasure

**Status: provisional**, with [format v1](format-v1.md). The key words MUST, MUST NOT, SHOULD and
MAY are used as in RFC 2119. The [test vectors](vectors/README.md) (`privacy.json`) are normative
examples.

An immutable log and the right to erasure conflict unless content stays out of the chain. Format v1
keeps it out: an entry's `body` is the address of an encrypted blob and its input digests are keyed,
both under a key that belongs to the entry's `subject`. Deleting that key erases the content and
leaves every chain, checkpoint and receipt verifiable, because none of them depends on it.

## 1. Data keys

A **data key** is 32 random bytes. A key store holds one or more per **subject** (the pseudonymous
handle in an entry's `subject`) and one or more per **tenant** (the stream), used by entries with
no `subject`. Each further key of the same subject or tenant starts a new **key epoch**: new data
uses the newest epoch; older epochs stay usable to read older data until they are erased.

Two keys are derived from a data key with HKDF-SHA-256 (RFC 5869), no salt (a string of 32 zero
bytes), 32 bytes of output:

```
blob key   = HKDF-SHA-256(salt = none, IKM = data key, info = "tenbri/blob/v1",   L = 32)
digest key = HKDF-SHA-256(salt = none, IKM = data key, info = "tenbri/digest/v1", L = 32)
```

The digest key alone confirms a subject's input digests and opens nothing: it is what an operator
discloses to an auditor for one subject.

## 2. Blobs

A body is sealed with XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha, as in libsodium's
`crypto_aead_xchacha20poly1305_ietf`) under the blob key of the newest data key of the entry's
subject, or of the tenant:

```
nonce = 24 random bytes, never reused with the same data key
aad   = "tenbri/blob/v1" || 0x00 || stream id (UTF-8, as in the entry's "stream")
blob  = nonce || XChaCha20-Poly1305-Seal(blob key, nonce, body, aad)    (ciphertext, then the 16-byte tag)
```

- The blob's **address** is `blob:ct-sha256:` followed by the lowercase hex SHA-256 of the whole
  blob, nonce included. It is what the entry's `body` holds. It depends on the ciphertext only, so
  it reveals nothing about the body, and two equal bodies have different addresses.
- The blob is stored in the stream at `blobs/ct-sha256/<first 2 hex digits>/<other 62>`, written
  with put-if-absent like a batch (format-v1.md, section 8), on a local disk or an object store.
  It SHOULD be written before the entry that names it.
- A reader fetches the blob by the entry's `body`, MUST check that its SHA-256 equals the address
  (`address_mismatch` otherwise: the blob was replaced), then opens it with the entry's `stream` in
  the AAD and each epoch of the subject's (or the tenant's) data keys in turn. If none opens it,
  the result is `not_opened`: the wrong key, another stream's blob, or changed bytes. A blob
  shorter than 24 bytes is `not_opened`. A missing blob shows as a missing body, never as a broken
  chain.
- Blobs carry no key identifier, so blobs of the same subject cannot be linked by their bytes;
  trying each epoch is the price.

## 3. Input digests

An input's `digest` is

```
"hmac-sha256:" || lowercase hex HMAC-SHA-256(digest key, the input's content bytes)
```

under the digest key of the newest data key of the entry's subject, or of the tenant. Without the
key, a guessed value (an email address, a short code) cannot be confirmed from the log. Confirming a
digest means computing it with each epoch's digest key in turn.

What the content bytes are is the integration's choice (the document, the policy text, the message),
fixed per input `ref`; the integration documents it.

## 4. Erasure

Erasing a subject deletes every epoch of its data keys from the key store. Then:

- its blobs can no longer be opened, and its input digests can no longer be confirmed;
- every entry, HEAD, checkpoint, receipt and link still verifies: they hash and sign the address
  and the digest, never the key or the plaintext;
- a later key made for the same handle starts from epoch 1 with new random bytes and opens none of
  the old blobs.

Entries without a subject can only be erased tenant-wide, by erasing the tenant's keys.

An erasure is recorded in the stream as a `note` entry, written after the keys are deleted:

| Member | Value |
| --- | --- |
| `kind` | `note` |
| `subject` | The erased handle; absent for a tenant-wide erasure |
| `action` | `{type: "tenbri.erase", target: <reason>}`: the reason is a reference, such as the request id |
| `principal` | Who asked for it, when known |

A new key epoch is recorded the same way, with `action` `{type: "tenbri.key_epoch", target:
"epoch:<n>"}`. Action types starting with `tenbri.` are reserved for the notes Tenbri writes.

A derived query index holds subjects, targets and input refs in plaintext, so the erasure reaches it:
it drops the subject's entries before the note, and keeps the note itself without its `subject`, so
erasures stay listable by action. An index rebuilt from the stream does the same; the subject's
entries after the note are indexed again.

## 5. The local key store

The local key store (Stable) is a directory beside the stream's signing keys: `<keys
dir>/<stream id, ':' as '-'>/data/`, never under the stream's directory or bucket prefix.

- One file per subject and epoch, `s-<hex SHA-256 of the handle>.<epoch>.json` (the tenant's:
  `tenant.<epoch>.json`), holding `{stream, subject, epoch, created, key}` with `key` the data key
  in lowercase hex. A file is created exclusively and never rewritten, so concurrent writers and
  rotations cannot lose an epoch.
- On Unix the directory MUST be mode `0700` and each file `0600`; an implementation refuses to use
  a key store open to group or others, or a symlink in place of either.
- Erasure overwrites each file with zeros, syncs it, deletes it and syncs the directory. Effective
  erasure is immediate on a disk without snapshots; on copy-on-write filesystems, with snapshots,
  or with backups of the key store, old copies survive until those are gone. The key store MUST NOT
  sit in the log's versioned or Object Lock bucket, nor in its backups.

Key management services and HSMs are not part of format v1; a key store backed by one stores and
deletes the same data keys.
