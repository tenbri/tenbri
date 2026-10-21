# The stream key in an HSM (Experimental)

A stream's stream key signs only key events: it certifies session keys, rotates to a new stream
key, revokes keys ([spec/format-v1.md](../spec/format-v1.md), section 5). Session keys, certified
for 24 hours, sign everything else. Kept in a key file or the OS keychain, the stream key can be
copied: whoever takes the host running tenbrid can certify session keys of their own for as long
as they like, from anywhere.

With the stream key in a PKCS#11 token, it never leaves the token. The token generates it, marked
sensitive and not extractable, and signs key events when tenbrid asks. The host keeps only
session keys.

| Someone who takes the host | Key file or keychain | PKCS#11 token |
|---|---|---|
| Carries away | The stream key: signs as the stream forever, from anywhere | One session key, valid at most 24 hours, which you revoke |
| While they are in | Can sign anything | Can ask the token to sign key events; each one is an entry in the stream, in plain sight |
| After you take the host back | Rotate the stream key and hope the old one is not used | Revoke their session key from the entry they started at; change the token PIN |

The token does not stop someone who holds the host from using it while they hold it: the PIN is on
the host. It stops them from leaving with the key.

## What you need

- tenbri and tenbrid built with the `pkcs11` feature (not in the release builds while it is
  Experimental):

  ```bash
  cargo install tenbri-cli --features pkcs11
  cargo install tenbri-server --features pkcs11
  ```

- A PKCS#11 module whose token supports Ed25519 (`CKM_EC_EDWARDS_KEY_PAIR_GEN` and `CKM_EDDSA`):
  a YubiHSM 2 (`yubihsm_pkcs11.so`), an HSM with an Ed25519-capable PKCS#11 library, or
  [SoftHSM](https://github.com/softhsm/SoftHSMv2) 2.6 or later to try it out and in tests. SoftHSM
  keeps keys in files on the same host, so it protects nothing in production.

Cloud KMSs sign with Ed25519 too (AWS KMS `ECC_NIST_EDWARDS25519`, Google Cloud KMS
`EC_SIGN_ED25519`), but have no backend here yet; any signer that keeps its key can be added
behind `tenbri_keys::External`.

## Try it with SoftHSM

```bash
brew install softhsm            # or: apt install softhsm2
mkdir -p ~/softhsm/tokens
echo "directories.tokendir = $HOME/softhsm/tokens" > ~/softhsm/softhsm2.conf
export SOFTHSM2_CONF=~/softhsm/softhsm2.conf
softhsm2-util --init-token --free --label tenbri --so-pin <so-pin> --pin <user-pin>

export TENBRI_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so  # /usr/lib/softhsm/libsofthsm2.so on Debian
export TENBRI_PKCS11_TOKEN=tenbri
export TENBRI_PKCS11_PIN=<user-pin>
tenbri init ./audit/support --pkcs11 --experimental
```

`init` prints the fingerprint to pin, as always. The keys directory holds the stream key's
description (`"backend": "pkcs11"`) and the first session key; there is no stream key file. The
key's id (`stream:<12 hex>`) is its label in the token.

The PIN is read from `TENBRI_PKCS11_PIN` only, never from a flag, which other users of the machine
could see in the process list.

## An existing stream

Rotate its stream key into the token. The current stream key signs the rotation and signs nothing
more:

```bash
tenbri keys rotate-stream ./audit/support --experimental
```

Then delete the old stream key's secret (`tenbri keys list` shows the ids; its `.secret` file is in
the keys directory) and every copy of it, backups included.

## tenbrid

Add the token to tenbrid's configuration; the PIN comes from the environment:

```toml
[pkcs11]
module = "/usr/lib/softhsm/libsofthsm2.so"   # TENBRI_PKCS11_MODULE
token = "tenbri"                             # its label; TENBRI_PKCS11_TOKEN
```

```bash
TENBRI_PKCS11_PIN=<user-pin> tenbrid --config tenbrid.toml
```

tenbrid refuses to start when a stream's current stream key is in a token and `[pkcs11]` is not
configured, or the token does not answer. When a session key has
less than a minute left, it makes a new one, asks the token to certify it, and keeps it as a key
file. A token that is unreachable then fails that write, and nothing is written; entries keep
flowing while the current session key is valid. tenbrid checks every signature the token returns
against the stream key before using it.

## When the host was taken

1. Take the host back, or stop tenbrid on it.
2. Find the first entry the intruder signed, and revoke their session key from there; the token
   signs the revocation, and their entries, before and after it, stop verifying. It asks you to
   type the key's id to confirm (`--yes` skips that):

   ```bash
   tenbri keys revoke ./audit/support sess:2026-10-21:0a1b2c3d4e5f --from 1042 --experimental
   ```

3. Change the token's user PIN.
4. Look for key events you did not make (`tenbri tail ./audit/support --all` shows key entries):
   a session key certified while they were in is theirs; revoke it too.

## Limits

- One session per key: a token that drops it (unplugged, restarted) fails every signature until
  tenbrid restarts.
- `tenbri` and tenbrid open the module when a key in it is first used, once per process, and keep
  it loaded until they exit. Commands that only read (`verify`, `query`) never open it.
- A failed `init --pkcs11` or `rotate-stream` leaves the key the token made in the token, labelled
  with its id; the error names it. Delete it with the token's tools if no stream names it.
- A build without the `pkcs11` feature ignores keys described as kept in a token: it still writes
  with the session keys it has, until they expire, and reads and verifies as usual.
- A key the token would let out (`CKA_EXTRACTABLE` true, or `CKA_SENSITIVE` false) is refused:
  generate stream keys with `tenbri`.
