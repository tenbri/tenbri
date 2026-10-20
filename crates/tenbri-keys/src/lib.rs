//! Tenbri stream keys, session-key certificates, rotation and revocation, and where keys are kept.
//!
//! A stream key identifies a stream and signs only key events; short-lived session keys, certified
//! by it, sign everything else (spec/format-v1.md, section 5). [`KeyStore`] keeps both, one
//! directory per stream, never under the stream's own directory. The secret half sits in a file
//! (`0600`) or, with the `keychain` feature, in the OS keychain; both keep keys exportable.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tenbri_core::sign::{SigningKey, encode_key, fingerprint};
use tenbri_core::{Entry, KeyEvent, Kind, Role, encoding};
use zeroize::Zeroizing;

/// How long a session key is certified for unless asked otherwise: 24 hours.
pub const SESSION_LIFETIME_MS: i64 = 24 * 3600 * 1000;

/// A key with its id and role. The private half is zeroed when dropped.
#[derive(Clone)]
pub struct Key {
    pub id: String,
    pub role: Role,
    /// Sessions only: the last timestamp the key may sign at.
    pub not_after: Option<String>,
    pub signing: SigningKey,
}

impl Key {
    /// A new stream key, with an id derived from it (`stream:<12 hex>`).
    pub fn new_stream() -> io::Result<Key> {
        let signing = generate()?;
        Ok(Key {
            id: format!("stream:{}", short(&signing)),
            role: Role::Stream,
            not_after: None,
            signing,
        })
    }

    /// A new session key valid from `now_ms` for `lifetime_ms`, id `sess:<date>:<12 hex>`.
    pub fn new_session(now_ms: i64, lifetime_ms: i64) -> io::Result<Key> {
        let signing = generate()?;
        let date = &encoding::format_ts(now_ms)[..10];
        Ok(Key {
            id: format!("sess:{date}:{}", short(&signing)),
            role: Role::Session,
            not_after: Some(encoding::format_ts(now_ms + lifetime_ms)),
            signing,
        })
    }

    /// `ed25519:<hex>`.
    pub fn public(&self) -> String {
        encode_key(&self.signing.verifying_key())
    }

    /// The fingerprint verifiers pin: `sha256:<hex>`.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.signing.verifying_key())
    }

    /// Whether a session key may still sign at `now_ms`.
    pub fn valid_at(&self, now_ms: i64) -> bool {
        self.not_after
            .as_deref()
            .and_then(encoding::parse_ts)
            .is_none_or(|t| now_ms <= t)
    }
}

fn generate() -> io::Result<SigningKey> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

fn short(k: &SigningKey) -> String {
    fingerprint(&k.verifying_key())["sha256:".len()..][..12].to_owned()
}

fn key_entry(event: KeyEvent) -> Entry {
    Entry {
        key: Some(event),
        ..Entry::new(Kind::Key)
    }
}

/// The draft of a key entry certifying `key`: the genesis entry for a stream key, signed by the
/// key itself; for a session key, signed by the current stream key.
pub fn certify(key: &Key) -> Entry {
    key_entry(KeyEvent::Certify {
        id: key.id.clone(),
        public: key.public(),
        role: key.role,
        not_after: key.not_after.clone(),
    })
}

/// The draft of a key entry making `new` the stream key; the current stream key signs it.
pub fn rotate(new: &Key) -> Entry {
    key_entry(KeyEvent::Rotate {
        id: new.id.clone(),
        public: new.public(),
    })
}

/// The draft of a key entry revoking key `id` from sequence number `from`; entries it signed
/// there or later stop verifying, including ones already written.
pub fn revoke(id: &str, from: u64) -> Entry {
    key_entry(KeyEvent::Revoke {
        id: id.to_owned(),
        from,
    })
}

/// Where the secret half of a key is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// A file readable only by its owner, next to the key's description.
    File,
    /// The OS keychain: macOS Keychain or Windows Credential Manager. Refused elsewhere for now.
    #[cfg(feature = "keychain")]
    Keychain,
}

/// The public description of a stored key; the secret is never in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMeta {
    pub id: String,
    pub role: Role,
    #[serde(rename = "pub")]
    pub public: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub backend: Backend,
}

/// The keys of one stream: `<keys dir>/<stream id>/`, one `<name>.json` per key and, for the file
/// backend, its `<name>.secret`.
#[derive(Clone, Debug)]
pub struct KeyStore {
    dir: PathBuf,
    stream: String,
}

/// The default keys directory: `$TENBRI_KEYS`, else `$XDG_CONFIG_HOME/tenbri/keys`, else
/// `~/.config/tenbri/keys` (`%APPDATA%\tenbri\keys` on Windows).
pub fn default_dir() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if let Some(d) = env("TENBRI_KEYS") {
        return Some(d);
    }
    let config = if cfg!(windows) {
        env("APPDATA")
    } else {
        env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))
    };
    config.map(|c| c.join("tenbri").join("keys"))
}

/// The file in a keys directory recording the fingerprints of the streams created on this machine,
/// one `<location> <fingerprint>` per line, like ssh's known_hosts.
pub const PINS: &str = "pins";

/// A stream's location as the pins file records it: an absolute path, or the URL as given.
pub fn pin_location(location: &str) -> String {
    if tenbri_store::is_url(location) {
        return location.to_owned();
    }
    fs::canonicalize(location).map_or_else(|_| location.to_owned(), |p| p.display().to_string())
}

/// Records `fingerprint` as the pin of the stream at `location` in `keys_dir`'s pins file, and
/// returns that file. The error names the file.
pub fn record_pin(keys_dir: &Path, location: &str, fingerprint: &str) -> io::Result<PathBuf> {
    let pins = keys_dir.join(PINS);
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&pins)
        .and_then(|mut f| writeln!(f, "{} {fingerprint}", pin_location(location)))
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", pins.display())))?;
    Ok(pins)
}

/// The fingerprint recorded for the stream at `location` in `keys_dir`'s pins file, with that
/// file. The last pin wins: a stream re-created at the same place is pinned anew.
pub fn recorded_pin(keys_dir: &Path, location: &str) -> Option<(String, PathBuf)> {
    let pins = keys_dir.join(PINS);
    let loc = pin_location(location);
    let text = fs::read_to_string(&pins).ok()?;
    let fp = text.lines().rev().find_map(|l| {
        let (at, fp) = l.rsplit_once(' ')?;
        (at == loc).then(|| fp.to_owned())
    })?;
    Some((fp, pins))
}

/// Refuses a keys directory inside the stream's directory, or the other way round: keys never live
/// under the stream root, so whoever can read or copy the log cannot sign as it.
pub fn check_apart(keys_dir: &Path, stream_dir: &Path) -> io::Result<()> {
    let keys = fs::canonicalize(keys_dir)?;
    let stream = fs::canonicalize(stream_dir)?;
    if keys.starts_with(&stream) || stream.starts_with(&keys) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "keys directory {} and stream {} must not contain each other",
                keys.display(),
                stream.display()
            ),
        ));
    }
    Ok(())
}

impl KeyStore {
    /// Opens (creating it, owner-only) the key directory of `stream` under `keys_dir`, after
    /// checking it is apart from `stream_dir`.
    pub fn open(keys_dir: &Path, stream_dir: &Path, stream: &str) -> io::Result<KeyStore> {
        KeyStore::open_with(keys_dir, Some(stream_dir), stream)
    }

    /// Opens the key directory of `stream`, kept in an object store (`s3://…`): no directory on
    /// this machine to keep the keys apart from.
    pub fn open_for_object_store(keys_dir: &Path, stream: &str) -> io::Result<KeyStore> {
        KeyStore::open_with(keys_dir, None, stream)
    }

    fn open_with(keys_dir: &Path, stream_dir: Option<&Path>, stream: &str) -> io::Result<KeyStore> {
        if tenbri_core::encoding::prefixed::<16>(stream, "tnb1:").is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{stream} is not a stream id"),
            ));
        }
        private_dir(keys_dir)?;
        if let Some(stream_dir) = stream_dir {
            check_apart(keys_dir, stream_dir)?;
        }
        // A stream id has a ':', which Windows does not allow in a file name.
        let dir = keys_dir.join(stream.replace(':', "-"));
        private_dir(&dir)?;
        Ok(KeyStore {
            dir,
            stream: stream.to_owned(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The stream id these keys belong to.
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// Stores `key`; refuses to replace a key already stored under the same name.
    pub fn save(&self, key: &Key, backend: Backend) -> io::Result<()> {
        let name = short(&key.signing);
        let secret = Zeroizing::new(encoding::hex(key.signing.as_bytes()));
        match backend {
            Backend::File => {
                write_new(&self.dir.join(format!("{name}.secret")), secret.as_bytes())?
            }
            #[cfg(feature = "keychain")]
            Backend::Keychain => keychain::set(&self.account(&name), &secret)?,
        }
        let meta = KeyMeta {
            id: key.id.clone(),
            role: key.role,
            public: key.public(),
            not_after: key.not_after.clone(),
            backend,
        };
        let json = serde_json::to_vec_pretty(&meta).map_err(io::Error::other)?;
        write_new(&self.dir.join(format!("{name}.json")), &json)
    }

    /// The descriptions of every stored key.
    pub fn list(&self) -> io::Result<Vec<KeyMeta>> {
        let mut out = vec![];
        for e in fs::read_dir(&self.dir)? {
            let p = e?.path();
            if p.extension().is_some_and(|x| x == "json") {
                out.push(
                    serde_json::from_slice(&fs::read(&p)?)
                        .map_err(|e| invalid(format!("{}: {e}", p.display())))?,
                );
            }
        }
        out.sort_by(|a: &KeyMeta, b| a.id.cmp(&b.id));
        Ok(out)
    }

    /// Loads the key with id `id`.
    pub fn load(&self, id: &str) -> io::Result<Key> {
        let meta = self
            .list()?
            .into_iter()
            .find(|m| m.id == id)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("no key {id} for {}", self.stream),
                )
            })?;
        let public =
            tenbri_core::sign::decode_key(&meta.public).map_err(|e| invalid(e.to_string()))?;
        let name = fingerprint(&public)["sha256:".len()..][..12].to_owned();
        let secret: Zeroizing<String> = match meta.backend {
            Backend::File => {
                Zeroizing::new(fs::read_to_string(self.dir.join(format!("{name}.secret")))?)
            }
            #[cfg(feature = "keychain")]
            Backend::Keychain => keychain::get(&self.account(&name))?,
        };
        let seed = Zeroizing::new(
            encoding::unhex::<32>(secret.trim())
                .ok_or_else(|| invalid(format!("key {id} is corrupt")))?,
        );
        let signing = SigningKey::from_bytes(&seed);
        if signing.verifying_key() != public {
            return Err(invalid(format!(
                "key {id}'s secret does not match its public key"
            )));
        }
        Ok(Key {
            id: meta.id,
            role: meta.role,
            not_after: meta.not_after,
            signing,
        })
    }

    /// Deletes key `id`: its secret, then its description. The file is unlinked, not overwritten;
    /// on a copy-on-write disk or with snapshots, copies may remain.
    pub fn delete(&self, id: &str) -> io::Result<()> {
        let key = self.load(id)?;
        let name = short(&key.signing);
        match self
            .list()?
            .into_iter()
            .find(|m| m.id == id)
            .map(|m| m.backend)
        {
            #[cfg(feature = "keychain")]
            Some(Backend::Keychain) => keychain::delete(&self.account(&name))?,
            _ => fs::remove_file(self.dir.join(format!("{name}.secret")))?,
        }
        fs::remove_file(self.dir.join(format!("{name}.json")))
    }

    #[cfg(feature = "keychain")]
    fn account(&self, name: &str) -> String {
        format!("{}/{name}", self.stream)
    }
}

fn invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn private_dir(dir: &Path) -> io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// Writes a new file readable only by its owner; never replaces one.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(all(
    feature = "keychain",
    not(any(target_os = "macos", target_os = "windows"))
))]
mod keychain {
    //! ponytail: no Linux Secret Service until keyring 4 fits the MSRV (1.88 > 1.85); key files
    //! meanwhile. keyring 3's zbus 4 is unmaintained (RUSTSEC-2026-0370..0372), and with no
    //! platform store it silently keeps secrets in memory, so it is not used at all here.
    use std::io;

    use zeroize::Zeroizing;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "the OS keychain backend supports macOS and Windows only for now; use key files",
        )
    }

    pub fn set(_: &str, _: &str) -> io::Result<()> {
        Err(unsupported())
    }

    pub fn get(_: &str) -> io::Result<Zeroizing<String>> {
        Err(unsupported())
    }

    pub fn delete(_: &str) -> io::Result<()> {
        Err(unsupported())
    }
}

#[cfg(all(feature = "keychain", any(target_os = "macos", target_os = "windows")))]
mod keychain {
    use std::io;

    use zeroize::Zeroizing;

    const SERVICE: &str = "tenbri";

    fn err(e: keyring::Error) -> io::Error {
        match e {
            keyring::Error::NoEntry => io::Error::new(io::ErrorKind::NotFound, e.to_string()),
            e => io::Error::other(e.to_string()),
        }
    }

    pub fn set(account: &str, secret: &str) -> io::Result<()> {
        let entry = keyring::Entry::new(SERVICE, account).map_err(err)?;
        if entry.get_password().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("keychain already holds {account}"),
            ));
        }
        entry.set_password(secret).map_err(err)
    }

    pub fn get(account: &str) -> io::Result<Zeroizing<String>> {
        keyring::Entry::new(SERVICE, account)
            .and_then(|e| e.get_password())
            .map(Zeroizing::new)
            .map_err(err)
    }

    pub fn delete(account: &str) -> io::Result<()> {
        keyring::Entry::new(SERVICE, account)
            .and_then(|e| e.delete_credential())
            .map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_pins_and_the_last_one_wins() {
        let tmp = std::env::temp_dir().join(format!("tenbri-pins-{}", std::process::id()));
        let (keys, stream) = (tmp.join("keys"), tmp.join("stream"));
        fs::create_dir_all(&keys).unwrap();
        fs::create_dir_all(&stream).unwrap();
        let s = stream.display().to_string();
        assert_eq!(recorded_pin(&keys, &s), None);
        let file = record_pin(&keys, &s, "sha256:aa").unwrap();
        record_pin(&keys, "s3://b/p", "sha256:bb").unwrap();
        record_pin(&keys, &format!("{s}/."), "sha256:cc").unwrap();
        let abs = fs::canonicalize(&stream).unwrap().display().to_string();
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            format!("{abs} sha256:aa\ns3://b/p sha256:bb\n{abs} sha256:cc\n")
        );
        assert_eq!(recorded_pin(&keys, &s), Some(("sha256:cc".into(), file)));
        assert_eq!(recorded_pin(&keys, "s3://b/p").unwrap().0, "sha256:bb");
        assert_eq!(recorded_pin(&keys, "s3://b/q"), None);
        let err = record_pin(&tmp.join("none"), &s, "sha256:aa").unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&tmp.join("none").join(PINS).display().to_string())
        );
        fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn stores_loads_and_refuses_keys_under_the_stream() {
        let tmp = std::env::temp_dir().join(format!("tenbri-keys-{}", std::process::id()));
        let (keys, stream) = (tmp.join("keys"), tmp.join("stream"));
        fs::create_dir_all(&stream).unwrap();
        assert!(
            KeyStore::open(
                &stream.join("keys"),
                &stream,
                "tnb1:00000000000000000000000000000000"
            )
            .is_err()
        );

        let sk = Key::new_stream().unwrap();
        let id = tenbri_core::sign::stream_id(&sk.signing.verifying_key());
        let store = KeyStore::open(&keys, &stream, &id).unwrap();
        let sess = Key::new_session(0, SESSION_LIFETIME_MS).unwrap();
        store.save(&sk, Backend::File).unwrap();
        store.save(&sess, Backend::File).unwrap();
        assert!(
            store.save(&sess, Backend::File).is_err(),
            "never replaces a key"
        );
        assert_eq!(store.load(&sk.id).unwrap().public(), sk.public());
        let s = store.load(&sess.id).unwrap();
        assert!(s.valid_at(SESSION_LIFETIME_MS) && !s.valid_at(SESSION_LIFETIME_MS + 1));
        assert_eq!(store.list().unwrap().len(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let secret = fs::read_dir(store.dir())
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| p.extension().is_some_and(|x| x == "secret"))
                .unwrap();
            assert_eq!(
                fs::metadata(secret).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        store.delete(&sess.id).unwrap();
        assert!(store.load(&sess.id).is_err());
        fs::remove_dir_all(&tmp).unwrap();
    }
}
