//! **Experimental.** Stream keys in a PKCS#11 token: an HSM, a YubiHSM 2, a cloud HSM, or SoftHSM
//! for tests. The token generates the Ed25519 key (`CKM_EC_EDWARDS_KEY_PAIR_GEN`), marked
//! sensitive and not extractable, and signs with it (`CKM_EDDSA`, pure Ed25519); the key never
//! leaves it. The key's id (`stream:<12 hex>`) is its `CKA_LABEL` in the token.

use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11};
use cryptoki::error::{Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use tenbri_core::sign::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::{External, Key, name};

/// The DER of Ed25519's OID, 1.3.101.112: the `CKA_EC_PARAMS` of an Ed25519 key.
const ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];

/// One token of a PKCS#11 module, logged in as its user when first used. The module is
/// initialized once per process: make one `Token` and share it.
pub struct Token {
    module: PathBuf,
    label: String,
    pin: AuthPin,
    opened: OnceLock<(Pkcs11, Slot)>,
}

fn err(e: Error) -> io::Error {
    io::Error::other(format!("PKCS#11: {e}"))
}

impl Token {
    /// The token labelled `label` in the module at `module`, which `pin` (the user PIN) opens.
    /// Nothing is loaded until a key is asked for.
    pub fn new(module: PathBuf, label: String, pin: Zeroizing<String>) -> Arc<Token> {
        Arc::new(Token {
            module,
            label,
            pin: AuthPin::new(pin.as_str().into()),
            opened: OnceLock::new(),
        })
    }

    /// The module, loaded and initialized, and the token's slot.
    fn opened(&self) -> io::Result<&(Pkcs11, Slot)> {
        if let Some(o) = self.opened.get() {
            return Ok(o);
        }
        let module = &self.module;
        let ctx = Pkcs11::new(module)
            .map_err(|e| io::Error::other(format!("{}: {e}", module.display())))?;
        match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Err(Error::Pkcs11(RvError::CryptokiAlreadyInitialized, Function::Initialize)) => {}
            r => r.map_err(err)?,
        }
        // The module stays loaded until the process exits: unloaded, a module's thread-exit
        // hooks (SoftHSM's) would run code no longer mapped.
        std::mem::forget(ctx.clone());
        let mut slot = None;
        for s in ctx.get_slots_with_token().map_err(err)? {
            if ctx.get_token_info(s).map_err(err)?.label().trim_end() == self.label {
                slot = Some(s);
                break;
            }
        }
        let slot = slot.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "no PKCS#11 token labelled {:?} in {}",
                    self.label,
                    module.display()
                ),
            )
        })?;
        Ok(self.opened.get_or_init(|| (ctx, slot)))
    }

    /// A read-write session, logged in.
    fn session(&self) -> io::Result<Session> {
        let (ctx, slot) = self.opened()?;
        let s = ctx.open_rw_session(*slot).map_err(err)?;
        match s.login(UserType::User, Some(&self.pin)) {
            Err(Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            r => r.map_err(err)?,
        }
        Ok(s)
    }

    /// A new stream key, generated in the token, which keeps it: sensitive, not extractable.
    pub fn new_stream(&self) -> io::Result<Key> {
        let s = self.session()?;
        let (public, private) = s
            .generate_key_pair(
                &Mechanism::EccEdwardsKeyPairGen,
                &[
                    Attribute::Token(true),
                    Attribute::Private(false),
                    Attribute::Verify(true),
                    Attribute::EcParams(ED25519.to_vec()),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Private(true),
                    Attribute::Sensitive(true),
                    Attribute::Extractable(false),
                    Attribute::Sign(true),
                ],
            )
            .map_err(err)?;
        let point = public_key(&s, public)?;
        let id = format!("stream:{}", name(&point));
        for o in [public, private] {
            s.update_attributes(o, &[Attribute::Label(id.clone().into_bytes())])
                .map_err(err)?;
        }
        Key::external_stream(Arc::new(TokenKey {
            session: Mutex::new(s),
            key: private,
            public: point,
        }))
    }

    /// The key labelled `id`, whose public half must be `public`, as a signer. Refuses a key
    /// the token would let out.
    pub fn key(&self, id: &str, public: &VerifyingKey) -> io::Result<Arc<dyn External>> {
        let s = self.session()?;
        let find = |class| {
            s.find_objects(&[
                Attribute::Class(class),
                Attribute::KeyType(KeyType::EC_EDWARDS),
                Attribute::Label(id.as_bytes().to_vec()),
            ])
            .map_err(err)
        };
        let not_one = |what: &str, n: usize| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("the PKCS#11 token holds {n} {what} labelled {id}, not one"),
            )
        };
        let (pubs, privs) = (
            find(ObjectClass::PUBLIC_KEY)?,
            find(ObjectClass::PRIVATE_KEY)?,
        );
        let ([p], [key]) = (&pubs[..], &privs[..]) else {
            return Err(if pubs.len() == 1 {
                not_one("private keys", privs.len())
            } else {
                not_one("public keys", pubs.len())
            });
        };
        if public_key(&s, *p)? != *public {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the PKCS#11 token's key {id} is not the one described"),
            ));
        }
        let attrs = s
            .get_attributes(
                *key,
                &[AttributeType::Extractable, AttributeType::Sensitive],
            )
            .map_err(err)?;
        let exportable = attrs.iter().any(|a| {
            matches!(a, Attribute::Extractable(true)) || matches!(a, Attribute::Sensitive(false))
        });
        if exportable || attrs.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the PKCS#11 token's key {id} is exportable; generate one with tenbri"),
            ));
        }
        Ok(Arc::new(TokenKey {
            session: Mutex::new(s),
            key: *key,
            public: *public,
        }))
    }
}

/// The Ed25519 public key of `o`, from its `CKA_EC_POINT`: a DER octet string, or the 32 bytes
/// as some modules return them.
fn public_key(s: &Session, o: ObjectHandle) -> io::Result<VerifyingKey> {
    let attrs = s
        .get_attributes(o, &[AttributeType::EcPoint])
        .map_err(err)?;
    let point = attrs.iter().find_map(|a| match a {
        Attribute::EcPoint(p) => Some(&p[..]),
        _ => None,
    });
    let raw = match point {
        Some([0x04, 0x20, rest @ ..]) if rest.len() == 32 => rest,
        Some(b) if b.len() == 32 => b,
        _ => &[][..],
    };
    <[u8; 32]>::try_from(raw)
        .ok()
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the PKCS#11 token returned no Ed25519 public key",
            )
        })
}

/// A key in the token, with its own logged-in session.
///
/// ponytail: one session, opened once; a token that drops it (unplugged, restarted) makes every
/// signature fail until tenbrid restarts. Reopen on CKR_SESSION_HANDLE_INVALID if that bites.
struct TokenKey {
    session: Mutex<Session>,
    key: ObjectHandle,
    public: VerifyingKey,
}

impl External for TokenKey {
    fn public(&self) -> VerifyingKey {
        self.public
    }

    fn sign(&self, msg: &[u8]) -> io::Result<Signature> {
        let s = self
            .session
            .lock()
            .map_err(|_| io::Error::other("PKCS#11: the session's lock is poisoned"))?;
        let mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
        let sig = s.sign(&mech, self.key, msg).map_err(err)?;
        <[u8; 64]>::try_from(&sig[..])
            .map(|b| Signature::from_bytes(&b))
            .map_err(|_| io::Error::other("PKCS#11: a signature that is not 64 bytes"))
    }
}
