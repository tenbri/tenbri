//! Tenbri checkpoint anchoring: RFC 3161 timestamp tokens (Sigstore Rekor later, Experimental).
//!
//! A timestamp authority (TSA) the operator names signs the hash of a checkpoint's note text, so
//! the checkpoint, and every entry it covers, existed by that time (spec/receipts.md, section 5).
//! The token is stored next to the checkpoint (`anchors/<size>.tsr`) and carried in receipts. It
//! adds independent time only: the operator stores it, so it does not stop a key holder rewriting
//! the stream.
//!
//! - [`request`] makes a request, [`timestamp`] (feature `client`) sends it over HTTP.
//! - [`verify`] checks a response against the verifier's pinned TSA roots, with no network.
//! - [`verify_receipt`] checks a whole receipt: `tenbri_merkle::receipt::verify`, then its tokens.
//! - [`test_tsa`] (feature `test-tsa`) is a TSA in memory for tests and test vectors.

use std::time::Duration;

use cms::cert::CertificateChoices;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{Int, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use rsa::pkcs8::DecodePublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tenbri_core::{Code, Error};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, SubjectKeyIdentifier};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "test-tsa")]
pub mod test_tsa;

#[cfg(feature = "client")]
pub use client::timestamp;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) mod oid {
    use der::asn1::ObjectIdentifier as O;
    pub const SHA256: O = O::new_unwrap("2.16.840.1.101.3.4.2.1");
    pub const SHA384: O = O::new_unwrap("2.16.840.1.101.3.4.2.2");
    pub const SHA512: O = O::new_unwrap("2.16.840.1.101.3.4.2.3");
    pub const RSA: O = O::new_unwrap("1.2.840.113549.1.1.1");
    pub const RSA_SHA256: O = O::new_unwrap("1.2.840.113549.1.1.11");
    pub const RSA_SHA384: O = O::new_unwrap("1.2.840.113549.1.1.12");
    pub const RSA_SHA512: O = O::new_unwrap("1.2.840.113549.1.1.13");
    pub const EC: O = O::new_unwrap("1.2.840.10045.2.1");
    pub const P256: O = O::new_unwrap("1.2.840.10045.3.1.7");
    pub const P384: O = O::new_unwrap("1.3.132.0.34");
    pub const ECDSA_SHA256: O = O::new_unwrap("1.2.840.10045.4.3.2");
    pub const ECDSA_SHA384: O = O::new_unwrap("1.2.840.10045.4.3.3");
    pub const ECDSA_SHA512: O = O::new_unwrap("1.2.840.10045.4.3.4");
    pub const SIGNED_DATA: O = O::new_unwrap("1.2.840.113549.1.7.2");
    pub const TST_INFO: O = O::new_unwrap("1.2.840.113549.1.9.16.1.4");
    pub const CONTENT_TYPE: O = O::new_unwrap("1.2.840.113549.1.9.3");
    pub const MESSAGE_DIGEST: O = O::new_unwrap("1.2.840.113549.1.9.4");
    pub const TIME_STAMPING: O = O::new_unwrap("1.3.6.1.5.5.7.3.8");
    pub const SIGNING_CERT: O = O::new_unwrap("1.2.840.113549.1.9.16.2.12");
    pub const SIGNING_CERT_V2: O = O::new_unwrap("1.2.840.113549.1.9.16.2.47");
}

/// ESS `SigningCertificate` (RFC 2634) and `SigningCertificateV2` (RFC 5035): the hash of the
/// signer's certificate first. Only what the check needs.
#[derive(der::Sequence)]
pub(crate) struct SigningCert {
    pub certs: Vec<EssCertId>,
    #[asn1(optional = "true")]
    pub policies: Option<der::Any>,
}

#[derive(der::Sequence)]
pub(crate) struct EssCertId {
    /// V2 only; absent means SHA-256.
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub issuer_serial: Option<der::Any>,
}

fn bad(detail: impl Into<String>) -> Error {
    Error::new(Code::BadTimestamp, detail)
}

/// The hash a digest algorithm names, of `data`; `None` for an algorithm Tenbri does not accept.
fn digest(alg: &ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    Some(match *alg {
        oid::SHA256 => Sha256::digest(data).to_vec(),
        oid::SHA384 => Sha384::digest(data).to_vec(),
        oid::SHA512 => Sha512::digest(data).to_vec(),
        _ => return None,
    })
}

/// A DER RFC 3161 request for the SHA-256 of `text` (a checkpoint's note text), asking for the
/// TSA's certificate, with `nonce` if given.
pub fn request(text: &[u8], nonce: Option<u64>) -> Vec<u8> {
    TimeStampReq {
        version: TspVersion::V1,
        message_imprint: imprint(text),
        req_policy: None,
        nonce: nonce.map(int),
        cert_req: true,
        extensions: None,
    }
    .to_der()
    .expect("a request encodes")
}

/// `n` as a DER INTEGER: no leading zero bytes but the one a high bit needs.
pub(crate) fn int(n: u64) -> Int {
    let b = n.to_be_bytes();
    let i = b.iter().position(|&x| x != 0).unwrap_or(7);
    let mut v = b[i..].to_vec();
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    Int::new(&v).expect("an integer")
}

pub(crate) fn imprint(text: &[u8]) -> MessageImprint {
    MessageImprint {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: oid::SHA256,
            parameters: None,
        },
        hashed_message: OctetString::new(Sha256::digest(text).to_vec()).expect("32 bytes"),
    }
}

/// Parses pinned TSA roots: one or more PEM certificates.
pub fn parse_roots(pem: &[u8]) -> Result<Vec<Certificate>, Error> {
    let roots = Certificate::load_pem_chain(pem).map_err(|e| bad(format!("TSA roots: {e}")))?;
    if roots.is_empty() {
        return Err(bad("TSA roots: no certificate"));
    }
    Ok(roots)
}

/// A timestamp that verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    /// When the TSA says it signed, in seconds since the Unix epoch (`genTime`, whole seconds).
    pub unix: u64,
    /// The TSA's signing certificate subject, as an RFC 4514 string.
    pub tsa: String,
}

/// The TSTInfo and SignedData of a response, if it is a granted one; nothing is verified.
fn open(tsr: &[u8]) -> Result<(TstInfo, SignedData, Vec<u8>), Error> {
    let resp =
        TimeStampResp::from_der(tsr).map_err(|e| bad(format!("not a TimeStampResp: {e}")))?;
    if (resp.status.status as u8) > 1 {
        return Err(bad("the TSA did not grant the timestamp"));
    }
    let token = resp
        .time_stamp_token
        .ok_or_else(|| bad("the response holds no token"))?;
    if token.content_type != oid::SIGNED_DATA {
        return Err(bad("the token is not CMS SignedData"));
    }
    let sd = token
        .content
        .decode_as::<SignedData>()
        .map_err(|e| bad(format!("the token's SignedData: {e}")))?;
    if sd.encap_content_info.econtent_type != oid::TST_INFO {
        return Err(bad("the token does not hold a TSTInfo"));
    }
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .and_then(|a| a.decode_as::<OctetString>().ok())
        .ok_or_else(|| bad("the token's TSTInfo is missing"))?
        .into_bytes();
    let tst = TstInfo::from_der(&econtent).map_err(|e| bad(format!("the TSTInfo: {e}")))?;
    Ok((tst, sd, econtent))
}

/// Checks a response's imprint against `text` and its nonce, without the signature: what the
/// operator checks when it receives a response.
pub fn check_reply(tsr: &[u8], text: &[u8], nonce: Option<u64>) -> Result<(), Error> {
    let (tst, ..) = open(tsr)?;
    check_imprint(&tst, text)?;
    if let Some(n) = nonce {
        let want = int(n);
        if tst.nonce.as_ref() != Some(&want) {
            return Err(bad("the response does not echo the request's nonce"));
        }
    }
    Ok(())
}

fn check_imprint(tst: &TstInfo, text: &[u8]) -> Result<(), Error> {
    let mi = &tst.message_imprint;
    let want = digest(&mi.hash_algorithm.oid, text).ok_or_else(|| {
        bad(format!(
            "imprint hash {} is not SHA-2",
            mi.hash_algorithm.oid
        ))
    })?;
    if mi.hashed_message.as_bytes() != want {
        return Err(bad("the token is for other data than this checkpoint"));
    }
    Ok(())
}

/// Checks an RFC 3161 response (`.tsr`, DER TimeStampResp) over `text` against `roots`, the TSA
/// certificates the verifier pinned, with no network: granted, the imprint is the hash of `text`,
/// the CMS signature over the TSTInfo verifies with the TSA certificate, which is for time
/// stamping, valid at the time it gives, and chains to a pinned root (spec/receipts.md,
/// section 5). Accepts RSA PKCS #1 v1.5 and ECDSA P-256 and P-384 with SHA-2. Fails with
/// `bad_timestamp`.
///
/// ponytail: no revocation (CRL, OCSP) of TSA certificates; pin a new root to drop a TSA.
pub fn verify(tsr: &[u8], text: &[u8], roots: &[Certificate]) -> Result<Timestamp, Error> {
    let (tst, sd, econtent) = open(tsr)?;
    check_imprint(&tst, text)?;
    let at = tst.gen_time.to_unix_duration();
    let [si] = &sd.signer_infos.0.as_slice() else {
        return Err(bad("the token has more or fewer than one signer"));
    };
    let certs: Vec<&Certificate> = sd
        .certificates
        .iter()
        .flat_map(|s| s.0.iter())
        .filter_map(|c| match c {
            CertificateChoices::Certificate(c) => Some(c),
            CertificateChoices::Other(_) => None,
        })
        .collect();
    let signer = certs
        .iter()
        .copied()
        .find(|c| identifies(&si.sid, c))
        .ok_or_else(|| {
            bad("the token does not hold the TSA's certificate (request it with certReq)")
        })?;
    check_signed_attrs(si, &econtent, signer)?;
    let attrs = si
        .signed_attrs
        .as_ref()
        .expect("checked")
        .to_der()
        .map_err(|e| bad(e.to_string()))?;
    let spki = &signer.tbs_certificate.subject_public_key_info;
    if !verify_sig(
        spki,
        &si.signature_algorithm.oid,
        Some(&si.digest_alg.oid),
        &attrs,
        si.signature.as_bytes(),
    ) {
        return Err(bad("the TSA's signature does not verify"));
    }
    let eku = ext::<ExtendedKeyUsage>(signer)
        .ok_or_else(|| bad("the TSA certificate has no extended key usage"))?;
    if !eku.0.contains(&oid::TIME_STAMPING) {
        return Err(bad("the TSA certificate is not for time stamping"));
    }
    chain(signer, &certs, roots, at)?;
    Ok(Timestamp {
        unix: at.as_secs(),
        tsa: signer.tbs_certificate.subject.to_string(),
    })
}

/// The signed attributes must name the TSTInfo content type, hold its digest, and name `signer`
/// by the hash of its certificate (ESS, RFC 3161 section 2.4.1).
fn check_signed_attrs(si: &SignerInfo, econtent: &[u8], signer: &Certificate) -> Result<(), Error> {
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or_else(|| bad("the signer has no signed attributes"))?;
    let one = |oid: ObjectIdentifier| {
        let mut values = attrs
            .iter()
            .filter(|a| a.oid == oid)
            .flat_map(|a| a.values.iter());
        match (values.next(), values.next()) {
            (Some(v), None) => Some(v.clone()),
            _ => None,
        }
    };
    let ct = one(oid::CONTENT_TYPE).and_then(|v| v.decode_as::<ObjectIdentifier>().ok());
    if ct != Some(oid::TST_INFO) {
        return Err(bad("the signed content type is not TSTInfo"));
    }
    let md = one(oid::MESSAGE_DIGEST)
        .and_then(|v| v.decode_as::<OctetString>().ok())
        .ok_or_else(|| bad("no message digest attribute"))?;
    let want = digest(&si.digest_alg.oid, econtent)
        .ok_or_else(|| bad(format!("digest {} is not SHA-2", si.digest_alg.oid)))?;
    if md.as_bytes() != want {
        return Err(bad(
            "the signed digest is not the TSTInfo's (the token was changed)",
        ));
    }
    let cert = signer.to_der().map_err(|e| bad(e.to_string()))?;
    let (v1, v2) = (one(oid::SIGNING_CERT), one(oid::SIGNING_CERT_V2));
    let named = match (v2, v1) {
        (Some(a), _) => a.decode_as::<SigningCert>().ok().and_then(|s| {
            let id = s.certs.into_iter().next()?;
            let alg = id.hash_algorithm.map_or(oid::SHA256, |a| a.oid);
            Some(digest(&alg, &cert)? == id.cert_hash.as_bytes())
        }),
        (None, Some(a)) => a.decode_as::<SigningCert>().ok().and_then(|s| {
            let id = s.certs.into_iter().next()?;
            Some(Sha1::digest(&cert).as_slice() == id.cert_hash.as_bytes())
        }),
        (None, None) => return Err(bad("no ESS signing-certificate attribute")),
    };
    if named != Some(true) {
        return Err(bad(
            "the ESS signing-certificate attribute names another certificate",
        ));
    }
    Ok(())
}

/// Whether `sid` names `cert`.
fn identifies(sid: &SignerIdentifier, cert: &Certificate) -> bool {
    let tbs = &cert.tbs_certificate;
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(i) => {
            i.issuer == tbs.issuer && i.serial_number == tbs.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(k) => {
            ext::<SubjectKeyIdentifier>(cert).is_some_and(|s| s == *k)
        }
    }
}

/// The extension `T` of `cert`, decoded, if it has it.
fn ext<T: der::DecodeOwned + der::oid::AssociatedOid>(cert: &Certificate) -> Option<T> {
    cert.tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == T::OID)
        .and_then(|e| T::from_der(e.extn_value.as_bytes()).ok())
}

/// Whether `at` is within `cert`'s validity.
fn valid_at(cert: &Certificate, at: Duration) -> bool {
    let v = &cert.tbs_certificate.validity;
    v.not_before.to_unix_duration() <= at && at <= v.not_after.to_unix_duration()
}

/// Whether `issuer`'s key signed `cert`.
fn signed_by(cert: &Certificate, issuer: &Certificate) -> bool {
    cert.tbs_certificate.issuer == issuer.tbs_certificate.subject
        && cert.tbs_certificate.to_der().is_ok_and(|tbs| {
            verify_sig(
                &issuer.tbs_certificate.subject_public_key_info,
                &cert.signature_algorithm.oid,
                None,
                &tbs,
                cert.signature.raw_bytes(),
            )
        })
}

/// Walks from the TSA certificate through the token's intermediates (CA certificates) to a pinned
/// root, every certificate valid at `at`.
fn chain(
    leaf: &Certificate,
    certs: &[&Certificate],
    roots: &[Certificate],
    at: Duration,
) -> Result<(), Error> {
    if !valid_at(leaf, at) {
        return Err(bad(
            "the TSA certificate was not valid at the time it gives",
        ));
    }
    let mut cur = leaf;
    for _ in 0..8 {
        if roots.contains(cur) {
            return Ok(());
        }
        if let Some(root) = roots.iter().find(|r| signed_by(cur, r)) {
            return if valid_at(root, at) {
                Ok(())
            } else {
                Err(bad(
                    "the pinned TSA root was not valid at the time it gives",
                ))
            };
        }
        let is_ca = |c: &&&Certificate| ext::<BasicConstraints>(c).is_some_and(|b| b.ca);
        cur = certs
            .iter()
            .filter(is_ca)
            .find(|c| signed_by(cur, c) && valid_at(c, at))
            .copied()
            .ok_or_else(|| bad("the TSA certificate does not chain to a pinned root"))?;
    }
    Err(bad("the TSA certificate chain is too long"))
}

/// Verifies `sig` over `msg` with `spki`. `alg` is the signature algorithm; for CMS's plain
/// `rsaEncryption`, `digest_alg` names the hash.
fn verify_sig(
    spki: &SubjectPublicKeyInfoOwned,
    alg: &ObjectIdentifier,
    digest_alg: Option<&ObjectIdentifier>,
    msg: &[u8],
    sig: &[u8],
) -> bool {
    let hash = match *alg {
        oid::RSA_SHA256 | oid::ECDSA_SHA256 => oid::SHA256,
        oid::RSA_SHA384 | oid::ECDSA_SHA384 => oid::SHA384,
        oid::RSA_SHA512 | oid::ECDSA_SHA512 => oid::SHA512,
        oid::RSA => match digest_alg {
            Some(d) => *d,
            None => return false,
        },
        _ => return false,
    };
    let Some(prehash) = digest(&hash, msg) else {
        return false;
    };
    let Ok(der) = spki.to_der() else {
        return false;
    };
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    match (spki.algorithm.oid, curve) {
        (oid::RSA, _)
            if matches!(
                *alg,
                oid::RSA | oid::RSA_SHA256 | oid::RSA_SHA384 | oid::RSA_SHA512
            ) =>
        {
            let Ok(key) = rsa::RsaPublicKey::from_public_key_der(&der) else {
                return false;
            };
            let scheme = match hash {
                oid::SHA256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
                oid::SHA384 => rsa::Pkcs1v15Sign::new::<Sha384>(),
                _ => rsa::Pkcs1v15Sign::new::<Sha512>(),
            };
            key.verify(scheme, &prehash, sig).is_ok()
        }
        (oid::EC, Some(oid::P256)) => p256::ecdsa::VerifyingKey::from_public_key_der(&der)
            .is_ok_and(|k| {
                p256::ecdsa::Signature::from_der(sig)
                    .is_ok_and(|s| k.verify_prehash(&prehash, &s).is_ok())
            }),
        (oid::EC, Some(oid::P384)) => p384::ecdsa::VerifyingKey::from_public_key_der(&der)
            .is_ok_and(|k| {
                p384::ecdsa::Signature::from_der(sig)
                    .is_ok_and(|s| k.verify_prehash(&prehash, &s).is_ok())
            }),
        _ => false,
    }
}

/// A receipt that verified, with its timestamps.
#[derive(Clone, Debug)]
pub struct VerifiedReceipt {
    pub receipt: tenbri_merkle::receipt::Verified,
    /// One per RFC 3161 token, in the receipt's order; `None` when no TSA root was pinned, so the
    /// tokens were not checked and prove nothing.
    pub timestamps: Option<Vec<Timestamp>>,
}

/// Checks a receipt against `pin` (spec/receipts.md, section 3), then each of its RFC 3161 tokens
/// against `tsa_roots`, if the verifier pinned any.
pub fn verify_receipt(
    bytes: &[u8],
    pin: &str,
    tsa_roots: Option<&[Certificate]>,
) -> Result<VerifiedReceipt, Error> {
    let receipt = tenbri_merkle::receipt::verify(bytes, pin)?;
    let timestamps = tsa_roots
        .map(|roots| {
            receipt
                .rfc3161
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    verify(t, receipt.text.as_bytes(), roots)
                        .map_err(|e| bad(format!("token {}: {}", i + 1, e.detail)))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    Ok(VerifiedReceipt {
        receipt,
        timestamps,
    })
}

/// `unix` seconds as an RFC 3339 UTC time.
pub fn rfc3339(unix: u64) -> String {
    let t = der::DateTime::from_unix_duration(Duration::from_secs(unix)).expect("in range");
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        t.month(),
        t.day(),
        t.hour(),
        t.minutes(),
        t.seconds()
    )
}
