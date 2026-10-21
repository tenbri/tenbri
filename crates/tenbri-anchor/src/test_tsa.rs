//! A timestamp authority in memory, for tests and the receipt test vectors. Never for production:
//! its keys come from a seed anyone can read.
//!
//! Deterministic: the same seed gives the same root, TSA certificate and, for the same text and
//! time, the same response (ECDSA P-256 with RFC 6979 nonces).

use std::time::Duration;

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{GeneralizedTime, Int, ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Any, Decode, Encode, EncodePem, Sequence, Tag};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use x509_tsp::{TimeStampReq, TspVersion, TstInfo};

use crate::{EssCertId, SigningCert, imprint, int, oid};

/// The certificates' validity: 2026-01-01 to 2046-01-01.
const NOT_BEFORE: u64 = 1_767_225_600;
const NOT_AFTER: u64 = 2_398_377_600;

/// A TSA: a root CA and a time-stamping certificate it issued, both with P-256 keys.
pub struct TestTsa {
    root: Certificate,
    cert: Certificate,
    key: SigningKey,
}

/// `TimeStampResp` with a granted status, encoded here so as not to depend on CMP's types.
#[derive(Sequence)]
struct Resp {
    status: Status,
    token: ContentInfo,
}

#[derive(Sequence)]
struct Status {
    status: u8,
}

fn key(seed: &[u8], label: &str) -> SigningKey {
    let d = Sha256::new()
        .chain_update(seed)
        .chain_update(label)
        .finalize();
    SigningKey::from_bytes(&d).expect("a P-256 scalar")
}

fn time(unix: u64) -> Time {
    Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(unix)).expect("in range"))
}

impl TestTsa {
    /// The TSA made from `seed`. Its names say "Tenbri Test TSA" and the seed's first byte.
    pub fn new(seed: &[u8]) -> TestTsa {
        let (root_key, key) = (key(seed, "root"), key(seed, "tsa"));
        let tag = seed.first().copied().unwrap_or(0);
        let root_name: Name = format!("CN=Tenbri Test TSA Root {tag},O=Tenbri tests")
            .parse()
            .expect("a name");
        let validity = Validity {
            not_before: time(NOT_BEFORE),
            not_after: time(NOT_AFTER),
        };
        let spki = |k: &SigningKey| {
            SubjectPublicKeyInfoOwned::from_key(*k.verifying_key()).expect("a P-256 key")
        };
        let root = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(1u32),
            validity,
            root_name.clone(),
            spki(&root_key),
            &root_key,
        )
        .expect("a root")
        .build::<DerSignature>()
        .expect("a root");
        let mut b = CertificateBuilder::new(
            Profile::Leaf {
                issuer: root_name,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            SerialNumber::from(2u32),
            validity,
            format!("CN=Tenbri Test TSA {tag},O=Tenbri tests")
                .parse()
                .expect("a name"),
            spki(&key),
            &root_key,
        )
        .expect("a TSA certificate");
        b.add_extension(&ExtendedKeyUsage(vec![oid::TIME_STAMPING]))
            .expect("an extension");
        let cert = b.build::<DerSignature>().expect("a TSA certificate");
        TestTsa { root, cert, key }
    }

    /// The root, as PEM: what a verifier pins.
    pub fn root_pem(&self) -> String {
        self.root
            .to_pem(der::pem::LineEnding::LF)
            .expect("a certificate")
    }

    pub fn root(&self) -> &Certificate {
        &self.root
    }

    /// A granted response over the SHA-256 of `text`, timed `unix` seconds since the epoch.
    pub fn respond(&self, text: &[u8], unix: u64, nonce: Option<Int>) -> Vec<u8> {
        let tst = self.tst_info(imprint(text), unix, nonce);
        self.sign(&tst, &tst)
    }

    /// A response whose TSTInfo says `unix + 3600` but whose signature is over the one saying
    /// `unix`: a token whose time was changed after the TSA signed it.
    pub fn respond_changed(&self, text: &[u8], unix: u64) -> Vec<u8> {
        let signed = self.tst_info(imprint(text), unix, None);
        let shown = self.tst_info(imprint(text), unix + 3600, None);
        self.sign(&signed, &shown)
    }

    /// The response to a DER `TimeStampReq`, timed `unix`; `None` if it does not parse.
    pub fn reply(&self, req: &[u8], unix: u64) -> Option<Vec<u8>> {
        let req = TimeStampReq::from_der(req).ok()?;
        let tst = self.tst_info(req.message_imprint, unix, req.nonce);
        Some(self.sign(&tst, &tst))
    }

    fn tst_info(&self, mi: x509_tsp::MessageImprint, unix: u64, nonce: Option<Int>) -> TstInfo {
        TstInfo {
            version: TspVersion::V1,
            policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
            message_imprint: mi,
            serial_number: int(unix),
            gen_time: GeneralizedTime::from_unix_duration(Duration::from_secs(unix))
                .expect("in range"),
            accuracy: None,
            ordering: false,
            nonce,
            tsa: None,
            extensions: None,
        }
    }

    /// SignedData over `signed`'s digest, carrying `shown`.
    fn sign(&self, signed: &TstInfo, shown: &TstInfo) -> Vec<u8> {
        let sha256 = AlgorithmIdentifierOwned {
            oid: oid::SHA256,
            parameters: None,
        };
        let digest = Sha256::digest(signed.to_der().expect("a TSTInfo"));
        let attr = |oid: ObjectIdentifier, value: Any| Attribute {
            oid,
            values: SetOfVec::try_from(vec![value]).expect("one value"),
        };
        let attrs = SetOfVec::try_from(vec![
            attr(
                oid::CONTENT_TYPE,
                Any::encode_from(&oid::TST_INFO).expect("an OID"),
            ),
            attr(
                oid::MESSAGE_DIGEST,
                Any::encode_from(&OctetString::new(digest.to_vec()).expect("bytes"))
                    .expect("bytes"),
            ),
            attr(
                oid::SIGNING_CERT_V2,
                Any::encode_from(&SigningCert {
                    certs: vec![EssCertId {
                        hash_algorithm: None,
                        cert_hash: OctetString::new(
                            Sha256::digest(self.cert.to_der().expect("a certificate")).to_vec(),
                        )
                        .expect("bytes"),
                        issuer_serial: None,
                    }],
                    policies: None,
                })
                .expect("ESS"),
            ),
        ])
        .expect("three attributes");
        let sig: DerSignature = self.key.sign(&attrs.to_der().expect("attributes"));
        let tbs = &self.cert.tbs_certificate;
        let si = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: tbs.issuer.clone(),
                serial_number: tbs.serial_number.clone(),
            }),
            digest_alg: sha256.clone(),
            signed_attrs: Some(attrs),
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: oid::ECDSA_SHA256,
                parameters: None,
            },
            signature: OctetString::new(sig.to_bytes().to_vec()).expect("bytes"),
            unsigned_attrs: None,
        };
        let econtent = shown.to_der().expect("a TSTInfo");
        let sd = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: SetOfVec::try_from(vec![sha256]).expect("one"),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: oid::TST_INFO,
                econtent: Some(Any::new(Tag::OctetString, econtent).expect("bytes")),
            },
            certificates: Some(CertificateSet(
                SetOfVec::try_from(vec![CertificateChoices::Certificate(self.cert.clone())])
                    .expect("one"),
            )),
            crls: None,
            signer_infos: SignerInfos(SetOfVec::try_from(vec![si]).expect("one")),
        };
        Resp {
            status: Status { status: 0 },
            token: ContentInfo {
                content_type: oid::SIGNED_DATA,
                content: Any::encode_from(&sd).expect("SignedData"),
            },
        }
        .to_der()
        .expect("a response")
    }

    /// Serves RFC 3161 over HTTP on 127.0.0.1 (POST, `application/timestamp-query`), timed by the
    /// clock, until the process ends. Returns its URL.
    pub async fn serve(self) -> std::io::Result<String> {
        crate::test_http::serve(move |body| {
            let now = crate::test_http::now();
            match self.reply(body, now) {
                Some(r) => (200, "application/timestamp-reply", r),
                None => (400, "application/timestamp-reply", vec![]),
            }
        })
        .await
    }
}
