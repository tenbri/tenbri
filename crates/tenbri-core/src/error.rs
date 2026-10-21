use std::fmt;

/// The error codes of format v1 (spec/format-v1.md, section 10, spec/checkpoints.md and spec/receipts.md). Their names are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
    Parse,
    DuplicateKey,
    NotInteger,
    IntegerRange,
    NotCanonical,
    UnknownField,
    InvalidField,
    BadSignature,
    UnknownSigner,
    SignerNotAllowed,
    KeyExpired,
    KeyRevoked,
    BadKeyEvent,
    BadGenesis,
    UntrustedRoot,
    WrongStream,
    BadSeq,
    BadPrev,
    DuplicateId,
    BadIntent,
    BadApproval,
    BadHlc,
    BadHead,
    BadBatch,
    MissingBatch,
    BadCheckpoint,
    Truncated,
    Fork,
    BadReceipt,
    BadProof,
    BadTimestamp,
    Unwitnessed,
}

impl Code {
    /// Every code, in the order of the spec's table.
    pub const ALL: [Code; 32] = [
        Code::Parse,
        Code::DuplicateKey,
        Code::NotInteger,
        Code::IntegerRange,
        Code::NotCanonical,
        Code::UnknownField,
        Code::InvalidField,
        Code::BadSignature,
        Code::UnknownSigner,
        Code::SignerNotAllowed,
        Code::KeyExpired,
        Code::KeyRevoked,
        Code::BadKeyEvent,
        Code::BadGenesis,
        Code::UntrustedRoot,
        Code::WrongStream,
        Code::BadSeq,
        Code::BadPrev,
        Code::DuplicateId,
        Code::BadIntent,
        Code::BadApproval,
        Code::BadHlc,
        Code::BadHead,
        Code::BadBatch,
        Code::MissingBatch,
        Code::BadCheckpoint,
        Code::Truncated,
        Code::Fork,
        Code::BadReceipt,
        Code::BadProof,
        Code::BadTimestamp,
        Code::Unwitnessed,
    ];

    /// The code as the spec and the test vectors spell it, e.g. `bad_signature`.
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Parse => "parse",
            Code::DuplicateKey => "duplicate_key",
            Code::NotInteger => "not_integer",
            Code::IntegerRange => "integer_range",
            Code::NotCanonical => "not_canonical",
            Code::UnknownField => "unknown_field",
            Code::InvalidField => "invalid_field",
            Code::BadSignature => "bad_signature",
            Code::UnknownSigner => "unknown_signer",
            Code::SignerNotAllowed => "signer_not_allowed",
            Code::KeyExpired => "key_expired",
            Code::KeyRevoked => "key_revoked",
            Code::BadKeyEvent => "bad_key_event",
            Code::BadGenesis => "bad_genesis",
            Code::UntrustedRoot => "untrusted_root",
            Code::WrongStream => "wrong_stream",
            Code::BadSeq => "bad_seq",
            Code::BadPrev => "bad_prev",
            Code::DuplicateId => "duplicate_id",
            Code::BadIntent => "bad_intent",
            Code::BadApproval => "bad_approval",
            Code::BadHlc => "bad_hlc",
            Code::BadHead => "bad_head",
            Code::BadBatch => "bad_batch",
            Code::MissingBatch => "missing_batch",
            Code::BadCheckpoint => "bad_checkpoint",
            Code::Truncated => "truncated",
            Code::Fork => "fork",
            Code::BadReceipt => "bad_receipt",
            Code::BadProof => "bad_proof",
            Code::BadTimestamp => "bad_timestamp",
            Code::Unwitnessed => "unwitnessed",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an entry, a HEAD or a canonical-JSON input was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: Code,
    pub detail: String,
}

impl Error {
    pub fn new(code: Code, detail: impl Into<String>) -> Self {
        Error {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Error {}

/// The first broken sequence number of a stream and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Broken {
    pub seq: u64,
    pub error: Error,
}

impl fmt::Display for Broken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "broken at seq {}: {}", self.seq, self.error)
    }
}

impl std::error::Error for Broken {}

pub(crate) fn invalid(detail: impl Into<String>) -> Error {
    Error::new(Code::InvalidField, detail)
}
