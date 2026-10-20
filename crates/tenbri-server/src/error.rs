//! The one catalogue of error codes, shared by REST and gRPC.

use std::fmt;

use serde::Serialize;
use utoipa::ToSchema;

/// A stable error code. REST returns it in the body with the HTTP status below; gRPC returns the
/// gRPC status below with the code in the `tenbri-error-code` metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub enum ErrorCode {
    /// The request is malformed: not JSON, a missing or malformed Idempotency-Key, an unknown
    /// query parameter. 400, INVALID_ARGUMENT.
    #[serde(rename = "TENBRI_INVALID_REQUEST")]
    InvalidRequest,
    /// The entry breaks a rule of format v1; `reason` holds the format's code (`unknown_field`,
    /// `bad_intent`...). Nothing was written. 400, INVALID_ARGUMENT.
    #[serde(rename = "TENBRI_INVALID_ENTRY")]
    InvalidEntry,
    /// The entry breaks its action's schema in tenbri.toml; `violations` lists how. Nothing was
    /// written. 422, INVALID_ARGUMENT.
    #[serde(rename = "TENBRI_SCHEMA_VIOLATION")]
    SchemaViolation,
    /// No bearer token, or one tenbrid does not know. 401, UNAUTHENTICATED.
    #[serde(rename = "TENBRI_UNAUTHENTICATED")]
    Unauthenticated,
    /// The token may not use this stream, or the entry names another principal than the token's.
    /// 403, PERMISSION_DENIED.
    #[serde(rename = "TENBRI_FORBIDDEN")]
    Forbidden,
    /// No such stream or entry. 404, NOT_FOUND.
    #[serde(rename = "TENBRI_NOT_FOUND")]
    NotFound,
    /// The Idempotency-Key (the entry id) was used for a different entry. 409, ALREADY_EXISTS.
    #[serde(rename = "TENBRI_IDEMPOTENCY_CONFLICT")]
    IdempotencyConflict,
    /// Another writer holds the stream; nothing was written. 409, ABORTED.
    #[serde(rename = "TENBRI_WRITE_CONFLICT")]
    WriteConflict,
    /// The stream's queue stayed full, or its writer busy, past the deadline: backpressure. Retry
    /// after the Retry-After header. 503, RESOURCE_EXHAUSTED.
    #[serde(rename = "TENBRI_DEADLINE_EXCEEDED")]
    DeadlineExceeded,
    /// Storage failed; the entry may not be durable. Retrying with the same key is safe. 503,
    /// UNAVAILABLE.
    #[serde(rename = "TENBRI_STORE_UNAVAILABLE")]
    StoreUnavailable,
    /// tenbrid has no usable session key for the stream and no stream key to certify one. 503,
    /// UNAVAILABLE.
    #[serde(rename = "TENBRI_NO_SESSION_KEY")]
    NoSessionKey,
    /// The stream does not verify; tenbrid stopped writing to it. 500, DATA_LOSS.
    #[serde(rename = "TENBRI_STREAM_BROKEN")]
    StreamBroken,
    /// A tail fell too far behind the writer; reconnect with `after_seq`. 503, RESOURCE_EXHAUSTED.
    #[serde(rename = "TENBRI_TAIL_LAGGED")]
    TailLagged,
    /// A bug. 500, INTERNAL.
    #[serde(rename = "TENBRI_INTERNAL")]
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidRequest => "TENBRI_INVALID_REQUEST",
            ErrorCode::InvalidEntry => "TENBRI_INVALID_ENTRY",
            ErrorCode::SchemaViolation => "TENBRI_SCHEMA_VIOLATION",
            ErrorCode::Unauthenticated => "TENBRI_UNAUTHENTICATED",
            ErrorCode::Forbidden => "TENBRI_FORBIDDEN",
            ErrorCode::NotFound => "TENBRI_NOT_FOUND",
            ErrorCode::IdempotencyConflict => "TENBRI_IDEMPOTENCY_CONFLICT",
            ErrorCode::WriteConflict => "TENBRI_WRITE_CONFLICT",
            ErrorCode::DeadlineExceeded => "TENBRI_DEADLINE_EXCEEDED",
            ErrorCode::StoreUnavailable => "TENBRI_STORE_UNAVAILABLE",
            ErrorCode::NoSessionKey => "TENBRI_NO_SESSION_KEY",
            ErrorCode::StreamBroken => "TENBRI_STREAM_BROKEN",
            ErrorCode::TailLagged => "TENBRI_TAIL_LAGGED",
            ErrorCode::Internal => "TENBRI_INTERNAL",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::InvalidRequest | ErrorCode::InvalidEntry => 400,
            ErrorCode::Unauthenticated => 401,
            ErrorCode::Forbidden => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::IdempotencyConflict | ErrorCode::WriteConflict => 409,
            ErrorCode::SchemaViolation => 422,
            ErrorCode::StreamBroken | ErrorCode::Internal => 500,
            ErrorCode::DeadlineExceeded
            | ErrorCode::StoreUnavailable
            | ErrorCode::NoSessionKey
            | ErrorCode::TailLagged => 503,
        }
    }

    pub fn grpc_code(self) -> tonic::Code {
        use tonic::Code as G;
        match self {
            ErrorCode::InvalidRequest | ErrorCode::InvalidEntry | ErrorCode::SchemaViolation => {
                G::InvalidArgument
            }
            ErrorCode::Unauthenticated => G::Unauthenticated,
            ErrorCode::Forbidden => G::PermissionDenied,
            ErrorCode::NotFound => G::NotFound,
            ErrorCode::IdempotencyConflict => G::AlreadyExists,
            ErrorCode::WriteConflict => G::Aborted,
            ErrorCode::DeadlineExceeded | ErrorCode::TailLagged => G::ResourceExhausted,
            ErrorCode::StoreUnavailable | ErrorCode::NoSessionKey => G::Unavailable,
            ErrorCode::StreamBroken => G::DataLoss,
            ErrorCode::Internal => G::Internal,
        }
    }

    /// Whether the client should retry later (REST adds Retry-After).
    pub fn retry(self) -> bool {
        self.http_status() == 503
    }
}

/// A failed request: the body of every REST error and of gRPC's `tenbri-error-bin`.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: ApiError,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    /// The format v1 error code, for TENBRI_INVALID_ENTRY and TENBRI_STREAM_BROKEN.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For TENBRI_SCHEMA_VIOLATION.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<Violation>,
}

/// A schema requirement the entry does not meet.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct Violation {
    /// The member, as a dotted path (`action.type`, `rule.result`).
    pub path: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError {
            code,
            message: message.into(),
            reason: None,
            violations: vec![],
        }
    }

    pub fn body(&self) -> Vec<u8> {
        serde_json::to_vec(&ErrorBody {
            error: self.clone(),
        })
        .expect("an error serializes")
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl From<tenbri_core::Error> for ApiError {
    fn from(e: tenbri_core::Error) -> Self {
        ApiError {
            reason: Some(e.code.as_str().into()),
            ..ApiError::new(ErrorCode::InvalidEntry, e.to_string())
        }
    }
}

impl From<tenbri_writer::WriteError> for ApiError {
    fn from(e: tenbri_writer::WriteError) -> Self {
        use tenbri_writer::WriteError as W;
        let msg = e.to_string();
        match e {
            W::Rejected(e) => e.into(),
            W::Broken(b) => ApiError {
                reason: Some(b.error.code.as_str().into()),
                ..ApiError::new(ErrorCode::StreamBroken, msg)
            },
            W::Conflict { .. } => ApiError::new(ErrorCode::WriteConflict, msg),
            W::NoSession(_) => ApiError::new(ErrorCode::NoSessionKey, msg),
            W::Io(_) | W::NoStream | W::Closed => ApiError::new(ErrorCode::StoreUnavailable, msg),
            W::Backpressure => ApiError::new(ErrorCode::DeadlineExceeded, msg),
            W::Exists => ApiError::new(ErrorCode::Internal, msg),
        }
    }
}

impl From<tenbri_writer::ReadError> for ApiError {
    fn from(e: tenbri_writer::ReadError) -> Self {
        tenbri_writer::WriteError::from(e).into()
    }
}

impl From<std::io::Error> for ApiError {
    fn from(e: std::io::Error) -> Self {
        ApiError::new(ErrorCode::StoreUnavailable, e.to_string())
    }
}
