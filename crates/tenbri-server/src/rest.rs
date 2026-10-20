//! The REST API, `/v1`. Its OpenAPI document is generated from these handlers and checked in as
//! contract/openapi.v1.yaml (tests/contract.rs).

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{FromRequestParts, Path, RawQuery, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, on};
use futures_util::{Stream, StreamExt};
use serde::Serialize;
use serde_json::value::RawValue;
use tenbri_core::{Trace, canon};
use tokio::net::TcpListener;
use utoipa::openapi::path::HttpMethod;
use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

use crate::{
    ApiError, Appended, Daemon, ErrorBody, ErrorCode, Op, Query, Stored, Token, Verification,
    Verified,
};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "tenbrid",
        version = "1",
        description = "The Tenbri network API: append decisions to tamper-evident streams, read \
them back with their verification status, verify streams. The same operations are served over \
gRPC (contract/proto/tenbri/v1/tenbri.proto).\n\n\
Every request but /v1/health and /v1/ready carries `Authorization: Bearer <token>`; each token \
is bound to one principal, and entries it writes carry that principal.\n\n\
Every write carries an `Idempotency-Key`: the entry id, a ULID the client generates. The same \
key with the same draft returns the original entry (200, `replayed: true`); the same key with \
another draft fails with TENBRI_IDEMPOTENCY_CONFLICT. Batches carry each entry's `id` instead.\n\n\
Errors have one body, `{\"error\": {\"code\", \"message\", \"reason\"?, \"violations\"?}}`, with \
a stable code: TENBRI_INVALID_REQUEST (400), TENBRI_INVALID_ENTRY (400, `reason` is the format \
v1 code), TENBRI_SCHEMA_VIOLATION (422), TENBRI_UNAUTHENTICATED (401), TENBRI_FORBIDDEN (403), \
TENBRI_NOT_FOUND (404), TENBRI_IDEMPOTENCY_CONFLICT (409), TENBRI_WRITE_CONFLICT (409), \
TENBRI_DEADLINE_EXCEEDED (503, backpressure), TENBRI_STORE_UNAVAILABLE (503), \
TENBRI_NO_SESSION_KEY (503), TENBRI_TAIL_LAGGED (503), TENBRI_STREAM_BROKEN (500), \
TENBRI_INTERNAL (500). A 503 carries Retry-After.",
        license(name = "Apache-2.0", identifier = "Apache-2.0"),
    ),
    modifiers(&BearerToken),
    // Every body a route names: `route` documents operations, not the schemas they refer to.
    components(schemas(
        ErrorBody,
        ErrorCode,
        AppendedBody,
        BatchBody,
        BatchRequest,
        QueriedBody,
        QueryBody,
        VerifyBody,
        StatusBody,
    ))
)]
struct ApiDoc;

struct BearerToken;

impl Modify for BearerToken {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        api.components.get_or_insert_default().add_security_scheme(
            "token",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        );
    }
}

/// The routes and the OpenAPI document they make, both from each handler's `#[utoipa::path]`.
fn api() -> (axum::Router<Arc<Daemon>>, utoipa::openapi::OpenApi) {
    let mut a = (axum::Router::new(), ApiDoc::openapi());
    a = route::<__path_append_intent, _, _>(a, append_intent);
    a = route::<__path_append_outcome, _, _>(a, append_outcome);
    a = route::<__path_append_approval, _, _>(a, append_approval);
    a = route::<__path_append_batch, _, _>(a, append_batch);
    a = route::<__path_query_entries, _, _>(a, query_entries);
    a = route::<__path_get_entry, _, _>(a, get_entry);
    a = route::<__path_tail_entries, _, _>(a, tail_entries);
    a = route::<__path_verify_stream, _, _>(a, verify_stream);
    a = route::<__path_list_schemas, _, _>(a, list_schemas);
    a = route::<__path_health, _, _>(a, health);
    a = route::<__path_ready, _, _>(a, ready);
    a
}

/// Serves `handler` at the path and methods its `#[utoipa::path]` declares, and documents it there.
fn route<P: utoipa::Path, H, T>(
    (router, mut doc): (axum::Router<Arc<Daemon>>, utoipa::openapi::OpenApi),
    handler: H,
) -> (axum::Router<Arc<Daemon>>, utoipa::openapi::OpenApi)
where
    H: axum::handler::Handler<T, Arc<Daemon>>,
    T: 'static,
{
    let methods = P::methods()
        .into_iter()
        .map(|m| match m {
            HttpMethod::Get => MethodFilter::GET,
            HttpMethod::Post => MethodFilter::POST,
            _ => unreachable!("tenbrid serves GET and POST only"),
        })
        .reduce(MethodFilter::or)
        .expect("an operation has a method");
    doc.paths
        .add_path_operation(P::path(), P::methods(), P::operation());
    (router.route(&P::path(), on(methods, handler)), doc)
}

/// The OpenAPI 3.1 document of the REST API, as checked in at contract/openapi.v1.yaml.
pub fn openapi_yaml() -> String {
    api().1.to_yaml().expect("the OpenAPI document serializes")
}

pub(crate) async fn serve(
    daemon: Arc<Daemon>,
    listener: TcpListener,
    stop: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, api().0.with_state(daemon))
        .with_graceful_shutdown(stop)
        .await
}

/// The caller, from `Authorization: Bearer <token>`.
struct Caller(Token);

impl FromRequestParts<Arc<Daemon>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, d: &Arc<Daemon>) -> Result<Self, ApiError> {
        let h = parts.headers.get(header::AUTHORIZATION);
        d.authenticate(h.and_then(|v| v.to_str().ok())).map(Caller)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status()).expect("a valid status");
        let mut r = (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            self.body(),
        )
            .into_response();
        if self.code.retry() {
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        r
    }
}

/// An appended entry.
#[derive(Serialize, ToSchema)]
struct AppendedBody {
    /// The entry as stored (format v1, canonical JSON).
    #[schema(value_type = Object)]
    entry: Box<RawValue>,
    /// The Idempotency-Key was used before; this is the entry it wrote.
    replayed: bool,
    /// Schema warnings, such as an action type tenbri.toml does not declare.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct BatchBody {
    /// In the order of the request's entries.
    entries: Vec<AppendedBody>,
}

/// A batch of drafts.
#[derive(ToSchema)]
#[allow(dead_code)]
struct BatchRequest {
    /// Drafts, each with its `id` (a ULID, the idempotency key) and `kind`.
    #[schema(value_type = Vec<Object>)]
    entries: Vec<()>,
}

/// An entry and whether it verifies against the stream's pinned key.
#[derive(Serialize, ToSchema)]
struct QueriedBody {
    verification: VerificationBody,
    #[schema(value_type = Object)]
    entry: Box<RawValue>,
}

#[derive(Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
enum VerificationBody {
    /// Checked from the pinned genesis key up to this entry.
    Verified,
    /// At or after the first sequence number that no longer verifies.
    Broken,
}

#[derive(Serialize, ToSchema)]
struct QueryBody {
    entries: Vec<QueriedBody>,
    /// When more entries match: pass it as `after_seq` for the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after_seq: Option<u64>,
}

#[derive(Serialize, ToSchema)]
struct VerifyBody {
    /// The stream id (tnb1:...).
    stream: String,
    /// Entries checked before the first break, or all of them.
    entries: u64,
    /// The genesis key fingerprint the stream was checked against.
    pinned_key: String,
    /// Absent when the stream verifies.
    #[serde(skip_serializing_if = "Option::is_none")]
    broken: Option<BrokenBody>,
}

#[derive(Serialize, ToSchema)]
struct BrokenBody {
    seq: u64,
    /// The format v1 error code (bad_signature, ...).
    code: String,
    message: String,
}

#[derive(Serialize, ToSchema)]
struct StatusBody {
    /// ok, ready or not_ready.
    status: String,
}

fn raw(s: &Stored) -> Box<RawValue> {
    RawValue::from_string(s.line.clone()).expect("a stored line is JSON")
}

fn appended(a: Appended) -> AppendedBody {
    AppendedBody {
        entry: raw(&a.stored),
        replayed: a.replayed,
        warnings: a.warnings,
    }
}

fn queried((s, v): (Arc<Stored>, Verification)) -> QueriedBody {
    QueriedBody {
        verification: match v {
            Verification::Verified => VerificationBody::Verified,
            Verification::Broken => VerificationBody::Broken,
        },
        entry: raw(&s),
    }
}

/// The ids of a valid W3C `traceparent` header; an invalid one is ignored, as Trace Context says.
fn trace(headers: &HeaderMap) -> Option<Trace> {
    headers
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .and_then(tenbri_otlp::traceparent::parse)
}

async fn append(
    d: Arc<Daemon>,
    token: Token,
    stream: String,
    op: Op,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AppendedBody>), ApiError> {
    let key = headers
        .get("idempotency-key")
        .map(|v| {
            v.to_str()
                .map_err(|_| ApiError::new(ErrorCode::InvalidRequest, "Idempotency-Key: not text"))
        })
        .transpose()?;
    let a = d
        .append(&token, &stream, op, key, &body, trace(&headers).as_ref())
        .await?;
    let status = if a.replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(appended(a))))
}

/// Append an intent; returns once it is durable, before the action runs.
#[utoipa::path(
    post,
    path = "/v1/streams/{stream}/intents",
    params(
        ("stream" = String, Path, description = "The stream's name in tenbrid's configuration, or its id (tnb1:...)"),
        ("Idempotency-Key" = String, Header, description = "The entry id: a ULID the client generates"),
        ("traceparent" = Option<String>, Header, description = "W3C Trace Context: the entry's `trace` (trace and span id) unless the draft has one"),
    ),
    request_body(content = Object, description = "A draft intent (spec/format-v1.md): action, inputs, rule, subject, approval, trace, links, ext... `kind` and `phase` may be left out; `principal` defaults to the token's; `source` to sdk; `durability` to local."),
    responses(
        (status = 201, description = "Written and durable", body = AppendedBody),
        (status = 200, description = "Replayed: the entry this key wrote before", body = AppendedBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn append_intent(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AppendedBody>), ApiError> {
    append(d, t, stream, Op::Intent, headers, body).await
}

/// Append the outcome of an intent.
#[utoipa::path(
    post,
    path = "/v1/streams/{stream}/outcomes",
    params(
        ("stream" = String, Path, description = "The stream's name or id"),
        ("Idempotency-Key" = String, Header, description = "The entry id: a ULID the client generates"),
        ("traceparent" = Option<String>, Header, description = "W3C Trace Context: the entry's `trace` (trace and span id) unless the draft has one"),
    ),
    request_body(content = Object, description = "A draft outcome: `intent` (the intent's id) and `status` (ok, error, refused, unknown). `principal`, `action`, `subject` and `source` default to the intent's."),
    responses(
        (status = 201, description = "Written and durable", body = AppendedBody),
        (status = 200, description = "Replayed: the entry this key wrote before", body = AppendedBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn append_outcome(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AppendedBody>), ApiError> {
    append(d, t, stream, Op::Outcome, headers, body).await
}

/// Append an approval.
#[utoipa::path(
    post,
    path = "/v1/streams/{stream}/approvals",
    params(
        ("stream" = String, Path, description = "The stream's name or id"),
        ("Idempotency-Key" = String, Header, description = "The entry id: a ULID the client generates"),
        ("traceparent" = Option<String>, Header, description = "W3C Trace Context: the entry's `trace` (trace and span id) unless the draft has one"),
    ),
    request_body(content = Object, description = "A draft approval: `action` approved, by the token's principal."),
    responses(
        (status = 201, description = "Written and durable", body = AppendedBody),
        (status = 200, description = "Replayed: the entry this key wrote before", body = AppendedBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn append_approval(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<AppendedBody>), ApiError> {
    append(d, t, stream, Op::Approval, headers, body).await
}

/// Append several entries in order, up to 1000. All are checked before any is written; if
/// storage fails part-way, the earlier ones stay written and retrying the batch is safe.
#[utoipa::path(
    post,
    path = "/v1/streams/{stream}/entries",
    params(
        ("stream" = String, Path, description = "The stream's name or id"),
        ("traceparent" = Option<String>, Header, description = "W3C Trace Context: the `trace` of every draft without one"),
    ),
    request_body(content = BatchRequest),
    responses(
        (status = 200, description = "Every entry is durable (or was replayed)", body = BatchBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn append_batch(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<BatchBody>, ApiError> {
    let bad = || {
        ApiError::new(
            ErrorCode::InvalidRequest,
            "expected {\"entries\": [draft, ...]}",
        )
    };
    let canon::Value::Obj(mut members) = canon::parse(&body)? else {
        return Err(bad());
    };
    let drafts = match members.pop() {
        Some((k, canon::Value::Arr(a))) if k == "entries" && members.is_empty() => a,
        _ => return Err(bad()),
    };
    let out = d
        .append_batch(&t, &stream, drafts, trace(&headers).as_ref())
        .await?;
    Ok(Json(BatchBody {
        entries: out.into_iter().map(appended).collect(),
    }))
}

/// Entries matching every filter given, in sequence order.
#[utoipa::path(
    get,
    path = "/v1/streams/{stream}/entries",
    params(
        ("stream" = String, Path, description = "The stream's name or id"),
        ("input" = Option<Vec<String>>, Query, description = "An input the entry used, as ref@version (policy:refund@14); repeat to require several"),
        ("action" = Option<String>, Query, description = "The action type (reply_ticket)"),
        ("principal" = Option<String>, Query, description = "kind:id (agent:support-assistant)"),
        ("target" = Option<String>, Query, description = "The action target, exactly"),
        ("subject" = Option<String>, Query, description = "The subject handle"),
        ("after_seq" = Option<u64>, Query, description = "Only entries with a greater sequence number"),
        ("limit" = Option<u32>, Query, description = "At most this many entries: default 100, at most 1000"),
    ),
    responses(
        (status = 200, description = "The matching entries", body = QueryBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn query_entries(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
    RawQuery(q): RawQuery,
) -> Result<Json<QueryBody>, ApiError> {
    let pairs: Vec<(String, String)> = serde_urlencoded::from_str(q.as_deref().unwrap_or(""))
        .map_err(|e| ApiError::new(ErrorCode::InvalidRequest, e.to_string()))?;
    let mut query = Query::default();
    for (k, v) in pairs {
        let bad = |what: &str| ApiError::new(ErrorCode::InvalidRequest, format!("{k}={v}: {what}"));
        match k.as_str() {
            "input" => {
                let (r, ver) = v
                    .rsplit_once('@')
                    .ok_or_else(|| bad("expected ref@version"))?;
                query.inputs.push((r.into(), ver.into()));
            }
            "action" => query.action = Some(v),
            "principal" => query.principal = Some(v),
            "target" => query.target = Some(v),
            "subject" => query.subject = Some(v),
            "after_seq" => query.after_seq = v.parse().map_err(|_| bad("not a number"))?,
            "limit" => query.limit = v.parse().map_err(|_| bad("not a number"))?,
            _ => return Err(bad("unknown parameter")),
        }
    }
    let (entries, next) = d.query(&t, &stream, &query)?;
    Ok(Json(QueryBody {
        entries: entries.into_iter().map(queried).collect(),
        next_after_seq: next,
    }))
}

/// One entry by id.
#[utoipa::path(
    get,
    path = "/v1/streams/{stream}/entries/{id}",
    params(
        ("stream" = String, Path, description = "The stream's name or id"),
        ("id" = String, Path, description = "The entry id"),
    ),
    responses(
        (status = 200, description = "The entry", body = QueriedBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn get_entry(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path((stream, id)): Path<(String, String)>,
) -> Result<Json<QueriedBody>, ApiError> {
    Ok(Json(queried(d.get(&t, &stream, &id)?)))
}

/// Server-sent events: the entries after `after_seq` (or the Last-Event-ID header), then new ones
/// as they are written. Each `entry` event's id is the entry's sequence number and its data a
/// QueriedBody; an `error` event carrying an ErrorBody ends the stream.
#[utoipa::path(
    get,
    path = "/v1/streams/{stream}/tail",
    params(
        ("stream" = String, Path, description = "The stream's name or id"),
        ("after_seq" = Option<u64>, Query, description = "Start after this sequence number; default 0"),
        ("Last-Event-ID" = Option<u64>, Header, description = "Resume after this sequence number, when after_seq is absent"),
    ),
    responses(
        (status = 200, description = "An event stream of `entry` events", content_type = "text/event-stream", body = QueriedBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn tail_entries(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
    RawQuery(q): RawQuery,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let bad = |m: &str| ApiError::new(ErrorCode::InvalidRequest, m.to_owned());
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(q.as_deref().unwrap_or("")).map_err(|e| bad(&e.to_string()))?;
    let mut after = match headers.get("last-event-id") {
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| bad("Last-Event-ID: not a sequence number"))?,
        None => 0,
    };
    for (k, v) in pairs {
        match k.as_str() {
            "after_seq" => after = v.parse().map_err(|_| bad("after_seq: not a number"))?,
            _ => return Err(bad(&format!("{k}: unknown parameter"))),
        }
    }
    let events = d.tail(&t, &stream, after)?.map(|r| {
        Ok(match r {
            Ok((s, v)) => {
                let seq = s.entry.seq;
                let data = serde_json::to_string(&queried((s, v))).expect("serializes");
                Event::default()
                    .event("entry")
                    .id(seq.to_string())
                    .data(data)
            }
            Err(e) => Event::default()
                .event("error")
                .data(String::from_utf8(e.body()).expect("JSON is UTF-8")),
        })
    });
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}

/// Read the whole stream from storage and check it against its pinned key: canonical bytes,
/// chain, signatures, keys, intents, HEAD.
#[utoipa::path(
    get,
    path = "/v1/streams/{stream}/verify",
    params(("stream" = String, Path, description = "The stream's name or id")),
    responses(
        (status = 200, description = "The report; `broken` is absent when the stream verifies", body = VerifyBody),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn verify_stream(
    State(d): State<Arc<Daemon>>,
    Caller(t): Caller,
    Path(stream): Path<String>,
) -> Result<Json<VerifyBody>, ApiError> {
    let Verified {
        stream,
        entries,
        pinned_key,
        broken,
    } = d.verify(&t, &stream).await?;
    Ok(Json(VerifyBody {
        stream,
        entries,
        pinned_key,
        broken: broken.map(|b| BrokenBody {
            seq: b.seq,
            code: b.error.code.as_str().into(),
            message: b.error.detail,
        }),
    }))
}

/// The action schemas declared in tenbri.toml.
#[utoipa::path(
    get,
    path = "/v1/schemas",
    responses(
        (status = 200, description = "tenbri.toml as JSON: {unknown_actions, actions: {type: schema}}", body = Object),
        (status = "default", description = "An error", body = ErrorBody),
    ),
    security(("token" = [])),
)]
async fn list_schemas(State(d): State<Arc<Daemon>>, Caller(_): Caller) -> Json<serde_json::Value> {
    Json(d.schemas_json())
}

/// Liveness: the process answers.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses((status = 200, description = "Alive", body = StatusBody)),
)]
async fn health() -> Json<StatusBody> {
    Json(StatusBody {
        status: "ok".into(),
    })
}

/// Readiness: not shutting down, and every stream verifies and has a session key.
#[utoipa::path(
    get,
    path = "/v1/ready",
    responses(
        (status = 200, description = "Ready for writes", body = StatusBody),
        (status = 503, description = "Not ready", body = StatusBody),
    ),
)]
async fn ready(State(d): State<Arc<Daemon>>) -> (StatusCode, Json<StatusBody>) {
    let (code, status) = if d.ready() {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not_ready")
    };
    (
        code,
        Json(StatusBody {
            status: status.into(),
        }),
    )
}
