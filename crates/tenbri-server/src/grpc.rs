//! The gRPC API, `tenbri.v1.TenbriService` (contract/proto), plus `grpc.health.v1`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::{Stream, StreamExt};
use tenbri_core::canon;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Request, Response, Status};

use crate::proto::tenbri_service_server::{TenbriService, TenbriServiceServer};
use crate::proto::{self as pb};
use crate::{
    ApiError, Appended, Daemon, ErrorCode, Op, Query, Stored, Token, Verification, Verified,
};

pub(crate) async fn serve(
    daemon: Arc<Daemon>,
    listener: TcpListener,
    stop: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let (health, health_service) = tonic_health::server::health_reporter();
    let serving = if daemon.ready() {
        tonic_health::ServingStatus::Serving
    } else {
        tonic_health::ServingStatus::NotServing
    };
    health.set_service_status("", serving).await;
    health
        .set_service_status("tenbri.v1.TenbriService", serving)
        .await;
    let stop = async move {
        stop.await;
        for s in ["", "tenbri.v1.TenbriService"] {
            health
                .set_service_status(s, tonic_health::ServingStatus::NotServing)
                .await;
        }
    };
    tonic::transport::Server::builder()
        .add_service(health_service)
        .add_service(TenbriServiceServer::new(Grpc(daemon)))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), stop)
        .await
        .map_err(std::io::Error::other)
}

struct Grpc(Arc<Daemon>);

impl Grpc {
    fn caller(&self, m: &MetadataMap) -> Result<Token, Status> {
        let h = m.get("authorization").and_then(|v| v.to_str().ok());
        self.0.authenticate(h).map_err(status)
    }

    async fn append(
        &self,
        m: &MetadataMap,
        op: Op,
        stream: &str,
        key: &str,
        draft: &str,
    ) -> Result<Option<pb::Appended>, Status> {
        let t = self.caller(m)?;
        let key = (!key.is_empty()).then_some(key);
        let a = self
            .0
            .append(&t, stream, op, key, draft.as_bytes())
            .await
            .map_err(status)?;
        Ok(Some(appended(a)))
    }
}

/// An [`ApiError`] as a gRPC status: the code in `tenbri-error-code`, the REST body in
/// `tenbri-error-bin`.
fn status(e: ApiError) -> Status {
    let mut s = Status::new(e.code.grpc_code(), e.message.clone());
    s.metadata_mut().insert(
        "tenbri-error-code",
        MetadataValue::from_static(e.code.as_str()),
    );
    s.metadata_mut()
        .insert_bin("tenbri-error-bin", MetadataValue::from_bytes(&e.body()));
    s
}

fn appended(a: Appended) -> pb::Appended {
    pb::Appended {
        entry_json: a.stored.line.clone(),
        replayed: a.replayed,
        warnings: a.warnings,
    }
}

fn queried((s, v): (Arc<Stored>, Verification)) -> pb::QueriedEntry {
    pb::QueriedEntry {
        entry_json: s.line.clone(),
        verification: match v {
            Verification::Verified => pb::Verification::Verified,
            Verification::Broken => pb::Verification::Broken,
        } as i32,
    }
}

type TailStream = Pin<Box<dyn Stream<Item = Result<pb::TailEntriesResponse, Status>> + Send>>;

#[tonic::async_trait]
impl TenbriService for Grpc {
    async fn append_intent(
        &self,
        r: Request<pb::AppendIntentRequest>,
    ) -> Result<Response<pb::AppendIntentResponse>, Status> {
        let q = r.get_ref();
        let appended = self
            .append(
                r.metadata(),
                Op::Intent,
                &q.stream,
                &q.idempotency_key,
                &q.draft_json,
            )
            .await?;
        Ok(Response::new(pb::AppendIntentResponse { appended }))
    }

    async fn append_outcome(
        &self,
        r: Request<pb::AppendOutcomeRequest>,
    ) -> Result<Response<pb::AppendOutcomeResponse>, Status> {
        let q = r.get_ref();
        let appended = self
            .append(
                r.metadata(),
                Op::Outcome,
                &q.stream,
                &q.idempotency_key,
                &q.draft_json,
            )
            .await?;
        Ok(Response::new(pb::AppendOutcomeResponse { appended }))
    }

    async fn append_approval(
        &self,
        r: Request<pb::AppendApprovalRequest>,
    ) -> Result<Response<pb::AppendApprovalResponse>, Status> {
        let q = r.get_ref();
        let appended = self
            .append(
                r.metadata(),
                Op::Approval,
                &q.stream,
                &q.idempotency_key,
                &q.draft_json,
            )
            .await?;
        Ok(Response::new(pb::AppendApprovalResponse { appended }))
    }

    async fn append_batch(
        &self,
        r: Request<pb::AppendBatchRequest>,
    ) -> Result<Response<pb::AppendBatchResponse>, Status> {
        let t = self.caller(r.metadata())?;
        let q = r.get_ref();
        let drafts = q
            .drafts_json
            .iter()
            .map(|d| canon::parse(d.as_bytes()).map_err(|e| status(e.into())))
            .collect::<Result<Vec<_>, _>>()?;
        let out = self
            .0
            .append_batch(&t, &q.stream, drafts)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::AppendBatchResponse {
            appended: out.into_iter().map(appended).collect(),
        }))
    }

    async fn get_entry(
        &self,
        r: Request<pb::GetEntryRequest>,
    ) -> Result<Response<pb::GetEntryResponse>, Status> {
        let t = self.caller(r.metadata())?;
        let q = r.get_ref();
        let e = self.0.get(&t, &q.stream, &q.id).map_err(status)?;
        Ok(Response::new(pb::GetEntryResponse {
            entry: Some(queried(e)),
        }))
    }

    async fn get_receipt(
        &self,
        r: Request<pb::GetReceiptRequest>,
    ) -> Result<Response<pb::GetReceiptResponse>, Status> {
        let t = self.caller(r.metadata())?;
        let q = r.get_ref();
        let receipt = self.0.receipt(&t, &q.stream, &q.id).await.map_err(status)?;
        Ok(Response::new(pb::GetReceiptResponse { receipt }))
    }

    async fn query_entries(
        &self,
        r: Request<pb::QueryEntriesRequest>,
    ) -> Result<Response<pb::QueryEntriesResponse>, Status> {
        let t = self.caller(r.metadata())?;
        let q = r.into_inner();
        let some = |s: String| (!s.is_empty()).then_some(s);
        let inputs = q
            .inputs
            .iter()
            .map(|i| {
                i.rsplit_once('@')
                    .map(|(r, v)| (r.to_owned(), v.to_owned()))
                    .ok_or_else(|| {
                        status(ApiError::new(
                            ErrorCode::InvalidRequest,
                            format!("input {i}: expected ref@version"),
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        let query = Query {
            inputs,
            action: some(q.action),
            principal: some(q.principal),
            target: some(q.target),
            subject: some(q.subject),
            after_seq: q.after_seq,
            limit: q.limit as usize,
        };
        let (entries, next) = self.0.query(&t, &q.stream, &query).map_err(status)?;
        Ok(Response::new(pb::QueryEntriesResponse {
            entries: entries.into_iter().map(queried).collect(),
            next_after_seq: next.unwrap_or(0),
        }))
    }

    type TailEntriesStream = TailStream;

    async fn tail_entries(
        &self,
        r: Request<pb::TailEntriesRequest>,
    ) -> Result<Response<TailStream>, Status> {
        let t = self.caller(r.metadata())?;
        let q = r.get_ref();
        let s = self
            .0
            .tail(&t, &q.stream, q.after_seq)
            .map_err(status)?
            .map(|r| {
                r.map(|e| pb::TailEntriesResponse {
                    entry: Some(queried(e)),
                })
                .map_err(status)
            });
        Ok(Response::new(Box::pin(s)))
    }

    async fn verify_stream(
        &self,
        r: Request<pb::VerifyStreamRequest>,
    ) -> Result<Response<pb::VerifyStreamResponse>, Status> {
        let t = self.caller(r.metadata())?;
        let Verified {
            stream,
            entries,
            pinned_key,
            broken,
        } = self
            .0
            .verify(&t, &r.get_ref().stream)
            .await
            .map_err(status)?;
        Ok(Response::new(pb::VerifyStreamResponse {
            stream_id: stream,
            entries,
            pinned_key,
            broken: broken.map(|b| pb::Broken {
                seq: b.seq,
                code: b.error.code.as_str().into(),
                message: b.error.detail,
            }),
        }))
    }

    async fn list_schemas(
        &self,
        r: Request<pb::ListSchemasRequest>,
    ) -> Result<Response<pb::ListSchemasResponse>, Status> {
        self.caller(r.metadata())?;
        Ok(Response::new(pb::ListSchemasResponse {
            schemas_json: self.0.schemas_json().to_string(),
        }))
    }
}
