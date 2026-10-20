//! Group commit: many tasks share one writer through a bounded queue.

use std::collections::HashSet;
use std::time::Duration;

use tenbri_core::{Entry, Status};
use tenbri_store::Store;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout, timeout_at};

use crate::{Hook, RECONCILE_AFTER_MS, WriteError, Writer, as_intent, outcome_of};

/// How long the lane waits for an append before it calls [`Writer::tick`].
const TICK: Duration = Duration::from_secs(1);

/// Group commit and backpressure for a [`Lane`]. The defaults are the PRD's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneConfig {
    /// A batch is sealed when it holds this many entries (256)…
    pub max_batch: usize,
    /// …or this long after its first entry was taken from the queue (2 ms).
    pub linger: Duration,
    /// How many appends may wait for a batch (10,000).
    pub queue: usize,
    /// How long an append waits for room in a full queue before failing closed with
    /// [`WriteError::Backpressure`] (2 s).
    pub deadline: Duration,
    /// Intents open longer than this are closed with a `reconcile` entry (status `unknown`) in
    /// the next batch, unless it holds their outcome (1 hour); `None`: never.
    pub reconcile_after: Option<Duration>,
}

impl Default for LaneConfig {
    fn default() -> Self {
        LaneConfig {
            max_batch: 256,
            linger: Duration::from_millis(2),
            queue: 10_000,
            deadline: Duration::from_secs(2),
            reconcile_after: Some(Duration::from_millis(RECONCILE_AFTER_MS as u64)),
        }
    }
}

struct Job {
    entries: Vec<Entry>,
    /// Call [`Writer::seal`] once the batch is written.
    seal: bool,
    done: oneshot::Sender<Vec<Result<Entry, WriteError>>>,
}

/// One writer shared by many tasks: appends are queued in order, sealed into batches (one put and
/// one HEAD swap each), and each caller's future resolves when its batch is durable. Clone it to
/// share it; the writer stops when the last clone is dropped. When idle, the lane calls
/// [`Writer::tick`] every second, so a hook can act on time alone.
///
/// An append whose caller stops waiting is still written once queued.
#[derive(Clone, Debug)]
pub struct Lane {
    tx: mpsc::Sender<Job>,
    deadline: Duration,
}

impl Lane {
    /// Moves `writer`, with its session key set, to a task on the current Tokio runtime.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime, or if `config.queue` or `config.max_batch` is 0.
    pub fn spawn<S, H>(writer: Writer<S, H>, config: LaneConfig) -> Lane
    where
        S: Store + 'static,
        H: Hook<S> + 'static,
    {
        assert!(config.max_batch > 0, "max_batch must be at least 1");
        let (tx, rx) = mpsc::channel(config.queue);
        tokio::spawn(run(writer, rx, config));
        Lane {
            tx,
            deadline: config.deadline,
        }
    }

    /// Appends `e`, signed by the writer's session key; returns it as stored, once durable.
    pub async fn append(&self, e: Entry) -> Result<Entry, WriteError> {
        self.append_batch(vec![e])
            .await
            .pop()
            .expect("one result per entry")
    }

    /// Appends `entries` together, in order, in one queue slot; returns each entry as stored, or
    /// why it was not (see [`Writer::append_batch`]).
    pub async fn append_batch(
        &self,
        #[allow(unused_mut)] mut entries: Vec<Entry>,
    ) -> Vec<Result<Entry, WriteError>> {
        #[cfg(feature = "otel")]
        let span = {
            crate::traced(&mut entries);
            tenbri_otlp::Append::start(entries.len())
        };
        let out = self.send(entries).await;
        #[cfg(feature = "otel")]
        span.end(&out);
        out
    }

    async fn send(&self, entries: Vec<Entry>) -> Vec<Result<Entry, WriteError>> {
        let n = entries.len();
        let fail = |e: WriteError| (0..n).map(|_| Err(e.again())).collect();
        let (done, rx) = oneshot::channel();
        if let Err(e) = self
            .tx
            .send_timeout(
                Job {
                    entries,
                    seal: false,
                    done,
                },
                self.deadline,
            )
            .await
        {
            return fail(match e {
                mpsc::error::SendTimeoutError::Timeout(_) => WriteError::Backpressure,
                mpsc::error::SendTimeoutError::Closed(_) => WriteError::Closed,
            });
        }
        rx.await.unwrap_or_else(|_| fail(WriteError::Closed))
    }

    /// Waits until everything queued before it is written (or failed).
    pub async fn flush(&self) {
        self.barrier(false).await;
    }

    /// Waits until everything queued before it is written, then lets the hook act at once
    /// ([`Writer::seal`]): with [`crate::Checkpoints`], a checkpoint covering all of it.
    pub async fn seal(&self) {
        self.barrier(true).await;
    }

    async fn barrier(&self, seal: bool) {
        let (done, rx) = oneshot::channel();
        let job = Job {
            entries: vec![],
            seal,
            done,
        };
        if self.tx.send(job).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Records an intent: durable before the action runs.
    pub async fn intent(&self, e: Entry) -> Result<Entry, WriteError> {
        self.append(as_intent(e)).await
    }

    /// Records the outcome of `intent`, with its principal, action, source and subject.
    pub async fn outcome(&self, intent: &Entry, status: Status) -> Result<Entry, WriteError> {
        self.append(outcome_of(intent, status)).await
    }
}

async fn run<S: Store, H: Hook<S>>(
    mut w: Writer<S, H>,
    mut rx: mpsc::Receiver<Job>,
    config: LaneConfig,
) {
    loop {
        let job = match timeout(TICK, rx.recv()).await {
            Ok(Some(job)) => job,
            Ok(None) => return,
            Err(_) => {
                w.tick().await;
                continue;
            }
        };
        let mut n = job.entries.len();
        let mut jobs = vec![job];
        let until = Instant::now() + config.linger;
        while n < config.max_batch {
            match timeout_at(until, rx.recv()).await {
                Ok(Some(job)) => {
                    n += job.entries.len();
                    jobs.push(job);
                }
                _ => break,
            }
        }
        let seal = jobs.iter().any(|j| j.seal);
        let (batches, done): (Vec<_>, Vec<_>) =
            jobs.into_iter().map(|j| (j.entries, j.done)).unzip();
        let counts: Vec<usize> = batches.iter().map(Vec::len).collect();
        let mut entries: Vec<Entry> = batches.into_iter().flatten().collect();
        // Stale intents are closed in the same batch, before the entries.
        let stale = match config.reconcile_after {
            Some(after) if !entries.is_empty() => {
                let keep: HashSet<&str> =
                    entries.iter().filter_map(|e| e.intent.as_deref()).collect();
                w.stale_intents(w.clock.now_ms(), after.as_millis() as i64, |id| {
                    keep.contains(id)
                })
            }
            _ => vec![],
        };
        let skip = stale.len();
        if skip > 0 {
            entries.splice(0..0, stale);
        }
        let mut results = if entries.is_empty() {
            vec![]
        } else {
            w.append_entries(entries).await
        }
        .into_iter()
        .skip(skip);
        if seal {
            w.seal().await;
        }
        for (d, n) in done.into_iter().zip(counts) {
            let _ = d.send(results.by_ref().take(n).collect());
        }
    }
}
