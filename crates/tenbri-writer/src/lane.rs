//! Group commit: many tasks share one writer through a bounded queue.

use std::time::Duration;

use tenbri_core::{Entry, Status};
use tenbri_store::Store;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout_at};

use crate::{Hook, WriteError, Writer, as_intent, outcome_of};

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
}

impl Default for LaneConfig {
    fn default() -> Self {
        LaneConfig {
            max_batch: 256,
            linger: Duration::from_millis(2),
            queue: 10_000,
            deadline: Duration::from_secs(2),
        }
    }
}

struct Job {
    entry: Entry,
    done: oneshot::Sender<Result<Entry, WriteError>>,
}

/// One writer shared by many tasks: appends are queued in order, sealed into batches (one put and
/// one HEAD swap each), and each caller's future resolves when its batch is durable. Clone it to
/// share it; the writer stops when the last clone is dropped.
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
        let (done, rx) = oneshot::channel();
        self.tx
            .send_timeout(Job { entry: e, done }, self.deadline)
            .await
            .map_err(|e| match e {
                mpsc::error::SendTimeoutError::Timeout(_) => WriteError::Backpressure,
                mpsc::error::SendTimeoutError::Closed(_) => WriteError::Closed,
            })?;
        rx.await.map_err(|_| WriteError::Closed)?
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
    while let Some(job) = rx.recv().await {
        let mut jobs = vec![job];
        let until = Instant::now() + config.linger;
        while jobs.len() < config.max_batch {
            match timeout_at(until, rx.recv()).await {
                Ok(Some(job)) => jobs.push(job),
                _ => break,
            }
        }
        let (entries, done): (Vec<_>, Vec<_>) = jobs.into_iter().map(|j| (j.entry, j.done)).unzip();
        for (r, d) in w.append_batch(entries).await.into_iter().zip(done) {
            let _ = d.send(r);
        }
    }
}
