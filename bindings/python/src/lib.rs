//! `tenbri._native`, the Rust core under the `tenbri` Python package (python/tenbri). Drafts and
//! entries cross as JSON strings; the Python side turns them into dicts and its errors into the
//! typed exceptions of `tenbri.errors`.
//!
//! Every call has a blocking form, which releases the GIL while it waits, and an `_async` form,
//! which returns an asyncio future resolved from the Tokio runtime: the event loop never blocks,
//! and thousands of appends can wait on one lane's group commit at once.

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use tenbri_bindings::{Error, Options};
use tokio::runtime::Runtime;

/// The Tokio runtime, started on first use and again in a forked child: a runtime does not
/// survive `fork`, so it is never started before one.
fn runtime() -> PyResult<&'static Runtime> {
    static RT: Mutex<Option<(u32, &'static Runtime)>> = Mutex::new(None);
    let mut rt = RT.lock().expect("runtime lock");
    let pid = std::process::id();
    match *rt {
        Some((p, r)) if p == pid => Ok(r),
        _ => {
            let r = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("tenbri")
                .build()
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            // The parent's runtime, if any, is left behind: its threads are not in this process.
            let r: &'static Runtime = Box::leak(Box::new(r));
            *rt = Some((pid, r));
            Ok(r)
        }
    }
}

/// `e` as the exception `tenbri.errors` has for its code.
fn raise(py: Python<'_>, e: Error) -> PyErr {
    let make = || -> PyResult<PyErr> {
        let exc = py.import("tenbri.errors")?.getattr("_from_code")?.call1((
            e.code,
            &e.message,
            e.reason.as_deref(),
            e.id.as_deref(),
        ))?;
        Ok(PyErr::from_value(exc))
    };
    make().unwrap_or_else(|err| err)
}

/// Runs `f` to completion with the GIL released.
fn block<T: Send>(py: Python<'_>, f: impl Future<Output = Result<T, Error>> + Send) -> PyResult<T> {
    let rt = runtime()?;
    py.detach(|| rt.block_on(f)).map_err(|e| raise(py, e))
}

/// Spawns `f` and returns an asyncio future of the running loop that it resolves.
fn spawn<'py, T, F>(py: Python<'py>, f: F) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = Result<T, Error>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    let event_loop = py.import("asyncio")?.call_method0("get_running_loop")?;
    let fut = event_loop.call_method0("create_future")?;
    let (lp, out) = (event_loop.unbind(), fut.clone().unbind());
    runtime()?.spawn(async move {
        let r = f.await;
        Python::attach(|py| {
            let value = r.map_err(|e| raise(py, e)).and_then(|v| v.into_py_any(py));
            let (ok, value) = match value {
                Ok(v) => (true, v),
                Err(e) => (false, e.into_value(py).into_any()),
            };
            // The loop may be closed by now: nobody is waiting.
            let _ = py
                .import("tenbri._native")
                .and_then(|m| m.getattr("_resolve"))
                .and_then(|f| {
                    lp.bind(py)
                        .call_method1("call_soon_threadsafe", (f, out, ok, value))
                });
        });
    });
    Ok(fut)
}

/// Resolves `fut` with `value`, unless it was cancelled; runs on the event loop.
#[pyfunction]
fn _resolve(fut: &Bound<'_, PyAny>, ok: bool, value: &Bound<'_, PyAny>) -> PyResult<()> {
    if fut.call_method0("done")?.is_truthy()? {
        return Ok(());
    }
    fut.call_method1(if ok { "set_result" } else { "set_exception" }, (value,))?;
    Ok(())
}

/// A new entry id (ULID), for idempotent retries.
#[pyfunction]
fn new_id(py: Python<'_>) -> PyResult<String> {
    tenbri_bindings::new_id().map_err(|e| raise(py, e))
}

/// The action schemas of the `tenbri.toml` at `path`, as JSON.
#[pyfunction]
fn schemas(py: Python<'_>, path: PathBuf) -> PyResult<String> {
    tenbri_bindings::schemas(&path).map_err(|e| raise(py, e))
}

fn options(keys: Option<PathBuf>, key: Option<String>, create: bool) -> Options {
    Options {
        keys,
        key,
        create,
        ..Options::default()
    }
}

/// One open stream; see tenbri_bindings::Stream.
#[pyclass(frozen, module = "tenbri._native")]
struct Stream(Arc<tenbri_bindings::Stream>);

#[pymethods]
impl Stream {
    #[staticmethod]
    #[pyo3(signature = (location, keys=None, key=None, create=false))]
    fn open(
        py: Python<'_>,
        location: String,
        keys: Option<PathBuf>,
        key: Option<String>,
        create: bool,
    ) -> PyResult<Stream> {
        let s = block(
            py,
            tenbri_bindings::Stream::open(&location, options(keys, key, create)),
        )?;
        Ok(Stream(Arc::new(s)))
    }

    #[staticmethod]
    #[pyo3(signature = (location, keys=None, key=None, create=false))]
    fn open_async(
        py: Python<'_>,
        location: String,
        keys: Option<PathBuf>,
        key: Option<String>,
        create: bool,
    ) -> PyResult<Bound<'_, PyAny>> {
        spawn(py, async move {
            let s = tenbri_bindings::Stream::open(&location, options(keys, key, create)).await?;
            Ok(Stream(Arc::new(s)))
        })
    }

    #[getter]
    fn id(&self) -> &str {
        self.0.id()
    }

    #[getter]
    fn fingerprint(&self) -> Option<&str> {
        self.0.fingerprint()
    }

    #[getter]
    fn writable(&self) -> bool {
        self.0.writable()
    }

    #[pyo3(signature = (subject, content))]
    fn digest(&self, py: Python<'_>, subject: Option<&str>, content: &[u8]) -> PyResult<String> {
        self.0.digest(subject, content).map_err(|e| raise(py, e))
    }

    fn append(&self, py: Python<'_>, draft: String) -> PyResult<String> {
        block(py, self.0.append(draft.as_bytes()))
    }

    fn append_async<'py>(&self, py: Python<'py>, draft: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move { s.append(draft.as_bytes()).await })
    }

    fn intent(&self, py: Python<'_>, draft: String) -> PyResult<String> {
        block(py, self.0.intent(draft.as_bytes()))
    }

    fn intent_async<'py>(&self, py: Python<'py>, draft: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move { s.intent(draft.as_bytes()).await })
    }

    fn outcome(
        &self,
        py: Python<'_>,
        intent: String,
        status: String,
        draft: String,
    ) -> PyResult<String> {
        block(
            py,
            self.0.outcome(intent.as_bytes(), &status, draft.as_bytes()),
        )
    }

    fn outcome_async<'py>(
        &self,
        py: Python<'py>,
        intent: String,
        status: String,
        draft: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move {
            s.outcome(intent.as_bytes(), &status, draft.as_bytes())
                .await
        })
    }

    #[pyo3(signature = (key=None))]
    fn verify(&self, py: Python<'_>, key: Option<String>) -> PyResult<String> {
        block(py, self.0.verify(key.as_deref()))
    }

    #[pyo3(signature = (key=None))]
    fn verify_async<'py>(
        &self,
        py: Python<'py>,
        key: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move { s.verify(key.as_deref()).await })
    }

    fn query(&self, py: Python<'_>, filter: String) -> PyResult<String> {
        block(py, self.0.query(filter.as_bytes()))
    }

    fn query_async<'py>(&self, py: Python<'py>, filter: String) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move { s.query(filter.as_bytes()).await })
    }

    fn flush(&self, py: Python<'_>) -> PyResult<()> {
        block(py, async {
            self.0.flush().await;
            Ok(())
        })
    }

    fn flush_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move {
            s.flush().await;
            Ok(())
        })
    }

    fn close(&self, py: Python<'_>) -> PyResult<()> {
        block(py, async {
            self.0.close().await;
            Ok(())
        })
    }

    fn close_async<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let s = self.0.clone();
        spawn(py, async move {
            s.close().await;
            Ok(())
        })
    }
}

#[pymodule]
#[pyo3(name = "_native")]
fn tenbri_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_class::<Stream>()?;
    m.add_function(wrap_pyfunction!(new_id, m)?)?;
    m.add_function(wrap_pyfunction!(schemas, m)?)?;
    m.add_function(wrap_pyfunction!(_resolve, m)?)?;
    Ok(())
}
