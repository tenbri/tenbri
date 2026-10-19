//! The `tenbri` Python module. Placeholder: it only carries the version.

use pyo3::prelude::*;

#[pymodule]
#[pyo3(name = "tenbri")]
fn tenbri_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_a_version() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
