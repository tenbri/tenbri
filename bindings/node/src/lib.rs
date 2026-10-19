//! The `tenbri` Node.js package. Placeholder: it only reports its version.

use napi_derive::napi;

/// The package's version.
#[napi]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_a_version() {
        assert!(!super::version().is_empty());
    }
}
