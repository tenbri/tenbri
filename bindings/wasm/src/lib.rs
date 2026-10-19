//! The Tenbri verifier for browsers. Placeholder: it only reports its version.

use wasm_bindgen::prelude::*;

/// The package's version.
#[wasm_bindgen]
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
