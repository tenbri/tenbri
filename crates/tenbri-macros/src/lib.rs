//! The `#[tenbri::decision]` attribute macro.
//!
//! Placeholder: the attribute is accepted and leaves the function unchanged; recording lands later.

use proc_macro::TokenStream;

/// Marks a function as an agent decision. For now it changes nothing.
#[proc_macro_attribute]
pub fn decision(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

#[cfg(test)]
mod tests {
    #[test]
    fn has_a_version() {
        assert!(!env!("CARGO_PKG_VERSION").is_empty());
    }
}
