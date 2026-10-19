//! RFC 6962 Merkle tree, inclusion and consistency proofs, C2SP checkpoints for Tenbri.
//!
//! Placeholder: the crate name is reserved and builds; the code lands later.

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn has_a_version() {
        assert!(!super::VERSION.is_empty());
    }
}
