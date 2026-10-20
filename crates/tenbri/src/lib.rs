//! The open-source Agent Decision Record, a tamper-evident audit trail for AI agents: the facade
//! crate that re-exports the Tenbri API.
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
