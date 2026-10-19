//! RFC 6962 Merkle tree, inclusion and consistency proofs, C2SP checkpoints for Tenbri.
//!
//! The reference implementation of [checkpoints](https://github.com/tenbri/tenbri/blob/main/spec/checkpoints.md),
//! provisional with format v1. No I/O, so it builds for `wasm32-unknown-unknown` like
//! `tenbri-core`.
//!
//! - [`tree`]: the Merkle tree hash over entry hashes, inclusion and consistency proofs.
//! - [`checkpoint`]: signing, parsing and checking checkpoints, and when the writer makes them.

pub mod checkpoint;
pub mod tree;

pub use checkpoint::{Checkpoint, Note};
pub use tree::Hash;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
