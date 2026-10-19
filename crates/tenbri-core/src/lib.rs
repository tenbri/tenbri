//! Tenbri entry types, canonical JSON, hashing, signing and validation. No I/O.
//!
//! This crate is the reference implementation of [format v1](https://github.com/tenbri/tenbri/blob/main/spec/format-v1.md),
//! which is provisional until its external review. It reads no files, clocks or randomness, so it
//! builds unchanged for native targets, Python, Node and `wasm32-unknown-unknown`.
//!
//! - [`canon`]: RFC 8785 canonical bytes and the byte-for-byte rule.
//! - [`Entry`], [`parse_line`]: the entry and the rules one entry follows on its own.
//! - [`sign`]: entry hashes, fingerprints, stream ids and domain-separated Ed25519.
//! - [`Chain`]: a stream checked entry by entry: chain, keys, intents, HEAD.

pub mod canon;
mod chain;
pub mod encoding;
mod entry;
mod error;
mod head;
pub mod sign;

pub use chain::{Chain, Checked, KeyInfo, OpenIntent};
pub use entry::*;
pub use error::{Broken, Code, Error};
pub use head::Head;

/// This crate's version, the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
