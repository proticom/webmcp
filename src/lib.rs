//! `webmcp-daemon`: the machine-side half of webmcp.fast.
//!
//! The library exposes the pieces the `webmcp` binary is built from so that
//! integration tests can drive the connect loop against a mock gateway
//! without spawning a process.

pub mod approvals;
pub mod config;
pub mod confirm;
pub mod connect;
pub mod device_auth;
pub mod discover;
pub mod error;
pub mod keys;
pub mod lock;
pub mod output;
pub mod pair;
pub mod passkey;
pub mod platform;
pub mod policy;
pub mod proto;
pub mod relay;
pub mod reload;
pub mod service;
pub mod signing;

pub use error::Error;
