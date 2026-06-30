//! Core Proton account/session/crypto primitives for the Rust Proton SDK.
//!
//! Pure-Rust reimplementation of the foundational `Proton.Sdk` layer of the
//! official [Proton Drive SDK](https://github.com/ProtonDriveApps/sdk). This
//! crate has no dependency on the native NativeAOT core; it talks to the Proton
//! API directly.
//!
//! Scope (matching the official SDK): Drive business-logic foundations only.
//! Login/SRP is provided behind [`session::ProtonApiSession::begin`] but read
//! workflows can be driven entirely through
//! [`session::ProtonApiSession::resume`] with pre-obtained tokens.
#![forbid(unsafe_code)]

pub mod account;
pub mod api;
pub mod cache;
pub mod config;
pub mod crypto;
pub mod error;
pub mod http;
pub mod ids;
pub mod session;
pub mod telemetry;

pub use error::{ProtonApiError, ProtonError, Result};
pub use session::ProtonApiSession;

