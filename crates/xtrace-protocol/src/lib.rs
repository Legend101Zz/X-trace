//! Generated XTP protocol bindings.
//!
//! The Rust types in [`xtp::agent`] are produced by `prost-build`
//! from the `.proto` files under `schema/proto/xtp-agent/v1/`. They
//! live behind a thin façade so the rest of the crate can add manual
//! helpers (envelope encode/decode, version negotiation, translation
//! into domain DTOs) without polluting the generated code.
//!
//! The domain never imports these generated types. Translation modules
//! validate wire input and construct domain values.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, reason = "library code must not panic")
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests assert on fallible fixture data"
    )
)]

pub mod envelope;
pub mod handshake;
pub mod translate;

pub use xtp as generated;

/// Re-export of the generated `xtp` module. `prost-build` emits the
/// whole module under the directory passed to `out_dir`, named after
/// the `.proto` `package` declaration. `xtp-agent` becomes the Rust
/// module path `xtp`.
#[allow(clippy::module_inception, reason = "generated module name mirrors the .proto package")]
pub mod xtp {
    #[allow(
        missing_docs,
        reason = "prost-build emits these symbols without rustdoc; the .proto comments stay authoritative"
    )]
    pub mod agent {
        include!(concat!(env!("OUT_DIR"), "/generated/xtp.agent.v1.rs"));
    }
}
