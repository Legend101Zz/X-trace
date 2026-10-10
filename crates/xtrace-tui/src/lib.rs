//! Terminal viewer library (lane X).
//!
//! Elm-style core with no terminal dependency: `update` is a pure function from `(Model, Message)`
//! to `(Model, Vec<Effect>)`; `view` renders a `Model` to a fixed-size character grid. Effects are
//! executed by the caller against a [`ReplayClient`]; nothing here performs I/O. The grid can be
//! written as plain text (no escape sequences) or as ANSI, so snapshot tests and `--plain` share
//! one renderer. The interactive driver (raw mode, key events) is a separate layer.
//!
//! Honesty rules mirror the web viewer: absence is shown as "not observed" or with a specific
//! reason, navigation that the server did not resolve is disabled with its reason, and nothing
//! is inferred client-side.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod client;
pub mod driver;
pub mod model;
pub mod update;
pub mod view;

pub use client::{ClientError, ReplayClient};
pub use model::{
    Effect, FrameRow, Key, Message, Model, NavAction, NavResult, RecordingRow, Screen, Status,
    Window,
};
pub use update::update;
pub use view::{Grid, render};
