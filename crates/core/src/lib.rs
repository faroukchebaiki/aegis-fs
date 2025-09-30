#![allow(dead_code)]
#![warn(clippy::pedantic)]

//! Core primitives and Phase 1 implementation for aegis-fs.

pub mod crypto;
pub mod db;
pub mod erasure;
pub mod journal;
pub mod model;
pub mod store;
pub mod util;
pub mod vault;

mod pipeline;

pub use model::DefaultsConfig;
pub use pipeline::{AegisFs, PackOptions, UnpackOptions};
