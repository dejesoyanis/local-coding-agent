//! Typed configuration for the local coding agent.
//!
//! The loader reads one TOML file, fills documented defaults, and rejects a workspace
//! root that does not exist or is not a directory. The canonical workspace path is what
//! later milestones must use as the confinement root. This crate does not contact Ollama
//! and does not execute tools.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod load;
mod model;
mod pathutil;

pub use error::ConfigError;
pub use load::load_from_path;
pub use model::{
    AgentConfig, ConfigSummary, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_CONTEXT_WINDOW,
    DEFAULT_GENERATION_LIMIT, DEFAULT_MAX_STEPS, DEFAULT_OLLAMA_ENDPOINT, DEFAULT_OLLAMA_MODEL,
    DEFAULT_REQUEST_TIMEOUT_SECS, DEFAULT_TIMEOUT_SECS, MAX_CONFIG_BYTES, MAX_CONTEXT_WINDOW,
    MAX_MODEL_NAME_LEN, MAX_REQUEST_TIMEOUT_SECS, MAX_STEPS, MAX_TIMEOUT_SECS,
};
