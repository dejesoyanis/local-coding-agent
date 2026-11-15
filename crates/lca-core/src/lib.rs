//! Domain model for the local coding agent.
//!
//! This crate owns lifecycle state, task identity, and typed errors. It does not
//! talk to Ollama, touch the filesystem, or parse command-line arguments.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod error;
mod lifecycle;
mod task;

pub use error::{AgentError, AgentResult};
pub use lifecycle::{AgentLifecycle, AgentStatus};
pub use task::AgentTask;
pub use uuid::Uuid;
