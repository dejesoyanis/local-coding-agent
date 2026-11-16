//! Domain model for the local coding agent.
//!
//! This crate owns lifecycle state, task identity, typed errors, and the approval
//! boundary for a validated filesystem action. It does not talk to Ollama or parse
//! command-line arguments. [`dispatch`] does not write; [`dispatch::commit_prepared`]
//! writes only after a trusted confirmation line.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod dispatch;
mod error;
mod lifecycle;
mod task;

pub use dispatch::{WriteConfirmation, commit_prepared, dispatch_validated};
pub use error::{AgentError, AgentResult};
pub use lifecycle::{AgentLifecycle, AgentStatus};
pub use task::AgentTask;
pub use uuid::Uuid;
