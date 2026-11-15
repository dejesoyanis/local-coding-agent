//! Tool requests and workspace authorization.
//!
//! The executor in this milestone evaluates those rules and then refuses to run the tool.
//! It does not read file contents, modify the workspace, or start a process.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod auth;
mod error;
mod executor;
mod model;
mod pathutil;

pub use auth::{AuthorizationDecision, ToolAuthorization, WorkspaceScope};
pub use error::{DenyReason, ToolError};
pub use executor::{RejectingToolExecutor, ToolExecutor};
pub use model::{ToolArguments, ToolName, ToolRequest, ToolResult};
