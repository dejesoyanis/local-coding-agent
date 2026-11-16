//! Domain model for the local coding agent.
//!
//! This crate owns lifecycle state, task identity, typed errors, the approval
//! boundary for a validated filesystem action, and the single-turn controller.
//! The controller calls a [`lca_model_runtime::ModelRuntime`]. It does not open an
//! HTTP connection and it does not parse command-line arguments. [`dispatch`] does
//! not write; [`dispatch::commit_prepared`] writes only after a trusted confirmation
//! line. The single-turn controller never calls that write path.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

mod dispatch;
mod error;
mod eval;
mod lifecycle;
mod task;
mod turn;

pub use dispatch::{WriteConfirmation, commit_prepared, dispatch_validated};
pub use error::{AgentError, AgentResult};
pub use eval::{
    EvalError, EvalExecution, EvalIdentity, EvalPlan, EvalReport, evaluate_tool_selection,
};
pub use lifecycle::{AgentLifecycle, AgentStatus};
pub use task::AgentTask;
pub use turn::{
    ExecutedAction, PROMPT_VERSION, ResponseClass, SingleTurnAgentController, TurnError,
    TurnReport, TurnSettings, classify_response,
};
pub use uuid::Uuid;
