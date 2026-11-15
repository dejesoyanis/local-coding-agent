use crate::lifecycle::AgentStatus;

/// Failure returned by the agent domain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentError {
    /// The requested status change is not part of the lifecycle.
    #[error("invalid agent transition from {from} to {to}")]
    InvalidTransition {
        /// Status before the rejected change.
        from: AgentStatus,
        /// Status that was rejected.
        to: AgentStatus,
    },

    /// A task prompt was empty or only whitespace.
    #[error("agent prompt must not be empty")]
    EmptyPrompt,

    /// A caller supplied a timestamp earlier than the task's last update.
    #[error("task timestamp moved backwards")]
    TimestampRegressed,
}

/// Result alias for agent domain operations.
pub type AgentResult<T> = Result<T, AgentError>;
