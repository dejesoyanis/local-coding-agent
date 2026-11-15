use std::fmt;

use crate::error::{AgentError, AgentResult};

const FROM_IDLE: &[AgentStatus] = &[AgentStatus::Initializing];
const FROM_INITIALIZING: &[AgentStatus] =
    &[AgentStatus::Ready, AgentStatus::Failed, AgentStatus::Halted];
const FROM_READY: &[AgentStatus] = &[AgentStatus::Running, AgentStatus::Halted];
const FROM_RUNNING: &[AgentStatus] = &[
    AgentStatus::WaitingForTool,
    AgentStatus::Completed,
    AgentStatus::Failed,
    AgentStatus::Halted,
];
const FROM_WAITING: &[AgentStatus] = &[
    AgentStatus::Running,
    AgentStatus::Failed,
    AgentStatus::Halted,
];
const FROM_TERMINAL: &[AgentStatus] = &[];

/// Lifecycle state of one agent.
///
/// Valid transitions:
/// - `idle` -> `initializing`
/// - `initializing` -> `ready`, `failed`, or `halted`
/// - `ready` -> `running` or `halted`
/// - `running` -> `waiting_for_tool`, `completed`, `failed`, or `halted`
/// - `waiting_for_tool` -> `running`, `failed`, or `halted`
///
/// `completed`, `failed`, and `halted` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentStatus {
    /// No task has been accepted.
    Idle,
    /// Configuration and runtime dependencies are being prepared.
    Initializing,
    /// The agent can accept a task.
    Ready,
    /// A task is in progress inside the agent.
    Running,
    /// The agent is paused until a tool result arrives.
    WaitingForTool,
    /// The task finished successfully.
    Completed,
    /// The task stopped because of an error.
    Failed,
    /// The task was stopped intentionally.
    Halted,
}

impl AgentStatus {
    /// Stable lowercase name used in logs and command output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Initializing => "initializing",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::WaitingForTool => "waiting_for_tool",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Halted => "halted",
        }
    }

    /// Whether this status accepts no further transitions.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Halted)
    }

    /// Statuses that may follow `self`.
    #[must_use]
    pub const fn allowed_transitions(self) -> &'static [Self] {
        match self {
            Self::Idle => FROM_IDLE,
            Self::Initializing => FROM_INITIALIZING,
            Self::Ready => FROM_READY,
            Self::Running => FROM_RUNNING,
            Self::WaitingForTool => FROM_WAITING,
            Self::Completed | Self::Failed | Self::Halted => FROM_TERMINAL,
        }
    }

    /// Returns whether `to` is a legal successor of `self`.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        self.allowed_transitions().contains(&to)
    }

    pub(crate) fn ensure_transition(self, to: Self) -> AgentResult<()> {
        if self.can_transition(to) {
            Ok(())
        } else {
            Err(AgentError::InvalidTransition { from: self, to })
        }
    }
}

impl fmt::Display for AgentStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// In-place lifecycle. Copies are not offered, so a caller cannot fork the state by accident.
#[derive(Debug, PartialEq, Eq)]
pub struct AgentLifecycle {
    status: AgentStatus,
}

impl Default for AgentLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentLifecycle {
    /// Starts at [`AgentStatus::Idle`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            status: AgentStatus::Idle,
        }
    }

    /// Current status.
    #[must_use]
    pub const fn status(&self) -> AgentStatus {
        self.status
    }

    /// Moves to `to` when that edge exists. The status is unchanged when it does not.
    pub fn transition(&mut self, to: AgentStatus) -> AgentResult<()> {
        if let Err(error) = self.status.ensure_transition(to) {
            tracing::warn!(
                from = self.status.as_str(),
                to = to.as_str(),
                "rejected agent status transition"
            );
            return Err(error);
        }

        tracing::debug!(
            from = self.status.as_str(),
            to = to.as_str(),
            "agent status transition"
        );
        self.status = to;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentError;

    const ALL: [AgentStatus; 8] = [
        AgentStatus::Idle,
        AgentStatus::Initializing,
        AgentStatus::Ready,
        AgentStatus::Running,
        AgentStatus::WaitingForTool,
        AgentStatus::Completed,
        AgentStatus::Failed,
        AgentStatus::Halted,
    ];

    fn specified(from: AgentStatus, to: AgentStatus) -> bool {
        matches!(
            (from, to),
            (AgentStatus::Idle, AgentStatus::Initializing)
                | (AgentStatus::Initializing, AgentStatus::Ready)
                | (AgentStatus::Initializing, AgentStatus::Failed)
                | (AgentStatus::Initializing, AgentStatus::Halted)
                | (AgentStatus::Ready, AgentStatus::Running)
                | (AgentStatus::Ready, AgentStatus::Halted)
                | (AgentStatus::Running, AgentStatus::WaitingForTool)
                | (AgentStatus::Running, AgentStatus::Completed)
                | (AgentStatus::Running, AgentStatus::Failed)
                | (AgentStatus::Running, AgentStatus::Halted)
                | (AgentStatus::WaitingForTool, AgentStatus::Running)
                | (AgentStatus::WaitingForTool, AgentStatus::Failed)
                | (AgentStatus::WaitingForTool, AgentStatus::Halted)
        )
    }

    fn reach(status: AgentStatus) -> AgentLifecycle {
        let mut lifecycle = AgentLifecycle::new();
        let path: &[AgentStatus] = match status {
            AgentStatus::Idle => &[],
            AgentStatus::Initializing => &[AgentStatus::Initializing],
            AgentStatus::Ready => &[AgentStatus::Initializing, AgentStatus::Ready],
            AgentStatus::Running => &[
                AgentStatus::Initializing,
                AgentStatus::Ready,
                AgentStatus::Running,
            ],
            AgentStatus::WaitingForTool => &[
                AgentStatus::Initializing,
                AgentStatus::Ready,
                AgentStatus::Running,
                AgentStatus::WaitingForTool,
            ],
            AgentStatus::Completed => &[
                AgentStatus::Initializing,
                AgentStatus::Ready,
                AgentStatus::Running,
                AgentStatus::Completed,
            ],
            AgentStatus::Failed => &[AgentStatus::Initializing, AgentStatus::Failed],
            AgentStatus::Halted => &[AgentStatus::Initializing, AgentStatus::Halted],
        };
        for step in path {
            lifecycle.transition(*step).expect("setup transition");
        }
        assert_eq!(lifecycle.status(), status);
        lifecycle
    }

    #[test]
    fn transitions_match_the_specification() {
        for from in ALL {
            for to in ALL {
                assert_eq!(
                    from.can_transition(to),
                    specified(from, to),
                    "{from} -> {to}"
                );

                let mut lifecycle = reach(from);
                let result = lifecycle.transition(to);
                if specified(from, to) {
                    assert_eq!(result, Ok(()));
                    assert_eq!(lifecycle.status(), to);
                } else {
                    assert_eq!(result, Err(AgentError::InvalidTransition { from, to }));
                    assert_eq!(lifecycle.status(), from);
                }
            }
        }
    }

    #[test]
    fn terminal_statuses_have_no_successors() {
        for status in [
            AgentStatus::Completed,
            AgentStatus::Failed,
            AgentStatus::Halted,
        ] {
            assert!(status.is_terminal());
            assert!(status.allowed_transitions().is_empty());
        }
        assert!(!AgentStatus::Running.is_terminal());
    }

    #[test]
    fn new_lifecycle_is_idle() {
        assert_eq!(AgentLifecycle::new().status(), AgentStatus::Idle);
        assert_eq!(AgentLifecycle::default().status(), AgentStatus::Idle);
    }

    #[test]
    fn display_names_are_stable() {
        assert_eq!(AgentStatus::WaitingForTool.to_string(), "waiting_for_tool");
        assert_eq!(AgentStatus::Idle.as_str(), "idle");
    }
}
