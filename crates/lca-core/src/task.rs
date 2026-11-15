use std::time::SystemTime;

use uuid::Uuid;

use crate::error::{AgentError, AgentResult};
use crate::lifecycle::AgentStatus;

/// One unit of work accepted by the agent.
///
/// Timestamps are supplied by the caller so the domain does not read the clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTask {
    id: Uuid,
    prompt: String,
    created_at: SystemTime,
    updated_at: SystemTime,
    status: AgentStatus,
}

impl AgentTask {
    /// Creates an idle task with a new random id.
    ///
    /// The stored prompt is trimmed. A prompt that is empty after trimming is rejected.
    pub fn create(prompt: impl Into<String>, now: SystemTime) -> AgentResult<Self> {
        let prompt = prompt.into();
        let prompt = prompt.trim();
        if prompt.is_empty() {
            return Err(AgentError::EmptyPrompt);
        }

        Ok(Self {
            id: Uuid::new_v4(),
            prompt: prompt.to_owned(),
            created_at: now,
            updated_at: now,
            status: AgentStatus::Idle,
        })
    }

    /// Task id.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }

    /// Trimmed prompt.
    #[must_use]
    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    /// Time supplied when the task was created.
    #[must_use]
    pub const fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// Time supplied by the latest accepted transition, or the creation time.
    #[must_use]
    pub const fn updated_at(&self) -> SystemTime {
        self.updated_at
    }

    /// Current lifecycle status.
    #[must_use]
    pub const fn status(&self) -> AgentStatus {
        self.status
    }

    /// Applies a lifecycle edge and records `now` as the update time.
    ///
    /// Invalid edges and timestamps earlier than `updated_at` leave the task unchanged.
    pub fn transition(&mut self, to: AgentStatus, now: SystemTime) -> AgentResult<()> {
        self.status.ensure_transition(to)?;
        if now < self.updated_at {
            return Err(AgentError::TimestampRegressed);
        }

        tracing::debug!(
            task_id = %self.id,
            from = self.status.as_str(),
            to = to.as_str(),
            "agent task transition"
        );
        self.status = to;
        self.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AgentError;
    use crate::lifecycle::AgentStatus;
    use uuid::Uuid;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }

    #[test]
    fn create_stores_identity_prompt_and_timestamps() {
        let task = AgentTask::create("  inspect the workspace  ", at(10)).expect("task");
        assert_ne!(task.id(), Uuid::nil());
        assert_eq!(task.prompt(), "inspect the workspace");
        assert_eq!(task.created_at(), at(10));
        assert_eq!(task.updated_at(), at(10));
        assert_eq!(task.status(), AgentStatus::Idle);
    }

    #[test]
    fn empty_prompts_are_rejected() {
        assert_eq!(
            AgentTask::create("   ", at(1)).expect_err("empty"),
            AgentError::EmptyPrompt
        );
        assert_eq!(
            AgentTask::create("", at(1)).expect_err("empty"),
            AgentError::EmptyPrompt
        );
    }

    #[test]
    fn transition_updates_status_and_timestamp_without_changing_identity() {
        let mut task = AgentTask::create("run", at(10)).expect("task");
        let id = task.id();
        task.transition(AgentStatus::Initializing, at(11))
            .expect("initializing");
        task.transition(AgentStatus::Ready, at(12)).expect("ready");
        task.transition(AgentStatus::Running, at(13))
            .expect("running");
        task.transition(AgentStatus::WaitingForTool, at(14))
            .expect("waiting");
        task.transition(AgentStatus::Running, at(15))
            .expect("running");
        task.transition(AgentStatus::Completed, at(16))
            .expect("completed");

        assert_eq!(task.id(), id);
        assert_eq!(task.prompt(), "run");
        assert_eq!(task.created_at(), at(10));
        assert_eq!(task.updated_at(), at(16));
        assert_eq!(task.status(), AgentStatus::Completed);
    }

    #[test]
    fn invalid_transition_and_earlier_timestamp_keep_the_task() {
        let mut task = AgentTask::create("run", at(10)).expect("task");
        let before = task.clone();

        let invalid = task
            .transition(AgentStatus::Running, at(11))
            .expect_err("skip");
        assert_eq!(
            invalid,
            AgentError::InvalidTransition {
                from: AgentStatus::Idle,
                to: AgentStatus::Running,
            }
        );
        assert_eq!(task, before);

        task.transition(AgentStatus::Initializing, at(12))
            .expect("initializing");
        let snapshot = task.clone();
        let regressed = task
            .transition(AgentStatus::Ready, at(11))
            .expect_err("time");
        assert_eq!(regressed, AgentError::TimestampRegressed);
        assert_eq!(task, snapshot);
    }

    #[test]
    fn distinct_tasks_receive_distinct_ids() {
        let first = AgentTask::create("one", at(1)).expect("first");
        let second = AgentTask::create("two", at(1)).expect("second");
        assert_ne!(first.id(), second.id());
    }
}
