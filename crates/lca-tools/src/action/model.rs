use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

/// Controller-issued identity of one proposed action.
///
/// The value comes from [`ActionIdFactory`]. Model text is not an identity source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActionId(u64);

impl ActionId {
    /// Numeric identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Allocates action identities for one controller operation.
///
/// The first identity is 1. A new factory restarts at 1 so tests stay deterministic.
/// Identities from one factory are unique. They are not taken from model output.
#[derive(Debug)]
pub struct ActionIdFactory {
    next: AtomicU64,
}

impl ActionIdFactory {
    /// Starts at identity 1.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Returns the next identity.
    pub fn next(&self) -> ActionId {
        ActionId(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for ActionIdFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a proposal was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionSource {
    /// A native backend `tool_calls` array.
    Native,
    /// The versioned JSON action document.
    StructuredJson,
}

impl ActionSource {
    /// Stable name used by the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::StructuredJson => "json",
        }
    }
}

impl fmt::Display for ActionSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether a trusted validator has accepted an action.
///
/// [`AgentAction`] is always [`Self::Unvalidated`]. [`Self::Valid`] is only reported by
/// [`super::ValidatedAction`], which the validator constructs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionStatus {
    /// Parsed and not yet accepted.
    Unvalidated,
    /// Accepted by the validator. This is not permission to execute.
    Valid,
}

impl ActionStatus {
    /// Stable name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unvalidated => "unvalidated",
            Self::Valid => "valid",
        }
    }
}

/// JSON arguments of a model proposal.
///
/// This is not [`crate::ToolArguments`]. The value is kept as JSON so numbers, objects,
/// and strings are not collapsed into text.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolArguments {
    value: Value,
}

impl ToolArguments {
    /// Wraps a JSON value. The wrap does not validate or authorize it.
    #[must_use]
    pub fn from_json(value: Value) -> Self {
        Self { value }
    }

    /// Borrowed JSON value.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.value
    }
}

/// A tool name plus its JSON arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    name: String,
    arguments: ToolArguments,
}

impl ToolCall {
    /// Tool name as proposed. The registry compares it exactly.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// JSON arguments. They may still be invalid.
    #[must_use]
    pub const fn arguments(&self) -> &ToolArguments {
        &self.arguments
    }
}

/// One untrusted proposal.
///
/// Construction assigns a controller identity and leaves the status unvalidated.
/// There is no deserializer for this type.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentAction {
    id: ActionId,
    call: ToolCall,
    source: ActionSource,
}

impl AgentAction {
    fn new(id: ActionId, name: String, arguments: Value, source: ActionSource) -> Self {
        Self {
            id,
            call: ToolCall {
                name,
                arguments: ToolArguments::from_json(arguments),
            },
            source,
        }
    }

    /// Controller identity.
    #[must_use]
    pub const fn id(&self) -> ActionId {
        self.id
    }

    /// Proposed tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.call.name()
    }

    /// Proposed JSON arguments.
    #[must_use]
    pub const fn arguments(&self) -> &ToolArguments {
        self.call.arguments()
    }

    /// Native or JSON origin.
    #[must_use]
    pub const fn source(&self) -> ActionSource {
        self.source
    }

    /// Always [`ActionStatus::Unvalidated`].
    #[must_use]
    pub const fn status(&self) -> ActionStatus {
        ActionStatus::Unvalidated
    }

    /// The proposed call.
    #[must_use]
    pub const fn call(&self) -> &ToolCall {
        &self.call
    }

    /// Test helper that can repeat an identity. Production proposals use [`propose_actions`].
    #[cfg(test)]
    pub(crate) fn propose_with_id(
        id: u64,
        name: &str,
        arguments: Value,
        source: ActionSource,
    ) -> Self {
        Self::new(ActionId::from_raw(id), name.to_owned(), arguments, source)
    }
}

/// Assigns fresh identities and records the origin of each call.
///
/// `calls` are `(tool name, JSON arguments)` pairs. Their order is preserved.
/// Names and arguments are not checked here.
pub fn propose_actions(
    factory: &ActionIdFactory,
    source: ActionSource,
    calls: impl IntoIterator<Item = (String, Value)>,
) -> Vec<AgentAction> {
    calls
        .into_iter()
        .map(|(name, arguments)| AgentAction::new(factory.next(), name, arguments, source))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn proposals_are_unvalidated_and_identities_come_from_the_factory() {
        let factory = ActionIdFactory::new();
        let actions = propose_actions(
            &factory,
            ActionSource::Native,
            [
                ("diagnostic_echo".to_owned(), json!({"message": "one"})),
                ("diagnostic_echo".to_owned(), json!({"message": "two"})),
            ],
        );
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].id().get(), 1);
        assert_eq!(actions[1].id().get(), 2);
        assert_ne!(actions[0].id(), actions[1].id());
        assert_eq!(actions[0].status(), ActionStatus::Unvalidated);
        assert_eq!(actions[0].source(), ActionSource::Native);
        assert_eq!(actions[0].name(), "diagnostic_echo");
        assert_eq!(actions[1].arguments().as_value()["message"], "two");
        assert_eq!(factory.next().get(), 3);
    }
}
