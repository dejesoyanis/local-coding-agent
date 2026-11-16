use crate::action::model::{ActionId, ActionSource, ActionStatus, AgentAction, ToolArguments};
use crate::action::policy::{PolicyDecision, PolicyDenyReason, authorize_proposal};
use crate::action::registry::ToolRegistry;
use crate::action::schema;

/// An action the validator accepted.
///
/// There is no public constructor. Deserialization cannot produce this type.
/// Acceptance still does not execute the tool.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedAction {
    id: ActionId,
    name: String,
    arguments: ToolArguments,
    source: ActionSource,
}

impl ValidatedAction {
    fn seal(action: &AgentAction) -> Self {
        Self {
            id: action.id(),
            name: action.name().to_owned(),
            arguments: action.arguments().clone(),
            source: action.source(),
        }
    }

    /// Controller identity copied from the proposal.
    #[must_use]
    pub const fn id(&self) -> ActionId {
        self.id
    }

    /// Canonical tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Arguments that satisfied the schema.
    #[must_use]
    pub const fn arguments(&self) -> &ToolArguments {
        &self.arguments
    }

    /// Native or JSON origin.
    #[must_use]
    pub const fn source(&self) -> ActionSource {
        self.source
    }

    /// Always [`ActionStatus::Valid`].
    #[must_use]
    pub const fn status(&self) -> ActionStatus {
        ActionStatus::Valid
    }
}

/// A batch that passed validation and policy as a whole.
///
/// An empty batch is a successful validation of zero proposals. It is not evidence that a
/// model exercised tool calling. Callers that probe tool calling treat it as a failure.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallBatch {
    actions: Vec<ValidatedAction>,
}

impl ToolCallBatch {
    /// Accepted actions, in proposal order.
    #[must_use]
    pub fn actions(&self) -> &[ValidatedAction] {
        &self.actions
    }

    /// Whether the batch contains no actions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Number of accepted actions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.actions.len()
    }
}

/// Why a batch was not accepted.
///
/// The first failing action rejects the batch. Earlier actions are not returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ActionValidationError {
    /// More proposals than [`super::MAX_ACTIONS`].
    #[error("batch exceeds {limit} actions")]
    TooManyActions {
        /// Configured limit.
        limit: usize,
        /// Number of proposals.
        actual: usize,
    },
    /// Two proposals share a controller identity.
    #[error("duplicate action id at index {index}")]
    DuplicateActionId {
        /// Index of the repeated identity.
        index: usize,
    },
    /// The name is not in the registry.
    #[error("unknown tool `{name}` at index {index}")]
    UnknownTool {
        /// Index in the proposal list.
        index: usize,
        /// Tool name, capped for diagnostics.
        name: String,
    },
    /// The argument JSON exceeds the tool limit.
    #[error("arguments at index {index} exceed {limit} bytes")]
    TooLarge {
        /// Index in the proposal list.
        index: usize,
        /// Tool limit, in bytes.
        limit: usize,
    },
    /// The arguments do not satisfy the schema.
    #[error("arguments at index {index} were rejected: {message}")]
    InvalidArguments {
        /// Index in the proposal list.
        index: usize,
        /// Schema explanation. It does not repeat the argument value.
        message: String,
    },
    /// Schema passed and policy denied the proposal.
    #[error("action `{name}` at index {index} was denied: {reason}")]
    PolicyDenied {
        /// Index in the proposal list.
        index: usize,
        /// Registered tool name.
        name: String,
        /// Policy reason.
        reason: PolicyDenyReason,
    },
}

impl ActionValidationError {
    /// Stable classification.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::TooManyActions { .. } => "too_many_actions",
            Self::DuplicateActionId { .. } => "duplicate_action_id",
            Self::UnknownTool { .. } => "unknown_tool",
            Self::TooLarge { .. } => "too_large",
            Self::InvalidArguments { .. } => "invalid_arguments",
            Self::PolicyDenied { .. } => "policy_denied",
        }
    }
}

/// Validates every proposal or rejects the batch.
///
/// The checks for one action are: known tool, argument size, schema, then policy.
/// Policy is a separate function. This function does not execute tools, touch the
/// filesystem, or start a process. Model-supplied identities are not read because
/// proposals do not carry them.
pub fn validate_batch(
    registry: &ToolRegistry,
    actions: &[AgentAction],
) -> Result<ToolCallBatch, ActionValidationError> {
    if actions.len() > super::MAX_ACTIONS {
        return reject(ActionValidationError::TooManyActions {
            limit: super::MAX_ACTIONS,
            actual: actions.len(),
        });
    }
    let mut seen = Vec::with_capacity(actions.len());
    let mut accepted = Vec::with_capacity(actions.len());
    for (index, action) in actions.iter().enumerate() {
        if seen.contains(&action.id()) {
            return reject(ActionValidationError::DuplicateActionId { index });
        }
        seen.push(action.id());
        accepted.push(validate_one(registry, index, action)?);
    }
    Ok(ToolCallBatch { actions: accepted })
}

fn validate_one(
    registry: &ToolRegistry,
    index: usize,
    action: &AgentAction,
) -> Result<ValidatedAction, ActionValidationError> {
    let Some(tool) = registry.get(action.name()) else {
        return reject(ActionValidationError::UnknownTool {
            index,
            name: cap_name(action.name()),
        });
    };
    let size = match serde_json::to_vec(action.arguments().as_value()) {
        Ok(bytes) => bytes.len(),
        Err(_) => {
            return reject(ActionValidationError::InvalidArguments {
                index,
                message: "arguments could not be encoded".to_owned(),
            });
        }
    };
    if size > tool.max_argument_bytes() {
        return reject(ActionValidationError::TooLarge {
            index,
            limit: tool.max_argument_bytes(),
        });
    }
    if let Err(message) = schema::validate_instance(tool.schema(), action.arguments().as_value()) {
        return reject(ActionValidationError::InvalidArguments { index, message });
    }
    match authorize_proposal(tool) {
        PolicyDecision::ProposalAllowed => Ok(ValidatedAction::seal(action)),
        PolicyDecision::Denied(reason) => reject(ActionValidationError::PolicyDenied {
            index,
            name: tool.name().to_owned(),
            reason,
        }),
    }
}

fn reject<T>(error: ActionValidationError) -> Result<T, ActionValidationError> {
    tracing::debug!(error_kind = error.kind(), "rejected tool-call batch");
    Err(error)
}

fn cap_name(name: &str) -> String {
    name.chars().take(64).collect()
}

/// Builds a registered tool for policy tests. The schema matches `diagnostic_echo`.
#[cfg(test)]
fn test_tool(
    name: &str,
    permission: crate::action::PermissionCategory,
    effect: crate::action::ToolEffect,
) -> crate::action::RegisteredTool {
    crate::action::RegisteredTool::try_new(
        name,
        "test tool",
        serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["message"],
            "properties": {
                "message": { "type": "string", "maxLength": 1024 }
            }
        }),
        permission,
        effect,
        crate::action::MAX_ARGUMENT_BYTES,
    )
    .expect("test tool")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{
        ActionIdFactory, ActionSource, PermissionCategory, ToolEffect, ToolRegistry,
        propose_actions,
    };
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn registry() -> ToolRegistry {
        ToolRegistry::diagnostic().expect("registry")
    }

    fn propose(calls: Vec<(String, Value)>) -> Vec<AgentAction> {
        propose_actions(&ActionIdFactory::new(), ActionSource::Native, calls)
    }

    fn echo(message: &str) -> (String, Value) {
        ("diagnostic_echo".to_owned(), json!({"message": message}))
    }

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir()
                .join(format!("lca-validate-{}-{nanos}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("temp");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_valid_call_is_accepted_without_becoming_authorized_by_parsing() {
        let batch = validate_batch(&registry(), &propose(vec![echo("hello")])).expect("batch");
        assert_eq!(batch.len(), 1);
        let action = &batch.actions()[0];
        assert_eq!(action.name(), "diagnostic_echo");
        assert_eq!(action.arguments().as_value()["message"], "hello");
        assert_eq!(action.id().get(), 1);
        assert_eq!(action.status(), ActionStatus::Valid);
        assert_eq!(action.source(), ActionSource::Native);
        assert_eq!(
            propose(vec![echo("hello")])[0].status(),
            ActionStatus::Unvalidated
        );
    }

    #[test]
    fn several_calls_keep_order_and_distinct_identities() {
        let batch = validate_batch(&registry(), &propose(vec![echo("first"), echo("second")]))
            .expect("batch");
        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch.actions()[0].arguments().as_value()["message"],
            "first"
        );
        assert_eq!(
            batch.actions()[1].arguments().as_value()["message"],
            "second"
        );
        assert_ne!(batch.actions()[0].id(), batch.actions()[1].id());
    }

    #[test]
    fn an_empty_batch_validates_and_is_empty() {
        let batch = validate_batch(&registry(), &[]).expect("empty");
        assert!(batch.is_empty());
    }

    #[test]
    fn unknown_names_missing_fields_and_wrong_types_reject_the_batch() {
        let unknown = validate_batch(
            &registry(),
            &propose(vec![(
                "execute_command".to_owned(),
                json!({"command": "do-not-run"}),
            )]),
        )
        .expect_err("unknown");
        assert_eq!(unknown.kind(), "unknown_tool");
        assert!(!unknown.to_string().contains("do-not-run"), "{unknown}");

        let missing = validate_batch(
            &registry(),
            &propose(vec![("diagnostic_echo".to_owned(), json!({}))]),
        )
        .expect_err("missing");
        assert_eq!(missing.kind(), "invalid_arguments");
        assert!(
            missing.to_string().contains("missing required field"),
            "{missing}"
        );

        let wrong = validate_batch(
            &registry(),
            &propose(vec![("diagnostic_echo".to_owned(), json!({"message": 1}))]),
        )
        .expect_err("type");
        assert!(wrong.to_string().contains("must be a string"), "{wrong}");

        let extra = validate_batch(
            &registry(),
            &propose(vec![(
                "diagnostic_echo".to_owned(),
                json!({"message": "hello", "loud": true}),
            )]),
        )
        .expect_err("extra");
        assert!(extra.to_string().contains("unknown field"), "{extra}");

        let spaced = validate_batch(
            &registry(),
            &propose(vec![(
                "diagnostic_echo ".to_owned(),
                json!({"message": "hello"}),
            )]),
        )
        .expect_err("space");
        assert_eq!(spaced.kind(), "unknown_tool");
    }

    #[test]
    fn one_invalid_action_discards_the_whole_batch() {
        let error = validate_batch(
            &registry(),
            &propose(vec![
                echo("hello"),
                ("write_file".to_owned(), json!({"path": "notes.txt"})),
            ]),
        )
        .expect_err("batch");
        assert_eq!(error.kind(), "unknown_tool");
        assert!(error.to_string().contains("index 1"), "{error}");
        let again = validate_batch(
            &registry(),
            &propose(vec![
                echo("hello"),
                ("write_file".to_owned(), json!({"path": "notes.txt"})),
            ]),
        )
        .expect_err("again");
        assert_eq!(error, again);
    }

    #[test]
    fn size_and_count_limits_reject_the_batch() {
        let long = "m".repeat(20_000);
        let error = validate_batch(&registry(), &propose(vec![echo(&long)])).expect_err("size");
        assert_eq!(error.kind(), "too_large");
        assert!(!error.to_string().contains(&long[..32]), "{error}");

        let calls = vec![echo("hello"); 9];
        let error = validate_batch(&registry(), &propose(calls)).expect_err("count");
        assert_eq!(error.kind(), "too_many_actions");
    }

    #[test]
    fn policy_denies_mutating_and_ungranted_tools_after_schema_checks() {
        let mut tools = ToolRegistry::empty();
        tools
            .insert(test_tool(
                "diagnostic_echo",
                PermissionCategory::Diagnostic,
                ToolEffect::Mutating,
            ))
            .expect("insert");
        let denied = validate_batch(&tools, &propose(vec![echo("hello")])).expect_err("mutating");
        assert_eq!(denied.kind(), "policy_denied");
        assert!(denied.to_string().contains("mutating"), "{denied}");

        let typed = validate_batch(
            &tools,
            &propose(vec![(
                "diagnostic_echo".to_owned(),
                json!({"message": true}),
            )]),
        )
        .expect_err("schema first");
        assert_eq!(typed.kind(), "invalid_arguments");

        let mut read = ToolRegistry::empty();
        read.insert(test_tool(
            "diagnostic_echo",
            PermissionCategory::WorkspaceRead,
            ToolEffect::ReadOnly,
        ))
        .expect("insert");
        let allowed = validate_batch(&read, &propose(vec![echo("hello")])).expect("workspace read");
        assert_eq!(allowed.len(), 1);
        assert_eq!(
            authorize_proposal(read.get("diagnostic_echo").expect("tool")),
            PolicyDecision::ProposalAllowed
        );

        let mut mismatched = ToolRegistry::empty();
        mismatched
            .insert(test_tool(
                "diagnostic_echo",
                PermissionCategory::WorkspaceRead,
                ToolEffect::ApprovalRequired,
            ))
            .expect("insert");
        let denied =
            validate_batch(&mismatched, &propose(vec![echo("hello")])).expect_err("permission");
        assert_eq!(denied.kind(), "policy_denied");
        assert_eq!(
            authorize_proposal(mismatched.get("diagnostic_echo").expect("tool")),
            PolicyDecision::Denied(PolicyDenyReason::PermissionNotGranted)
        );
    }

    #[test]
    fn duplicate_controller_identities_are_rejected() {
        let actions = vec![
            AgentAction::propose_with_id(
                7,
                "diagnostic_echo",
                json!({"message": "a"}),
                ActionSource::Native,
            ),
            AgentAction::propose_with_id(
                7,
                "diagnostic_echo",
                json!({"message": "b"}),
                ActionSource::Native,
            ),
        ];
        let error = validate_batch(&registry(), &actions).expect_err("duplicate");
        assert_eq!(error.kind(), "duplicate_action_id");
    }

    #[test]
    fn validation_does_not_read_files_or_start_a_process() {
        let root = TempDir::new();
        let secret = root.0.join("secret.txt");
        std::fs::write(&secret, "SENTINEL_DO_NOT_LEAK").expect("secret");
        let command = "SENTINEL_COMMAND_DO_NOT_RUN";
        let actions = propose(vec![
            (
                "execute_command".to_owned(),
                json!({"command": command, "message": "SENTINEL_DO_NOT_LEAK"}),
            ),
            echo("hello"),
        ]);
        let error = validate_batch(&registry(), &actions).expect_err("rejected");
        assert_eq!(error.kind(), "unknown_tool");
        assert!(
            !error.to_string().contains("SENTINEL_DO_NOT_LEAK"),
            "{error}"
        );
        assert!(!error.to_string().contains(command), "{error}");
        assert_eq!(
            std::fs::read_to_string(&secret).expect("unchanged"),
            "SENTINEL_DO_NOT_LEAK"
        );
    }
}
