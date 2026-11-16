use crate::action::registry::{PermissionCategory, RegisteredTool, ToolEffect};

/// Whether a schema-valid proposal may be handed back as validated.
///
/// Allowing a proposal does not execute it and does not grant a later milestone permission
/// by itself. The decision is separate from schema checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The proposal may be returned. Execution stays disabled.
    ProposalAllowed,
    /// The proposal must not be treated as validated.
    Denied(PolicyDenyReason),
}

/// Why policy rejected a proposal that may otherwise be well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyDenyReason {
    /// Writes, edits, and process execution are not authorized.
    #[error("mutating actions are not authorized")]
    MutatingEffect,
    /// The permission category is not granted in this milestone.
    #[error("only diagnostic actions are authorized")]
    PermissionNotGranted,
}

impl PolicyDenyReason {
    /// Stable classification.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::MutatingEffect => "mutating_effect",
            Self::PermissionNotGranted => "permission_not_granted",
        }
    }
}

/// Judges a registered tool without reading arguments or running it.
#[must_use]
pub fn authorize_proposal(tool: &RegisteredTool) -> PolicyDecision {
    if tool.effect() == ToolEffect::Mutating {
        return PolicyDecision::Denied(PolicyDenyReason::MutatingEffect);
    }
    if tool.permission() != PermissionCategory::Diagnostic {
        return PolicyDecision::Denied(PolicyDenyReason::PermissionNotGranted);
    }
    PolicyDecision::ProposalAllowed
}
