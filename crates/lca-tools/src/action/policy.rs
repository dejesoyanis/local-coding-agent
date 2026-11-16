use crate::action::registry::{PermissionCategory, RegisteredTool, ToolEffect};

/// Whether a schema-valid proposal may be handed back as validated.
///
/// Allowing a proposal does not execute it and does not approve a write.
/// The decision is separate from schema checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The proposal may be returned. A caller still has to dispatch it.
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
    /// The permission category is not paired with an effect this milestone allows.
    #[error("the tool permission is not granted for its effect")]
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
///
/// Read-only diagnostic and workspace-read tools are allowed as proposals.
/// `apply_patch` is allowed only as an approval-gated effect. A mutating effect
/// is still denied, so a registered shell or unchecked write cannot pass.
#[must_use]
pub fn authorize_proposal(tool: &RegisteredTool) -> PolicyDecision {
    if tool.effect() == ToolEffect::Mutating {
        return PolicyDecision::Denied(PolicyDenyReason::MutatingEffect);
    }
    let allowed = matches!(
        (tool.permission(), tool.effect()),
        (PermissionCategory::Diagnostic, ToolEffect::ReadOnly)
            | (PermissionCategory::WorkspaceRead, ToolEffect::ReadOnly)
            | (
                PermissionCategory::WorkspaceMutation,
                ToolEffect::ApprovalRequired
            )
    );
    if allowed {
        PolicyDecision::ProposalAllowed
    } else {
        PolicyDecision::Denied(PolicyDenyReason::PermissionNotGranted)
    }
}
