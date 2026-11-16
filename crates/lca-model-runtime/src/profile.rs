//! Model-aware protocol profiles.
//!
//! The only model-name comparison in this crate lives in [`resolve_protocol_profile`].
//! Callers use the returned profile. They do not compare names again.

/// Protocol a profile prefers when the caller asked for `auto`.
///
/// An explicit `native` or `json` preference is not overridden by this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredProtocol {
    /// Existing capability rules: native when the backend confirms tools, otherwise JSON.
    Capability,
    /// Native tool calls when the backend confirms them.
    Native,
    /// The versioned JSON action document, even when native tool calling is confirmed.
    StructuredJson,
}

impl PreferredProtocol {
    /// Stable name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capability => "capability",
            Self::Native => "native",
            Self::StructuredJson => "json",
        }
    }
}

/// Typed protocol preference for one model identifier.
///
/// `fallback_eligible` applies only while the protocol is being chosen, before the first
/// generation. It does not authorize a second protocol after a model, transport, or parser
/// error. The chosen protocol stays fixed for the whole agent run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelProtocolProfile {
    model: String,
    preferred: PreferredProtocol,
    fallback_eligible: bool,
    version: u32,
    digest: Option<String>,
}

impl ModelProtocolProfile {
    /// Model identifier this profile was resolved for.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Protocol `auto` should prefer.
    #[must_use]
    pub const fn preferred(&self) -> PreferredProtocol {
        self.preferred
    }

    /// Whether the other protocol may be selected when the preferred one is unavailable.
    ///
    /// This is not an error retry.
    #[must_use]
    pub const fn fallback_eligible(&self) -> bool {
        self.fallback_eligible
    }

    /// Profile revision. Zero means no registered profile matched the identifier.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Optional model digest. LCA-01F does not verify it.
    #[must_use]
    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

const REGISTERED_AGENT_MODEL: &str = "lca-30b-agent";
const REGISTERED_AGENT_PROFILE_VERSION: u32 = 1;

/// Resolves the protocol profile for `model`.
///
/// `lca-30b-agent` prefers JSON and is not eligible to switch to native during selection.
/// Every other identifier keeps the capability rules. The comparison is exact: a tag such
/// as `lca-30b-agent:latest` is a different identifier and stays on the capability rules.
#[must_use]
pub fn resolve_protocol_profile(model: &str) -> ModelProtocolProfile {
    if model == REGISTERED_AGENT_MODEL {
        ModelProtocolProfile {
            model: model.to_owned(),
            preferred: PreferredProtocol::StructuredJson,
            fallback_eligible: false,
            version: REGISTERED_AGENT_PROFILE_VERSION,
            digest: None,
        }
    } else {
        ModelProtocolProfile {
            model: model.to_owned(),
            preferred: PreferredProtocol::Capability,
            fallback_eligible: true,
            version: 0,
            digest: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_model_is_json_first_without_a_selection_fallback() {
        let profile = resolve_protocol_profile("lca-30b-agent");
        assert_eq!(profile.model(), "lca-30b-agent");
        assert_eq!(profile.preferred(), PreferredProtocol::StructuredJson);
        assert!(!profile.fallback_eligible());
        assert_eq!(profile.version(), 1);
        assert_eq!(profile.digest(), None);
        assert_eq!(profile.preferred().as_str(), "json");
    }

    #[test]
    fn unknown_models_keep_capability_rules() {
        for model in ["lca-agent", "lca-30b-agent:latest", "other"] {
            let profile = resolve_protocol_profile(model);
            assert_eq!(
                profile.preferred(),
                PreferredProtocol::Capability,
                "{model}"
            );
            assert!(profile.fallback_eligible(), "{model}");
            assert_eq!(profile.version(), 0, "{model}");
            assert_eq!(profile.model(), model);
        }
    }
}
