use std::fmt;

use crate::capabilities::{CapabilityStatus, ModelCapabilities};
use crate::profile::{ModelProtocolProfile, PreferredProtocol};

/// Which tool protocol the controller asked for.
///
/// Selection happens once, before the model is called. A rejected model payload does not
/// cause a second selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPreference {
    /// Native tool calls. Requires an explicit confirmation from the backend.
    Native,
    /// The versioned JSON action document.
    StructuredJson,
    /// Native when it is confirmed, otherwise an expressly allowed JSON fallback.
    Auto,
}

/// The protocol chosen for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedProtocol {
    /// The backend confirmed native tool calling.
    Native,
    /// The JSON action document will be validated strictly.
    ///
    /// `json_mode_confirmed` is true only when the backend listed JSON mode.
    /// A false value still allows the fallback, because the controller validates the
    /// bytes. It does not mean the model will reliably emit JSON.
    StructuredJson {
        /// Whether the backend listed JSON mode.
        json_mode_confirmed: bool,
    },
}

impl SelectedProtocol {
    /// Stable name used by the CLI.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::StructuredJson { .. } => "json",
        }
    }

    /// Whether the backend listed JSON mode for this selection.
    #[must_use]
    pub const fn json_mode_confirmed(self) -> bool {
        match self {
            Self::Native => false,
            Self::StructuredJson {
                json_mode_confirmed,
            } => json_mode_confirmed,
        }
    }
}

impl fmt::Display for SelectedProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Protocols the controller is willing to use for one runtime.
///
/// Unknown capabilities never flip these flags. The composition root sets
/// `json_fallback_allowed` only when strict JSON validation is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolAvailability {
    json_fallback_allowed: bool,
}

impl ProtocolAvailability {
    /// Records whether the JSON action document is an allowed fallback.
    #[must_use]
    pub const fn new(json_fallback_allowed: bool) -> Self {
        Self {
            json_fallback_allowed,
        }
    }

    /// Whether the controller may select the JSON action document.
    #[must_use]
    pub const fn json_fallback_allowed(self) -> bool {
        self.json_fallback_allowed
    }
}

/// Why a protocol could not be selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolSelectionError {
    /// Native mode was requested and the backend did not confirm tool calling.
    #[error("native tool calling is not confirmed (status: {status})")]
    NativeUnconfirmed {
        /// Reported tool-calling status. `unknown` is not treated as support.
        status: CapabilityStatus,
    },

    /// JSON mode was requested and this runtime did not allow the fallback.
    #[error("structured JSON fallback is not enabled for this runtime")]
    JsonFallbackDisabled,

    /// Auto mode found neither confirmed native tool calling nor an allowed JSON fallback.
    #[error("no tool-calling protocol is available")]
    NoProtocolAvailable,
}

impl ProtocolSelectionError {
    /// Stable classification that does not include model output.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NativeUnconfirmed { .. } => "native_unconfirmed",
            Self::JsonFallbackDisabled => "json_fallback_disabled",
            Self::NoProtocolAvailable => "no_protocol",
        }
    }
}

/// Chooses one protocol from an explicit preference and a capability report.
///
/// `Unknown` and `NotReported` are not confirmations. This function does not inspect
/// unrecognized capability names.
pub fn select_protocol(
    preference: ProtocolPreference,
    capabilities: &ModelCapabilities,
    availability: ProtocolAvailability,
) -> Result<SelectedProtocol, ProtocolSelectionError> {
    match preference {
        ProtocolPreference::Native => confirmed_native(capabilities),
        ProtocolPreference::StructuredJson => allowed_json(capabilities, availability),
        ProtocolPreference::Auto => {
            if capabilities.tools() == CapabilityStatus::Confirmed {
                Ok(SelectedProtocol::Native)
            } else {
                allowed_json(capabilities, availability)
                    .map_err(|_| ProtocolSelectionError::NoProtocolAvailable)
            }
        }
    }
}

/// Chooses one protocol, applying a model profile when the preference is `auto`.
///
/// Explicit `native` and `json` preferences ignore the profile. `auto` uses
/// [`ModelProtocolProfile::preferred`]. A failure here does not try the other protocol
/// unless `fallback_eligible` is set, and it never tries again after a generation error.
/// The caller must keep the returned protocol for the rest of the run.
pub fn select_protocol_with_profile(
    preference: ProtocolPreference,
    profile: &ModelProtocolProfile,
    capabilities: &ModelCapabilities,
    availability: ProtocolAvailability,
) -> Result<SelectedProtocol, ProtocolSelectionError> {
    match preference {
        ProtocolPreference::Native | ProtocolPreference::StructuredJson => {
            select_protocol(preference, capabilities, availability)
        }
        ProtocolPreference::Auto => match profile.preferred() {
            PreferredProtocol::Capability => {
                select_protocol(ProtocolPreference::Auto, capabilities, availability)
            }
            PreferredProtocol::StructuredJson => prefer_then(
                allowed_json(capabilities, availability),
                || confirmed_native(capabilities),
                profile,
            ),
            PreferredProtocol::Native => prefer_then(
                confirmed_native(capabilities),
                || allowed_json(capabilities, availability),
                profile,
            ),
        },
    }
}

fn prefer_then(
    preferred: Result<SelectedProtocol, ProtocolSelectionError>,
    other: impl FnOnce() -> Result<SelectedProtocol, ProtocolSelectionError>,
    profile: &ModelProtocolProfile,
) -> Result<SelectedProtocol, ProtocolSelectionError> {
    match preferred {
        Ok(selected) => Ok(selected),
        Err(_) if profile.fallback_eligible() => {
            other().map_err(|_| ProtocolSelectionError::NoProtocolAvailable)
        }
        Err(error) => Err(error),
    }
}

fn confirmed_native(
    capabilities: &ModelCapabilities,
) -> Result<SelectedProtocol, ProtocolSelectionError> {
    if capabilities.tools() == CapabilityStatus::Confirmed {
        Ok(SelectedProtocol::Native)
    } else {
        Err(ProtocolSelectionError::NativeUnconfirmed {
            status: capabilities.tools(),
        })
    }
}

fn allowed_json(
    capabilities: &ModelCapabilities,
    availability: ProtocolAvailability,
) -> Result<SelectedProtocol, ProtocolSelectionError> {
    if !availability.json_fallback_allowed() {
        return Err(ProtocolSelectionError::JsonFallbackDisabled);
    }
    Ok(SelectedProtocol::StructuredJson {
        json_mode_confirmed: capabilities.json_mode() == CapabilityStatus::Confirmed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::CapabilityParts;

    fn capabilities(tools: CapabilityStatus, json_mode: CapabilityStatus) -> ModelCapabilities {
        ModelCapabilities::from_parts(
            "model",
            CapabilityParts {
                tools,
                json_mode,
                unrecognized: vec!["function_calling".to_owned()],
                ..CapabilityParts::default()
            },
        )
    }

    #[test]
    fn native_requires_an_explicit_confirmation() {
        let allowed = ProtocolAvailability::new(true);
        let confirmed = capabilities(CapabilityStatus::Confirmed, CapabilityStatus::Unknown);
        assert_eq!(
            select_protocol(ProtocolPreference::Native, &confirmed, allowed).expect("native"),
            SelectedProtocol::Native
        );

        for status in [CapabilityStatus::Unknown, CapabilityStatus::NotReported] {
            let report = capabilities(status, CapabilityStatus::Confirmed);
            let error = select_protocol(ProtocolPreference::Native, &report, allowed)
                .expect_err("unconfirmed");
            assert_eq!(error, ProtocolSelectionError::NativeUnconfirmed { status });
            assert_eq!(error.kind(), "native_unconfirmed");
        }
    }

    #[test]
    fn auto_prefers_native_and_does_not_invent_support() {
        let allowed = ProtocolAvailability::new(true);
        let native = capabilities(CapabilityStatus::Confirmed, CapabilityStatus::NotReported);
        assert_eq!(
            select_protocol(ProtocolPreference::Auto, &native, allowed).expect("auto"),
            SelectedProtocol::Native
        );

        let fallback = capabilities(CapabilityStatus::Unknown, CapabilityStatus::Unknown);
        let selected =
            select_protocol(ProtocolPreference::Auto, &fallback, allowed).expect("fallback");
        assert_eq!(
            selected,
            SelectedProtocol::StructuredJson {
                json_mode_confirmed: false
            }
        );
        assert_eq!(selected.as_str(), "json");

        let confirmed_json =
            capabilities(CapabilityStatus::NotReported, CapabilityStatus::Confirmed);
        let selected =
            select_protocol(ProtocolPreference::StructuredJson, &confirmed_json, allowed)
                .expect("json");
        assert_eq!(
            selected,
            SelectedProtocol::StructuredJson {
                json_mode_confirmed: true
            }
        );

        let blocked = ProtocolAvailability::new(false);
        let error =
            select_protocol(ProtocolPreference::Auto, &fallback, blocked).expect_err("blocked");
        assert_eq!(error, ProtocolSelectionError::NoProtocolAvailable);
        let error = select_protocol(ProtocolPreference::StructuredJson, &confirmed_json, blocked)
            .expect_err("disabled");
        assert_eq!(error, ProtocolSelectionError::JsonFallbackDisabled);
    }

    #[test]
    fn auto_uses_the_profile_and_does_not_switch_after_selection() {
        let allowed = ProtocolAvailability::new(true);
        let blocked = ProtocolAvailability::new(false);
        let confirmed = capabilities(CapabilityStatus::Confirmed, CapabilityStatus::Unknown);
        let profile = crate::resolve_protocol_profile("lca-30b-agent");
        let selected =
            select_protocol_with_profile(ProtocolPreference::Auto, &profile, &confirmed, allowed)
                .expect("json first");
        assert_eq!(
            selected,
            SelectedProtocol::StructuredJson {
                json_mode_confirmed: false
            }
        );
        assert_eq!(
            select_protocol_with_profile(
                ProtocolPreference::Native,
                &profile,
                &confirmed,
                allowed,
            )
            .expect("explicit native"),
            SelectedProtocol::Native
        );
        let error =
            select_protocol_with_profile(ProtocolPreference::Auto, &profile, &confirmed, blocked)
                .expect_err("no silent native");
        assert_eq!(error, ProtocolSelectionError::JsonFallbackDisabled);

        let unknown = crate::resolve_protocol_profile("lca-agent");
        assert_eq!(
            select_protocol_with_profile(ProtocolPreference::Auto, &unknown, &confirmed, allowed)
                .expect("capability native"),
            SelectedProtocol::Native
        );
    }
}
