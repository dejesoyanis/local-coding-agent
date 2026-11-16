/// How much a backend said about one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityStatus {
    /// The backend explicitly listed this capability.
    Confirmed,
    /// The backend provided a capability list and this capability was not in it.
    NotReported,
    /// The backend did not provide information this crate can interpret.
    Unknown,
}

impl CapabilityStatus {
    /// Stable name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::NotReported => "not_reported",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for CapabilityStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Pieces of a capability report before sanitizing.
///
/// Adapters fill only values the backend returned. [`ModelCapabilities::from_parts`]
/// drops blanks and sorts unrecognized names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityParts {
    /// Chat or completion support.
    pub chat: CapabilityStatus,
    /// Tool-calling support.
    pub tools: CapabilityStatus,
    /// JSON-mode support.
    pub json_mode: CapabilityStatus,
    /// Context length in tokens, when the backend reported one.
    pub context_length: Option<u64>,
    /// Model family, when the backend reported one.
    pub family: Option<String>,
    /// Parameter size label, when the backend reported one.
    pub parameter_size: Option<String>,
    /// Quantization label, when the backend reported one.
    pub quantization: Option<String>,
    /// Capability names this crate does not interpret.
    pub unrecognized: Vec<String>,
}

impl Default for CapabilityParts {
    fn default() -> Self {
        Self {
            chat: CapabilityStatus::Unknown,
            tools: CapabilityStatus::Unknown,
            json_mode: CapabilityStatus::Unknown,
            context_length: None,
            family: None,
            parameter_size: None,
            quantization: None,
            unrecognized: Vec::new(),
        }
    }
}

/// What a backend explicitly reported about a model.
///
/// Unset fields mean the information was not available. They do not mean the feature exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCapabilities {
    model: String,
    chat: CapabilityStatus,
    tools: CapabilityStatus,
    json_mode: CapabilityStatus,
    context_length: Option<u64>,
    family: Option<String>,
    parameter_size: Option<String>,
    quantization: Option<String>,
    unrecognized: Vec<String>,
}

impl ModelCapabilities {
    /// Builds a sanitized report.
    ///
    /// Blank labels and a zero context length become `None`. Unrecognized names are trimmed,
    /// sorted, and deduplicated. This constructor does not mark tools or JSON mode as confirmed.
    #[must_use]
    pub fn from_parts(model: impl Into<String>, parts: CapabilityParts) -> Self {
        let mut unrecognized: Vec<String> = parts
            .unrecognized
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect();
        unrecognized.sort();
        unrecognized.dedup();

        Self {
            model: model.into(),
            chat: parts.chat,
            tools: parts.tools,
            json_mode: parts.json_mode,
            context_length: parts.context_length.filter(|value| *value > 0),
            family: blank_to_none(parts.family),
            parameter_size: blank_to_none(parts.parameter_size),
            quantization: blank_to_none(parts.quantization),
            unrecognized,
        }
    }

    /// Model identifier that was queried.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Chat or completion support.
    #[must_use]
    pub const fn chat(&self) -> CapabilityStatus {
        self.chat
    }

    /// Tool-calling support.
    #[must_use]
    pub const fn tools(&self) -> CapabilityStatus {
        self.tools
    }

    /// JSON-mode support.
    #[must_use]
    pub const fn json_mode(&self) -> CapabilityStatus {
        self.json_mode
    }

    /// Context length in tokens, when the backend reported one.
    #[must_use]
    pub const fn context_length(&self) -> Option<u64> {
        self.context_length
    }

    /// Model family, when the backend reported one.
    #[must_use]
    pub fn family(&self) -> Option<&str> {
        self.family.as_deref()
    }

    /// Parameter size label, when the backend reported one.
    #[must_use]
    pub fn parameter_size(&self) -> Option<&str> {
        self.parameter_size.as_deref()
    }

    /// Quantization label, when the backend reported one.
    #[must_use]
    pub fn quantization(&self) -> Option<&str> {
        self.quantization.as_deref()
    }

    /// Capability names the backend listed and this crate does not interpret.
    #[must_use]
    pub fn unrecognized(&self) -> &[String] {
        &self.unrecognized
    }
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_owned())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizing_drops_blanks_and_sorts_unknown_names() {
        let report = ModelCapabilities::from_parts(
            "lca-agent",
            CapabilityParts {
                chat: CapabilityStatus::Confirmed,
                tools: CapabilityStatus::NotReported,
                json_mode: CapabilityStatus::Unknown,
                context_length: Some(0),
                family: Some("  ".to_owned()),
                parameter_size: Some(" 30B ".to_owned()),
                quantization: Some("".to_owned()),
                unrecognized: vec![
                    "vision".to_owned(),
                    " vision ".to_owned(),
                    "insert".to_owned(),
                ],
            },
        );

        assert_eq!(report.model(), "lca-agent");
        assert_eq!(report.chat(), CapabilityStatus::Confirmed);
        assert_eq!(report.tools(), CapabilityStatus::NotReported);
        assert_eq!(report.json_mode(), CapabilityStatus::Unknown);
        assert_eq!(report.context_length(), None);
        assert_eq!(report.family(), None);
        assert_eq!(report.parameter_size(), Some("30B"));
        assert_eq!(report.quantization(), None);
        assert_eq!(
            report.unrecognized(),
            &["insert".to_owned(), "vision".to_owned()]
        );
    }

    #[test]
    fn default_parts_do_not_confirm_tools_or_json_mode() {
        let report = ModelCapabilities::from_parts("model", CapabilityParts::default());
        assert_eq!(report.tools(), CapabilityStatus::Unknown);
        assert_eq!(report.json_mode(), CapabilityStatus::Unknown);
        assert_eq!(report.chat(), CapabilityStatus::Unknown);
        assert!(report.unrecognized().is_empty());
    }
}
