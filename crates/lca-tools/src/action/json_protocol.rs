use serde_json::Value;

use crate::action::model::ActionSource;

/// Version of the JSON action document LCA-01C accepts.
///
/// Version 1 contains only `protocol_version` and `actions`. [`parse_action_document`]
/// still accepts only this version, so single-turn callers keep the LCA-01C contract.
pub const PROTOCOL_VERSION: u64 = 1;

/// Version of the multi-turn JSON document.
///
/// Version 2 adds an optional `final_answer` string. It is required when `actions` is
/// empty and forbidden when `actions` is not empty. [`parse_action_document`] rejects it.
pub const AGENT_PROTOCOL_VERSION: u64 = 2;

/// Largest accepted JSON document, in bytes.
pub const MAX_PROTOCOL_BYTES: usize = 64 * 1024;

const MAX_FIELD_CHARS: usize = 64;

/// One action object inside a versioned JSON document.
///
/// This value is not an [`super::AgentAction`] and it is not validated.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedAction {
    tool: String,
    arguments: Value,
}

impl ParsedAction {
    /// Tool name from the document.
    #[must_use]
    pub fn tool(&self) -> &str {
        &self.tool
    }

    /// Raw argument JSON.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }

    /// Origin recorded when the controller turns this into a proposal.
    #[must_use]
    pub const fn source(&self) -> ActionSource {
        ActionSource::StructuredJson
    }
}

/// One parsed JSON action document.
///
/// Version 1 has no [`Self::final_answer`]. Version 2 carries one only when `actions` is empty.
#[derive(Debug, Clone, PartialEq)]
pub struct ActionDocument {
    version: u64,
    actions: Vec<ParsedAction>,
    final_answer: Option<String>,
}

impl ActionDocument {
    /// `protocol_version` from the document.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Actions in document order.
    #[must_use]
    pub fn actions(&self) -> &[ParsedAction] {
        &self.actions
    }

    /// Final answer from protocol version 2. Absent on version 1.
    #[must_use]
    pub fn final_answer(&self) -> Option<&str> {
        self.final_answer.as_deref()
    }

    /// Consumes the document and returns the actions.
    #[must_use]
    pub fn into_actions(self) -> Vec<ParsedAction> {
        self.actions
    }
}

/// Why a byte string was not accepted as the action document.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JsonProtocolError {
    /// The document exceeds [`MAX_PROTOCOL_BYTES`].
    #[error("JSON action document exceeds {limit} bytes")]
    TooLarge {
        /// Configured limit.
        limit: usize,
    },
    /// The bytes are not one JSON value.
    #[error("response was not valid JSON")]
    InvalidJson,
    /// The JSON value is not an object.
    #[error("JSON action document must be an object")]
    NotAnObject,
    /// The text is a markdown fence. The interior is not parsed.
    #[error("markdown is not a JSON action document")]
    MarkdownFence,
    /// `protocol_version` is absent.
    #[error("JSON action document is missing protocol_version")]
    MissingProtocolVersion,
    /// `protocol_version` is present and is not an integer.
    #[error("protocol_version must be an integer")]
    InvalidProtocolVersion,
    /// `protocol_version` is an integer other than [`PROTOCOL_VERSION`].
    #[error("protocol version {version} is not supported")]
    UnsupportedProtocolVersion {
        /// Version from the document.
        version: u64,
    },
    /// The envelope contains a field other than `protocol_version` or `actions`.
    #[error("JSON action document contains unknown field `{field}`")]
    UnknownField {
        /// Field name, capped for diagnostics.
        field: String,
    },
    /// A required envelope field other than the version is absent.
    #[error("JSON action document is missing {field}")]
    MissingField {
        /// Field name.
        field: &'static str,
    },
    /// `actions` is not an array, or one entry is not an object with the required fields.
    #[error("action {index} was rejected: {message}")]
    InvalidAction {
        /// Zero-based index.
        index: usize,
        /// Static explanation.
        message: String,
    },
    /// `actions` itself is not an array.
    #[error("actions must be an array")]
    InvalidActions,
    /// The document contains more actions than the milestone allows.
    #[error("JSON action document contains {actual} actions; limit is {limit}")]
    TooManyActions {
        /// Configured limit.
        limit: usize,
        /// Number of actions in the document.
        actual: usize,
    },
    /// `final_answer` is present together with one or more actions.
    #[error("final_answer is only valid when actions is empty")]
    FinalAnswerConflict,
    /// `final_answer` is present and is not a string.
    #[error("final_answer must be a string")]
    InvalidFinalAnswer,
    /// Protocol version 2 has an empty action list and no `final_answer`.
    #[error("an empty action list requires final_answer")]
    MissingFinalAnswer,
}

impl JsonProtocolError {
    /// Stable classification. The document body is not part of it.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "too_large",
            Self::InvalidJson => "invalid_json",
            Self::NotAnObject => "not_an_object",
            Self::MarkdownFence => "markdown",
            Self::MissingProtocolVersion => "missing_version",
            Self::InvalidProtocolVersion => "invalid_version",
            Self::UnsupportedProtocolVersion { .. } => "unsupported_version",
            Self::UnknownField { .. } => "unknown_field",
            Self::MissingField { .. } => "missing_field",
            Self::InvalidAction { .. } => "invalid_action",
            Self::InvalidActions => "invalid_actions",
            Self::TooManyActions { .. } => "too_many_actions",
            Self::FinalAnswerConflict => "final_answer_conflict",
            Self::InvalidFinalAnswer => "invalid_final_answer",
            Self::MissingFinalAnswer => "missing_final_answer",
        }
    }
}

/// Parses a complete JSON action document.
///
/// The input must be the whole response. Markdown fences are rejected before parsing.
/// Invalid JSON is not repaired, and a JSON value embedded in prose is not extracted.
pub fn parse_action_document(text: &str) -> Result<Vec<ParsedAction>, JsonProtocolError> {
    Ok(decode_document(text, false)?.actions)
}

/// Parses a version 1 or version 2 action document.
///
/// This is the same decoder as [`parse_action_document`]. Version 2 is accepted only here
/// so existing single-turn callers still reject `final_answer` and version 2.
pub fn parse_agent_document(text: &str) -> Result<ActionDocument, JsonProtocolError> {
    decode_document(text, true)
}

fn decode_document(text: &str, allow_v2: bool) -> Result<ActionDocument, JsonProtocolError> {
    if text.len() > MAX_PROTOCOL_BYTES {
        return Err(JsonProtocolError::TooLarge {
            limit: MAX_PROTOCOL_BYTES,
        });
    }
    if text.trim_start().starts_with("```") {
        return Err(JsonProtocolError::MarkdownFence);
    }
    let value = serde_json::from_str::<Value>(text).map_err(|_| JsonProtocolError::InvalidJson)?;
    interpret_document(value, allow_v2)
}

fn interpret_document(value: Value, allow_v2: bool) -> Result<ActionDocument, JsonProtocolError> {
    let Some(object) = value.as_object() else {
        return Err(JsonProtocolError::NotAnObject);
    };
    let Some(version_value) = object.get("protocol_version") else {
        return Err(JsonProtocolError::MissingProtocolVersion);
    };
    let version = match version_token(version_value) {
        Some(PROTOCOL_VERSION) => PROTOCOL_VERSION,
        Some(AGENT_PROTOCOL_VERSION) if allow_v2 => AGENT_PROTOCOL_VERSION,
        Some(_) | None => return Err(version_error(version_value)),
    };
    for key in object.keys() {
        let allowed = key == "protocol_version"
            || key == "actions"
            || (version == AGENT_PROTOCOL_VERSION && key == "final_answer");
        if !allowed {
            return Err(JsonProtocolError::UnknownField { field: cap(key) });
        }
    }
    let Some(actions) = object.get("actions") else {
        return Err(JsonProtocolError::MissingField { field: "actions" });
    };
    let Some(actions) = actions.as_array() else {
        return Err(JsonProtocolError::InvalidActions);
    };
    if actions.len() > super::MAX_ACTIONS {
        return Err(JsonProtocolError::TooManyActions {
            limit: super::MAX_ACTIONS,
            actual: actions.len(),
        });
    }
    let parsed = actions
        .iter()
        .enumerate()
        .map(|(index, action)| parse_action(index, action))
        .collect::<Result<Vec<_>, _>>()?;
    let final_answer = match object.get("final_answer") {
        None => None,
        Some(Value::String(text)) => Some(text.clone()),
        Some(_) => return Err(JsonProtocolError::InvalidFinalAnswer),
    };
    if version == AGENT_PROTOCOL_VERSION {
        if parsed.is_empty() && final_answer.is_none() {
            return Err(JsonProtocolError::MissingFinalAnswer);
        }
        if !parsed.is_empty() && final_answer.is_some() {
            return Err(JsonProtocolError::FinalAnswerConflict);
        }
    }
    Ok(ActionDocument {
        version,
        actions: parsed,
        final_answer,
    })
}

fn version_token(version: &Value) -> Option<u64> {
    let text = serde_json::to_string(version).ok()?;
    let number = version.as_u64()?;
    if text == number.to_string() {
        Some(number)
    } else {
        None
    }
}

fn version_error(version: &Value) -> JsonProtocolError {
    match (version.as_u64(), serde_json::to_string(version).ok()) {
        (Some(number), Some(text)) if text == number.to_string() => {
            JsonProtocolError::UnsupportedProtocolVersion { version: number }
        }
        _ => JsonProtocolError::InvalidProtocolVersion,
    }
}

fn parse_action(index: usize, value: &Value) -> Result<ParsedAction, JsonProtocolError> {
    let Some(object) = value.as_object() else {
        return Err(action_error(index, "action must be an object"));
    };
    for key in object.keys() {
        if key != "tool" && key != "arguments" {
            return Err(action_error(index, format!("unknown field `{}`", cap(key))));
        }
    }
    let Some(tool) = object.get("tool").and_then(Value::as_str) else {
        return Err(action_error(index, "tool must be a string"));
    };
    if tool.is_empty() {
        return Err(action_error(index, "tool name must not be empty"));
    }
    let Some(arguments) = object.get("arguments") else {
        return Err(action_error(index, "missing arguments"));
    };
    Ok(ParsedAction {
        tool: tool.to_owned(),
        arguments: arguments.clone(),
    })
}

fn action_error(index: usize, message: impl Into<String>) -> JsonProtocolError {
    JsonProtocolError::InvalidAction {
        index,
        message: message.into(),
    }
}

fn cap(field: &str) -> String {
    field.chars().take(MAX_FIELD_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_documents_keep_action_order() {
        let parsed = parse_action_document(
            r#"{"protocol_version":1,"actions":[{"tool":"diagnostic_echo","arguments":{"message":"one"}},{"tool":"diagnostic_echo","arguments":{"message":"two"}}]}"#,
        )
        .expect("document");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].tool(), "diagnostic_echo");
        assert_eq!(parsed[0].arguments()["message"], "one");
        assert_eq!(parsed[1].arguments()["message"], "two");
        assert_eq!(parsed[0].source(), ActionSource::StructuredJson);
    }

    #[test]
    fn strict_failures_do_not_repair_or_extract_json() {
        let markdown = "```json\n{\"protocol_version\":1,\"actions\":[]}\n```";
        assert_eq!(
            parse_action_document(markdown).expect_err("fence").kind(),
            "markdown"
        );
        let indented = "\n```\n{\"protocol_version\":1,\"actions\":[]}\n```";
        assert_eq!(
            parse_action_document(indented)
                .expect_err("indented")
                .kind(),
            "markdown"
        );

        let prose = "Here is the call:\n{\"protocol_version\":1,\"actions\":[]}";
        let error = parse_action_document(prose).expect_err("prose");
        assert_eq!(error.kind(), "invalid_json");
        assert!(!error.to_string().contains("protocol_version"), "{error}");

        assert_eq!(
            parse_action_document("{").expect_err("broken").kind(),
            "invalid_json"
        );
        assert_eq!(
            parse_action_document("Sure, I can help with that.")
                .expect_err("text")
                .kind(),
            "invalid_json"
        );
        assert_eq!(
            parse_action_document(r#"{"actions":[]}"#)
                .expect_err("version")
                .kind(),
            "missing_version"
        );
        assert_eq!(
            parse_action_document(r#"{"protocol_version":"1","actions":[]}"#)
                .expect_err("type")
                .kind(),
            "invalid_version"
        );
        assert_eq!(
            parse_action_document(r#"{"protocol_version":2,"actions":[]}"#)
                .expect_err("version 2")
                .kind(),
            "unsupported_version"
        );
        assert_eq!(
            parse_action_document(r#"{"protocol_version":1.5,"actions":[]}"#)
                .expect_err("fraction")
                .kind(),
            "invalid_version"
        );
        assert_eq!(
            parse_action_document(r#"{"protocol_version":1,"actions":[],"note":"x"}"#)
                .expect_err("extra")
                .kind(),
            "unknown_field"
        );
        let identified = parse_action_document(
            r#"{"protocol_version":1,"actions":[{"tool":"diagnostic_echo","arguments":{},"id":99}]}"#,
        )
        .expect_err("model id");
        assert_eq!(identified.kind(), "invalid_action");
        assert!(
            identified.to_string().contains("unknown field"),
            "{identified}"
        );
    }

    #[test]
    fn size_and_count_limits_are_enforced() {
        let huge = "x".repeat(MAX_PROTOCOL_BYTES + 1);
        assert_eq!(
            parse_action_document(&huge).expect_err("size").kind(),
            "too_large"
        );

        let actions = vec![json!({"tool": "diagnostic_echo", "arguments": {}}); 9];
        let document = json!({"protocol_version": 1, "actions": actions}).to_string();
        let error = parse_action_document(&document).expect_err("count");
        assert_eq!(error.kind(), "too_many_actions");
    }

    #[test]
    fn version_two_accepts_a_final_answer_only_on_the_agent_decoder() {
        let finished = r#"{"protocol_version":2,"actions":[],"final_answer":"done"}"#;
        assert_eq!(
            parse_action_document(finished)
                .expect_err("single turn")
                .kind(),
            "unsupported_version"
        );
        let document = parse_agent_document(finished).expect("agent");
        assert_eq!(document.version(), 2);
        assert!(document.actions().is_empty());
        assert_eq!(document.final_answer(), Some("done"));

        let call = r#"{"protocol_version":2,"actions":[{"tool":"read_file","arguments":{"path":"a.rs"}}]}"#;
        let document = parse_agent_document(call).expect("call");
        assert_eq!(document.actions().len(), 1);
        assert_eq!(document.final_answer(), None);

        assert_eq!(
            parse_agent_document(r#"{"protocol_version":2,"actions":[]}"#)
                .expect_err("missing")
                .kind(),
            "missing_final_answer"
        );
        assert_eq!(
            parse_agent_document(
                r#"{"protocol_version":2,"actions":[{"tool":"read_file","arguments":{}}],"final_answer":"x"}"#
            )
            .expect_err("conflict")
            .kind(),
            "final_answer_conflict"
        );
        assert_eq!(
            parse_agent_document(r#"{"protocol_version":1,"actions":[],"final_answer":"x"}"#)
                .expect_err("v1 field")
                .kind(),
            "unknown_field"
        );
    }
}
