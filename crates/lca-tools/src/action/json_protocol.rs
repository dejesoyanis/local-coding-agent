use serde_json::Value;

use crate::action::model::ActionSource;

/// Version of the JSON action document this milestone accepts.
pub const PROTOCOL_VERSION: u64 = 1;

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
        }
    }
}

/// Parses a complete JSON action document.
///
/// The input must be the whole response. Markdown fences are rejected before parsing.
/// Invalid JSON is not repaired, and a JSON value embedded in prose is not extracted.
pub fn parse_action_document(text: &str) -> Result<Vec<ParsedAction>, JsonProtocolError> {
    if text.len() > MAX_PROTOCOL_BYTES {
        return Err(JsonProtocolError::TooLarge {
            limit: MAX_PROTOCOL_BYTES,
        });
    }
    if text.trim_start().starts_with("```") {
        return Err(JsonProtocolError::MarkdownFence);
    }
    let value = serde_json::from_str::<Value>(text).map_err(|_| JsonProtocolError::InvalidJson)?;
    interpret_document(value)
}

fn interpret_document(value: Value) -> Result<Vec<ParsedAction>, JsonProtocolError> {
    let Some(object) = value.as_object() else {
        return Err(JsonProtocolError::NotAnObject);
    };
    for key in object.keys() {
        if key != "protocol_version" && key != "actions" {
            return Err(JsonProtocolError::UnknownField { field: cap(key) });
        }
    }
    let Some(version) = object.get("protocol_version") else {
        return Err(JsonProtocolError::MissingProtocolVersion);
    };
    if serde_json::to_string(version).ok().as_deref() != Some("1") {
        return Err(version_error(version));
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
    actions
        .iter()
        .enumerate()
        .map(|(index, action)| parse_action(index, action))
        .collect()
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
}
