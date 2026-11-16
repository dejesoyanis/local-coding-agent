use serde_json::Value;

use crate::error::RuntimeError;

/// Largest accepted tool name, in bytes.
pub const MAX_TOOL_NAME_LEN: usize = 64;

/// Largest accepted tool description, in characters.
pub const MAX_TOOL_DESCRIPTION_LEN: usize = 4 * 1024;

/// Largest number of tool definitions in one request.
pub const MAX_TOOLS_PER_REQUEST: usize = 16;

/// Largest number of native tool calls accepted from one response.
///
/// The validation boundary uses the same limit. A larger array is a protocol violation
/// so a backend cannot force the controller to retain an unbounded call list.
pub const MAX_NATIVE_TOOL_CALLS: usize = 8;

/// Largest accepted JSON schema document, in bytes.
const MAX_SCHEMA_BYTES: usize = 64 * 1024;

/// How the backend should shape the assistant text.
///
/// [`Self::Text`] is the default and preserves the LCA-01B generation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseFormat {
    /// Ordinary assistant text.
    #[default]
    Text,
    /// Ask the backend to constrain assistant text to JSON.
    ///
    /// Setting this value does not mark JSON mode as a confirmed model capability.
    /// The Ollama adapter sends the string `json`, which requests syntactic JSON.
    /// It does not send a JSON Schema. The controller still validates the bytes.
    Json,
}

impl ResponseFormat {
    /// Stable name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

/// One tool definition advertised to a backend.
///
/// The parameters are a JSON schema object. This type does not check that the schema
/// is enforceable; the tool registry does that before a definition is built.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolDefinition {
    name: String,
    description: String,
    parameters: Value,
}

impl ToolDefinition {
    /// Validates and stores one definition.
    pub fn try_new(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: Value,
    ) -> Result<Self, RuntimeError> {
        let definition = Self {
            name: name.into(),
            description: description.into(),
            parameters,
        };
        definition.validate()?;
        Ok(definition)
    }

    /// Checks the transport limits. The error does not include the description or schema.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        if !valid_tool_name(&self.name) {
            return Err(RuntimeError::invalid(
                "tool name must be 1..=64 bytes, start with an ASCII letter, and contain only ASCII letters, digits, or underscore",
            ));
        }
        let description_len = self.description.chars().count();
        if description_len == 0 || description_len > MAX_TOOL_DESCRIPTION_LEN {
            return Err(RuntimeError::invalid(
                "tool description must be from 1 through 4096 characters",
            ));
        }
        if !self.parameters.is_object() {
            return Err(RuntimeError::invalid(
                "tool parameters must be a JSON object",
            ));
        }
        match serde_json::to_vec(&self.parameters) {
            Ok(bytes) if bytes.len() <= MAX_SCHEMA_BYTES => Ok(()),
            Ok(_) => Err(RuntimeError::invalid("tool parameters are too large")),
            Err(_) => Err(RuntimeError::invalid(
                "tool parameters could not be encoded",
            )),
        }
    }

    /// Tool name, compared exactly by the registry.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Description sent to the backend.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// JSON schema object sent to the backend.
    #[must_use]
    pub const fn parameters(&self) -> &Value {
        &self.parameters
    }
}

/// One tool call as the backend structured it.
///
/// Arguments stay JSON. A JSON string is not parsed again. This value is not authorized.
#[derive(Debug, Clone, PartialEq)]
pub struct RawToolCall {
    name: String,
    arguments: Value,
    id: Option<String>,
}

impl RawToolCall {
    /// Stores a name and JSON arguments without consulting a registry.
    #[must_use]
    pub fn new(name: impl Into<String>, arguments: Value) -> Self {
        Self {
            name: name.into(),
            arguments,
            id: None,
        }
    }

    /// Attaches a backend call id when the adapter preserved one.
    ///
    /// The id is not an authorization and it is not a controller action identity.
    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        let id = id.into();
        self.id = if id.is_empty() { None } else { Some(id) };
        self
    }

    /// Function name, unchanged from the backend.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Arguments as JSON. Missing arguments are an empty object at the adapter boundary.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }

    /// Backend call id, when the adapter preserved one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

pub(crate) fn valid_tool_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    name.len() <= MAX_TOOL_NAME_LEN
        && first.is_ascii_alphabetic()
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn definitions_keep_schema_objects_and_reject_bad_names() {
        let definition =
            ToolDefinition::try_new("diagnostic_echo", "echo", json!({"type": "object"}))
                .expect("definition");
        assert_eq!(definition.name(), "diagnostic_echo");
        assert!(definition.parameters().is_object());

        let cases = [
            ToolDefinition::try_new("", "echo", json!({})),
            ToolDefinition::try_new("Diagnostic-Echo", "echo", json!({})),
            ToolDefinition::try_new("1tool", "echo", json!({})),
            ToolDefinition::try_new("diagnostic_echo", "", json!({})),
            ToolDefinition::try_new("diagnostic_echo", "echo", json!("schema")),
        ];
        for case in cases {
            let error = case.expect_err("invalid definition");
            assert_eq!(error.kind(), "invalid_request");
            assert!(!error.to_string().contains("schema"), "{error}");
        }
    }
}
