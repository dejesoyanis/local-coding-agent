use serde_json::{Value, json};

use crate::action::schema;

/// Largest argument document accepted for the built-in diagnostic tool, in bytes.
pub const MAX_ARGUMENT_BYTES: usize = 8 * 1024;

const MAX_NAME_LEN: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 4 * 1024;
const MAX_ARGUMENT_LIMIT: usize = 64 * 1024;

/// Coarse permission recorded on a registry entry.
///
/// Only [`Self::Diagnostic`] is granted. The other categories exist so a registered tool
/// is not authorized merely because it was inserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PermissionCategory {
    /// Harmless diagnostic proposal.
    Diagnostic,
    /// Workspace inspection. Not granted in this milestone.
    WorkspaceRead,
    /// Workspace or process mutation. Not granted in this milestone.
    WorkspaceMutation,
}

/// Whether a tool would change the machine if a later milestone executed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolEffect {
    /// The tool would not modify files or start a process.
    ReadOnly,
    /// The tool would modify files or start a process.
    Mutating,
}

/// Why a tool could not be registered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// The name, description, schema, or limit was rejected.
    #[error("{message}")]
    Invalid {
        /// Static explanation. It does not include argument values.
        message: String,
    },
    /// The registry already has this exact name.
    #[error("tool `{name}` is already registered")]
    DuplicateName {
        /// Tool name.
        name: String,
    },
}

impl RegistryError {
    /// Stable classification.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "invalid_tool",
            Self::DuplicateName { .. } => "duplicate_tool",
        }
    }
}

/// One controller-owned tool definition.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredTool {
    name: String,
    description: String,
    schema: Value,
    permission: PermissionCategory,
    effect: ToolEffect,
    max_argument_bytes: usize,
}

impl RegisteredTool {
    /// Validates a definition. Registration does not authorize the tool.
    pub fn try_new(
        name: impl Into<String>,
        description: impl Into<String>,
        schema: Value,
        permission: PermissionCategory,
        effect: ToolEffect,
        max_argument_bytes: usize,
    ) -> Result<Self, RegistryError> {
        let name = name.into();
        let description = description.into();
        if !valid_name(&name) {
            return Err(invalid(
                "tool name must be 1..=64 bytes, start with an ASCII letter, and contain only ASCII letters, digits, or underscore",
            ));
        }
        let description_len = description.chars().count();
        if description_len == 0 || description_len > MAX_DESCRIPTION_CHARS {
            return Err(invalid(
                "tool description must be from 1 through 4096 characters",
            ));
        }
        if max_argument_bytes == 0 || max_argument_bytes > MAX_ARGUMENT_LIMIT {
            return Err(invalid("argument byte limit must be from 1 through 65536"));
        }
        schema::ensure_supported(&schema).map_err(invalid)?;
        Ok(Self {
            name,
            description,
            schema,
            permission,
            effect,
            max_argument_bytes,
        })
    }

    /// Exact tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Description advertised to a model.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// JSON schema enforced by the validator.
    #[must_use]
    pub const fn schema(&self) -> &Value {
        &self.schema
    }

    /// Permission category. This is not an authorization decision.
    #[must_use]
    pub const fn permission(&self) -> PermissionCategory {
        self.permission
    }

    /// Read-only or mutating classification.
    #[must_use]
    pub const fn effect(&self) -> ToolEffect {
        self.effect
    }

    /// Maximum accepted size of the argument JSON, in bytes.
    #[must_use]
    pub const fn max_argument_bytes(&self) -> usize {
        self.max_argument_bytes
    }
}

/// The tools the controller knows.
///
/// Lookup is exact. `diagnostic_echo` does not match `Diagnostic_Echo`.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolRegistry {
    tools: Vec<RegisteredTool>,
}

impl ToolRegistry {
    /// A registry with no tools. Every proposal is rejected until one is inserted.
    #[must_use]
    pub const fn empty() -> Self {
        Self { tools: Vec::new() }
    }

    /// The milestone registry. It contains only `diagnostic_echo`.
    pub fn diagnostic() -> Result<Self, RegistryError> {
        let mut registry = Self { tools: Vec::new() };
        registry.insert(diagnostic_echo()?)?;
        Ok(registry)
    }

    /// Adds a tool. A duplicate exact name is rejected.
    pub fn insert(&mut self, tool: RegisteredTool) -> Result<(), RegistryError> {
        if self.get(tool.name()).is_some() {
            return Err(RegistryError::DuplicateName {
                name: tool.name().to_owned(),
            });
        }
        self.tools.push(tool);
        Ok(())
    }

    /// Exact name lookup.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RegisteredTool> {
        self.tools.iter().find(|tool| tool.name() == name)
    }

    /// Tools in registration order.
    pub fn iter(&self) -> impl Iterator<Item = &RegisteredTool> {
        self.tools.iter()
    }
}

fn diagnostic_echo() -> Result<RegisteredTool, RegistryError> {
    RegisteredTool::try_new(
        "diagnostic_echo",
        "Return the provided message. This diagnostic tool is validated and is not executed.",
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["message"],
            "properties": {
                "message": {
                    "type": "string",
                    "maxLength": 1024
                }
            }
        }),
        PermissionCategory::Diagnostic,
        ToolEffect::ReadOnly,
        MAX_ARGUMENT_BYTES,
    )
}

fn invalid(message: impl Into<String>) -> RegistryError {
    RegistryError::Invalid {
        message: message.into(),
    }
}

fn valid_name(name: &str) -> bool {
    let mut characters = name.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    name.len() <= MAX_NAME_LEN
        && first.is_ascii_alphabetic()
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_registry_contains_only_the_echo_tool() {
        let registry = ToolRegistry::diagnostic().expect("registry");
        let names: Vec<&str> = registry.iter().map(RegisteredTool::name).collect();
        assert_eq!(names, vec!["diagnostic_echo"]);
        let tool = registry.get("diagnostic_echo").expect("echo");
        assert_eq!(tool.permission(), PermissionCategory::Diagnostic);
        assert_eq!(tool.effect(), ToolEffect::ReadOnly);
        assert!(registry.get("Diagnostic_Echo").is_none());
        assert!(registry.get("diagnostic_echo ").is_none());
        assert!(registry.get("execute_command").is_none());
    }

    #[test]
    fn duplicate_and_unsupported_tools_are_rejected() {
        let mut registry = ToolRegistry::diagnostic().expect("registry");
        let again = diagnostic_echo().expect("echo");
        let error = registry.insert(again).expect_err("duplicate");
        assert_eq!(error.kind(), "duplicate_tool");

        let error = RegisteredTool::try_new(
            "read_file",
            "read",
            json!({"type": "object", "properties": {"path": {"type": "string", "pattern": ".*"}}, "required": ["path"]}),
            PermissionCategory::WorkspaceRead,
            ToolEffect::ReadOnly,
            128,
        )
        .expect_err("pattern");
        assert_eq!(error.kind(), "invalid_tool");
        assert!(error.to_string().contains("pattern"), "{error}");
    }
}
