use std::fmt;
use std::path::PathBuf;

use crate::error::ToolError;

/// Tool identifier. Names describe intent; this milestone does not run them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToolName {
    /// Read one file.
    ReadFile,
    /// List one directory.
    ListDirectory,
    /// Search inside the workspace.
    SearchWorkspace,
    /// Create or replace a file.
    WriteFile,
    /// Change an existing file.
    EditFile,
    /// Start a process.
    ExecuteCommand,
}

impl ToolName {
    /// Stable lowercase name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadFile => "read_file",
            Self::ListDirectory => "list_directory",
            Self::SearchWorkspace => "search_workspace",
            Self::WriteFile => "write_file",
            Self::EditFile => "edit_file",
            Self::ExecuteCommand => "execute_command",
        }
    }

    /// Writes, edits, and process execution change the machine.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::WriteFile | Self::EditFile | Self::ExecuteCommand
        )
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Arguments that belong with a [`ToolName`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolArguments {
    /// A workspace-relative or absolute path.
    Path {
        /// Caller-supplied path.
        path: PathBuf,
    },
    /// A search query. It is stored trimmed.
    Search {
        /// Query text.
        query: String,
    },
    /// A command line. The executor must not print or run it.
    Command {
        /// Caller-supplied command text.
        command: String,
    },
}

/// One tool invocation proposed by a future agent loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRequest {
    name: ToolName,
    arguments: ToolArguments,
}

impl ToolRequest {
    /// Request to read `path`.
    #[must_use]
    pub fn read_file(path: PathBuf) -> Self {
        Self {
            name: ToolName::ReadFile,
            arguments: ToolArguments::Path { path },
        }
    }

    /// Request to list `path`.
    #[must_use]
    pub fn list_directory(path: PathBuf) -> Self {
        Self {
            name: ToolName::ListDirectory,
            arguments: ToolArguments::Path { path },
        }
    }

    /// Request to search the workspace. The query is trimmed.
    #[must_use]
    pub fn search(query: impl Into<String>) -> Self {
        let query = query.into();
        Self {
            name: ToolName::SearchWorkspace,
            arguments: ToolArguments::Search {
                query: query.trim().to_owned(),
            },
        }
    }

    /// Request to write `path`. Authorization denies it in this milestone.
    #[must_use]
    pub fn write_file(path: PathBuf) -> Self {
        Self {
            name: ToolName::WriteFile,
            arguments: ToolArguments::Path { path },
        }
    }

    /// Request to edit `path`. Authorization denies it in this milestone.
    #[must_use]
    pub fn edit_file(path: PathBuf) -> Self {
        Self {
            name: ToolName::EditFile,
            arguments: ToolArguments::Path { path },
        }
    }

    /// Request to run a command. Authorization denies it in this milestone.
    #[must_use]
    pub fn execute_command(command: impl Into<String>) -> Self {
        Self {
            name: ToolName::ExecuteCommand,
            arguments: ToolArguments::Command {
                command: command.into(),
            },
        }
    }

    /// Builds a request when the name and arguments match.
    pub fn try_new(name: ToolName, arguments: ToolArguments) -> Result<Self, ToolError> {
        if arguments_match(name, &arguments) {
            Ok(Self { name, arguments })
        } else {
            Err(ToolError::InvalidRequest {
                message: "tool arguments do not match the tool".to_owned(),
            })
        }
    }

    /// Tool name.
    #[must_use]
    pub const fn name(&self) -> ToolName {
        self.name
    }

    /// Arguments.
    #[must_use]
    pub const fn arguments(&self) -> &ToolArguments {
        &self.arguments
    }
}

pub(crate) fn arguments_match(name: ToolName, arguments: &ToolArguments) -> bool {
    matches!(
        (name, arguments),
        (
            ToolName::ReadFile | ToolName::ListDirectory | ToolName::WriteFile | ToolName::EditFile,
            ToolArguments::Path { .. }
        ) | (ToolName::SearchWorkspace, ToolArguments::Search { .. })
            | (ToolName::ExecuteCommand, ToolArguments::Command { .. })
    )
}

/// Successful tool output. No executor in this milestone constructs one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    tool: ToolName,
    output: String,
}

impl ToolResult {
    /// Builds a result value for a later milestone.
    #[must_use]
    pub fn new(tool: ToolName, output: impl Into<String>) -> Self {
        Self {
            tool,
            output: output.into(),
        }
    }

    /// Tool that produced the output.
    #[must_use]
    pub const fn tool(&self) -> ToolName {
        self.tool
    }

    /// Output text.
    #[must_use]
    pub fn output(&self) -> &str {
        &self.output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_arguments_are_rejected() {
        let error = ToolRequest::try_new(
            ToolName::ReadFile,
            ToolArguments::Command {
                command: "ignored".to_owned(),
            },
        )
        .expect_err("mismatch");
        assert!(matches!(error, ToolError::InvalidRequest { .. }));
    }

    #[test]
    fn search_query_is_trimmed() {
        let request = ToolRequest::search("  find main  ");
        assert_eq!(
            request.arguments(),
            &ToolArguments::Search {
                query: "find main".to_owned()
            }
        );
    }
}
