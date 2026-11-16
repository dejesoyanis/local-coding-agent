//! Non-recursive directory listing inside the sandbox.

use crate::fs::limits::{FsLimits, MAX_DIRECTORY_SCAN};
use crate::fs::read::{privacy_gate, read_gate};
use crate::fs_error::{FsError, display_path};
use crate::privacy::deny_overrides;
use crate::sandbox::WorkspaceSandbox;

/// One directory entry. `kind` is `file`, `directory`, `reparse`, or `error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// File name.
    pub name: String,
    /// `file`, `directory`, `reparse`, or `error`.
    pub kind: String,
    /// Workspace-relative path using `/`.
    pub path: String,
    /// File length when the entry is a regular file.
    pub size: Option<u64>,
    /// Why the entry could not be classified, when `kind` is `error`.
    pub error: Option<String>,
}

/// Sorted listing. `truncated` means the directory had more entries than the limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListResult {
    /// Directory that was listed.
    pub path: String,
    /// Entries in name order, after the limit is applied.
    pub entries: Vec<DirectoryEntry>,
    /// Whether entries were omitted after sorting.
    pub truncated: bool,
}

pub(crate) fn list_directory(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    path: &str,
) -> Result<ListResult, FsError> {
    deny_overrides(&[read_gate(limits, "list_directory")])?;
    let resolved = sandbox.resolve_visible(path)?;
    deny_overrides(&[privacy_gate(sandbox, resolved.relative())])?;
    if !resolved.is_dir() {
        return Err(FsError::NotADirectory {
            path: display_path(path),
        });
    }
    let children = sandbox.list_children(resolved.relative(), MAX_DIRECTORY_SCAN)?;
    let mut entries = Vec::with_capacity(children.len());
    for child in children {
        let child_path = child_relative(resolved.relative(), &child.name);
        if sandbox.privacy().blocks(&child_path) {
            continue;
        }
        if !safe_entry_name(&child.name) {
            entries.push(DirectoryEntry {
                name: child.name,
                kind: "error".to_owned(),
                path: child_path,
                size: None,
                error: Some("name is not a safe directory entry".to_owned()),
            });
            continue;
        }
        entries.push(DirectoryEntry {
            name: child.name,
            kind: child.kind,
            path: child_path,
            size: child.size,
            error: None,
        });
    }
    entries.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.kind.cmp(&right.kind))
    });
    let truncated = entries.len() > limits.max_directory_entries();
    entries.truncate(limits.max_directory_entries());
    Ok(ListResult {
        path: resolved.relative().to_owned(),
        entries,
        truncated,
    })
}

fn child_relative(parent: &str, name: &str) -> String {
    if parent == "." {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn safe_entry_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(':')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(|character| character.is_control())
}
