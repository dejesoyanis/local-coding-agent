//! Non-recursive directory listing inside the sandbox.

use crate::fs::limits::{FsLimits, MAX_DIRECTORY_SCAN};
use crate::fs_error::{FsError, display_path};
use crate::sandbox::{WorkspaceSandbox, is_reparse};

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
    if !limits.read_enabled() {
        return Err(FsError::ToolDisabled {
            tool: "list_directory".to_owned(),
        });
    }
    let resolved = sandbox.resolve(path)?;
    if !resolved.is_dir() {
        return Err(FsError::NotADirectory {
            path: display_path(path),
        });
    }
    let before = resolved.identity();
    let mut raw_entries = Vec::new();
    let reader = std::fs::read_dir(resolved.absolute()).map_err(|error| FsError::Io {
        path: resolved.relative().to_owned(),
        message: error.to_string(),
    })?;
    for entry in reader {
        let entry = entry.map_err(|error| FsError::Io {
            path: resolved.relative().to_owned(),
            message: error.to_string(),
        })?;
        if raw_entries.len() == MAX_DIRECTORY_SCAN {
            return Err(FsError::LimitExceeded {
                message: "directory is too large to list deterministically".to_owned(),
            });
        }
        raw_entries.push(entry);
    }
    let after = std::fs::symlink_metadata(resolved.absolute()).map_err(|error| FsError::Io {
        path: resolved.relative().to_owned(),
        message: error.to_string(),
    })?;
    if is_reparse(&after) {
        return Err(FsError::ReparseDenied {
            path: resolved.relative().to_owned(),
        });
    }
    let after_id = crate::sandbox::file_identity(&after, resolved.relative())?;
    if after_id != before {
        return Err(FsError::FileChanged {
            path: resolved.relative().to_owned(),
        });
    }

    let mut entries = Vec::with_capacity(raw_entries.len());
    for entry in raw_entries {
        entries.push(classify_entry(resolved.relative(), &entry));
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

fn classify_entry(parent: &str, entry: &std::fs::DirEntry) -> DirectoryEntry {
    let raw_name = entry.file_name();
    let Some(name) = raw_name.to_str() else {
        return DirectoryEntry {
            name: raw_name.to_string_lossy().into_owned(),
            kind: "error".to_owned(),
            path: parent.to_owned(),
            size: None,
            error: Some("name is not valid Unicode".to_owned()),
        };
    };
    let child_path = child_relative(parent, name);
    if !safe_entry_name(name) {
        return DirectoryEntry {
            name: name.to_owned(),
            kind: "error".to_owned(),
            path: child_path,
            size: None,
            error: Some("name is not a safe directory entry".to_owned()),
        };
    }
    let full = entry.path();
    match std::fs::symlink_metadata(&full) {
        Ok(meta) if is_reparse(&meta) => DirectoryEntry {
            name: name.to_owned(),
            kind: "reparse".to_owned(),
            path: child_path,
            size: None,
            error: None,
        },
        Ok(meta) if meta.is_dir() => DirectoryEntry {
            name: name.to_owned(),
            kind: "directory".to_owned(),
            path: child_path,
            size: None,
            error: None,
        },
        Ok(meta) if meta.is_file() => DirectoryEntry {
            name: name.to_owned(),
            kind: "file".to_owned(),
            path: child_path,
            size: Some(meta.len()),
            error: None,
        },
        Ok(_) => DirectoryEntry {
            name: name.to_owned(),
            kind: "error".to_owned(),
            path: child_path,
            size: None,
            error: Some("entry is neither a file nor a directory".to_owned()),
        },
        Err(error) => DirectoryEntry {
            name: name.to_owned(),
            kind: "error".to_owned(),
            path: child_path,
            size: None,
            error: Some(error.to_string()),
        },
    }
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
