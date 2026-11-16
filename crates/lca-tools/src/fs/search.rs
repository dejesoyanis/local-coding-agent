//! Literal text search. Regular expressions are not evaluated.

use crate::fs::limits::{FsLimits, MAX_DIRECTORY_SCAN};
use crate::fs::read::{privacy_gate, read_gate};
use crate::fs_error::{FsError, display_path};
use crate::privacy::deny_overrides;
use crate::sandbox::{WorkspaceSandbox, read_resolved_file};

const EXCLUDED_DIRECTORIES: &[&str] = &[".git", "target", "node_modules"];
const MAX_LINE_CHARS: usize = 512;

/// One matching line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    /// Workspace-relative path using `/`.
    pub path: String,
    /// 1-based line number.
    pub line: u64,
    /// Line text, capped for the response.
    pub text: String,
}

/// Search output. `truncated` means a limit stopped the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// Matches in walk order: directory names sorted, then line number.
    pub matches: Vec<SearchMatch>,
    /// Whether a match, file, or byte limit stopped the search.
    pub truncated: bool,
    /// Files whose bytes were examined.
    pub files_scanned: usize,
    /// Files skipped because they were not UTF-8 text or could not be classified.
    pub skipped: usize,
}

pub(crate) fn search_files(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    query: &str,
    path: &str,
) -> Result<SearchResult, FsError> {
    deny_overrides(&[read_gate(limits, "search_files")])?;
    if query.is_empty() || query.chars().count() > 1024 {
        return Err(FsError::InvalidArguments {
            message: "search query length is not allowed".to_owned(),
        });
    }
    if query.contains('\0') {
        return Err(FsError::InvalidArguments {
            message: "search query contains a control character".to_owned(),
        });
    }
    let resolved = sandbox.resolve_visible(path)?;
    deny_overrides(&[privacy_gate(sandbox, resolved.relative())])?;
    if !resolved.is_dir() {
        return Err(FsError::NotADirectory {
            path: display_path(path),
        });
    }
    if contains_excluded(resolved.relative()) {
        return Err(FsError::ExcludedPath {
            path: resolved.relative().to_owned(),
        });
    }
    let mut state = Walk {
        matches: Vec::new(),
        truncated: false,
        files_scanned: 0,
        skipped: 0,
        bytes_read: 0,
    };
    visit(sandbox, limits, resolved.relative(), query, &mut state)?;
    Ok(SearchResult {
        matches: state.matches,
        truncated: state.truncated,
        files_scanned: state.files_scanned,
        skipped: state.skipped,
    })
}

struct Walk {
    matches: Vec<SearchMatch>,
    truncated: bool,
    files_scanned: usize,
    skipped: usize,
    bytes_read: u64,
}

fn visit(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    directory: &str,
    query: &str,
    state: &mut Walk,
) -> Result<(), FsError> {
    if state.truncated {
        return Ok(());
    }
    let resolved = sandbox.resolve_visible(directory)?;
    if !resolved.is_dir() {
        return Err(FsError::NotADirectory {
            path: directory.to_owned(),
        });
    }
    let children = match sandbox.list_children(directory, MAX_DIRECTORY_SCAN) {
        Ok(children) => children,
        Err(FsError::LimitExceeded { .. }) => {
            state.truncated = true;
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if children.len() > MAX_DIRECTORY_SCAN {
        state.truncated = true;
        return Ok(());
    }
    let mut children = children;
    children.sort_by(|left, right| left.name.cmp(&right.name));
    for child in children {
        if state.truncated {
            break;
        }
        if child.name == "." || child.name == ".." || !safe_name(&child.name) {
            continue;
        }
        let path = if directory == "." {
            child.name.clone()
        } else {
            format!("{directory}/{}", child.name)
        };
        if sandbox.privacy().blocks(&path) {
            continue;
        }
        if child.kind == "reparse" {
            continue;
        }
        if child.kind == "directory" {
            if is_excluded_name(&child.name) {
                continue;
            }
            visit(sandbox, limits, &path, query, state)?;
            continue;
        }
        if child.kind == "file" {
            scan_file(
                sandbox,
                limits,
                &path,
                child.size.unwrap_or(0),
                query,
                state,
            )?;
        } else {
            state.skipped += 1;
        }
    }
    Ok(())
}

fn scan_file(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    path: &str,
    len: u64,
    query: &str,
    state: &mut Walk,
) -> Result<(), FsError> {
    if sandbox.privacy().blocks(path) {
        return Ok(());
    }
    if state.files_scanned >= limits.max_search_files()
        || state.bytes_read.saturating_add(len) > limits.max_search_total_bytes()
    {
        state.truncated = true;
        return Ok(());
    }
    if len > limits.max_file_size_bytes() {
        state.skipped += 1;
        return Ok(());
    }
    let resolved = match sandbox.resolve(path) {
        Ok(resolved) => resolved,
        Err(_) => {
            state.skipped += 1;
            return Ok(());
        }
    };
    if !resolved.is_file() {
        state.skipped += 1;
        return Ok(());
    }
    let bytes = match read_resolved_file(sandbox, &resolved, limits.max_file_size_bytes()) {
        Ok(bytes) => bytes,
        Err(FsError::FileChanged { .. }) => {
            return Err(FsError::FileChanged {
                path: path.to_owned(),
            });
        }
        Err(FsError::HardlinkDenied { .. } | FsError::ReparseDenied { .. }) => {
            state.skipped += 1;
            return Ok(());
        }
        Err(_) => {
            state.skipped += 1;
            return Ok(());
        }
    };
    state.bytes_read = state.bytes_read.saturating_add(bytes.len() as u64);
    if bytes.contains(&0) {
        state.skipped += 1;
        return Ok(());
    }
    let Ok(text) = std::str::from_utf8(&bytes) else {
        state.skipped += 1;
        return Ok(());
    };
    state.files_scanned += 1;
    for (index, line) in text.split('\n').enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if !line.contains(query) {
            continue;
        }
        if state.matches.len() >= limits.max_search_matches() {
            state.truncated = true;
            return Ok(());
        }
        state.matches.push(SearchMatch {
            path: resolved.relative().to_owned(),
            line: u64::try_from(index + 1).unwrap_or(u64::MAX),
            text: cap_line(line),
        });
    }
    Ok(())
}

fn cap_line(line: &str) -> String {
    if line.chars().count() <= MAX_LINE_CHARS {
        return line.to_owned();
    }
    line.chars().take(MAX_LINE_CHARS).collect()
}

fn contains_excluded(relative: &str) -> bool {
    relative != "." && relative.split('/').any(is_excluded_name)
}

fn is_excluded_name(name: &str) -> bool {
    EXCLUDED_DIRECTORIES
        .iter()
        .any(|excluded| name.eq_ignore_ascii_case(excluded))
}

fn safe_name(name: &str) -> bool {
    !name.contains(':')
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(|character| character.is_control())
}
