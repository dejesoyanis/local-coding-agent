//! UTF-8 file reads inside the sandbox.

use crate::fs::limits::FsLimits;
use crate::fs_error::{FsError, display_path};
use crate::sandbox::{WorkspaceSandbox, read_resolved_file};

/// Bytes from one text file. A truncated result is a prefix, not the whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResult {
    /// Workspace-relative path.
    pub path: String,
    /// UTF-8 text. Incomplete when `truncated` is true.
    pub content: String,
    /// Whether `content` is only a prefix of the file.
    pub truncated: bool,
    /// File length in bytes before truncation.
    pub file_bytes: u64,
}

pub(crate) fn read_file(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    path: &str,
) -> Result<ReadResult, FsError> {
    if !limits.read_enabled() {
        return Err(FsError::ToolDisabled {
            tool: "read_file".to_owned(),
        });
    }
    let resolved = sandbox.resolve(path)?;
    if !resolved.is_file() {
        return Err(FsError::NotAFile {
            path: display_path(path),
        });
    }
    let bytes = read_resolved_file(&resolved, limits.max_file_size_bytes())?;
    if bytes.contains(&0) {
        return Err(FsError::BinaryFile {
            path: resolved.relative().to_owned(),
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| FsError::InvalidUtf8 {
        path: resolved.relative().to_owned(),
    })?;
    let file_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let limit = usize::try_from(limits.max_response_bytes()).unwrap_or(usize::MAX);
    if text.len() > limit {
        let mut end = limit.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        return Ok(ReadResult {
            path: resolved.relative().to_owned(),
            content: text[..end].to_owned(),
            truncated: true,
            file_bytes,
        });
    }
    Ok(ReadResult {
        path: resolved.relative().to_owned(),
        content: text.to_owned(),
        truncated: false,
        file_bytes,
    })
}
