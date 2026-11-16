//! Capability-based workspace root.
//!
//! The root is canonicalized once and then immutable. Every caller path is treated as
//! untrusted: only relative components are accepted, and each existing component is
//! checked with `symlink_metadata` before the walk continues. Symlinks, junctions, and
//! other reparse points are rejected rather than followed.
//!
//! On Windows, file reads open with `FILE_FLAG_OPEN_REPARSE_POINT`, so the final
//! component is not followed. Intermediate components are still subject to a
//! check-then-open race. That race is not claimed to be closed. See the LCA-01D notes.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use crate::fs_error::{FsError, display_path};
use crate::pathutil::{is_within, paths_equivalent, simplify_verbatim};
use crate::privacy::{PrivacyPolicy, lexical_relative};

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

const MAX_PATH_CHARS: usize = 4096;

/// Identity of one directory entry, used to detect a replacement between prepare and apply.
///
/// Rust 1.99 does not expose the NTFS file index on the stable channel. On Windows this
/// value is the creation time, last write time, and length. A delete-and-recreate usually
/// changes the creation time. It is not a file id, and two entries can theoretically share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FileIdentity {
    created: u64,
    modified: u64,
    len: u64,
}

impl FileIdentity {
    #[must_use]
    pub(crate) const fn created(self) -> u64 {
        self.created
    }

    #[must_use]
    pub(crate) const fn modified(self) -> u64 {
        self.modified
    }

    #[must_use]
    pub(crate) const fn len(self) -> u64 {
        self.len
    }
}

/// What the final component is, after reparse points have been rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// A caller path that resolved inside the sandbox root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    absolute: PathBuf,
    relative: String,
    identity: FileIdentity,
    kind: ResolvedKind,
}

impl ResolvedPath {
    /// Canonical absolute path.
    #[must_use]
    pub fn absolute(&self) -> &Path {
        &self.absolute
    }

    /// Workspace-relative path using `/` separators. `.` is the workspace root.
    #[must_use]
    pub fn relative(&self) -> &str {
        &self.relative
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> FileIdentity {
        self.identity
    }

    #[must_use]
    pub const fn kind(&self) -> ResolvedKind {
        self.kind
    }

    #[must_use]
    pub const fn is_file(&self) -> bool {
        matches!(self.kind, ResolvedKind::File)
    }

    #[must_use]
    pub const fn is_dir(&self) -> bool {
        matches!(self.kind, ResolvedKind::Directory)
    }
}

/// Immutable workspace root for one process.
///
/// [`Self::privacy`] is a separate denial layer. A path the sandbox would otherwise
/// open can still be rejected before its bytes are read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSandbox {
    root: PathBuf,
    privacy: PrivacyPolicy,
}

impl WorkspaceSandbox {
    /// Accepts an existing directory and stores its canonical path.
    ///
    /// The stored root does not change for the life of this value. Privacy is the
    /// mandatory baseline.
    pub fn new(root: &Path) -> Result<Self, FsError> {
        Self::with_privacy(root, PrivacyPolicy::baseline())
    }

    /// Same root capture as [`Self::new`], with extra privacy exclusions.
    ///
    /// The baseline names stay in `privacy`. This constructor does not replace them.
    pub fn with_privacy(root: &Path, privacy: PrivacyPolicy) -> Result<Self, FsError> {
        let metadata = match std::fs::metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(FsError::WorkspaceNotFound {
                    path: root.to_path_buf(),
                });
            }
            Err(error) => {
                return Err(FsError::InvalidWorkspace {
                    path: root.to_path_buf(),
                    message: error.to_string(),
                });
            }
        };
        if !metadata.is_dir() {
            return Err(FsError::WorkspaceNotDirectory {
                path: root.to_path_buf(),
            });
        }
        let canonical = std::fs::canonicalize(root).map_err(|error| FsError::InvalidWorkspace {
            path: root.to_path_buf(),
            message: error.to_string(),
        })?;
        let root = simplify_verbatim(canonical);
        if !root.is_dir() {
            return Err(FsError::WorkspaceNotDirectory { path: root });
        }
        let meta = std::fs::symlink_metadata(&root).map_err(|error| FsError::InvalidWorkspace {
            path: root.clone(),
            message: error.to_string(),
        })?;
        if is_reparse(&meta) {
            return Err(FsError::ReparseDenied {
                path: root.display().to_string(),
            });
        }
        Ok(Self { root, privacy })
    }

    /// Canonical workspace root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Privacy rules bound to this root. The baseline cannot be removed.
    #[must_use]
    pub fn privacy(&self) -> &PrivacyPolicy {
        &self.privacy
    }

    /// Resolves `raw` after rejecting a protected name.
    ///
    /// A lexically protected path is rejected before [`Self::resolve`], so the file
    /// is not opened. A path that resolves and is still protected is rejected before
    /// the caller reads bytes.
    pub(crate) fn resolve_visible(&self, raw: &str) -> Result<ResolvedPath, FsError> {
        if let Some(relative) = lexical_relative(raw)
            && self.privacy.blocks(&relative)
        {
            return Err(FsError::PrivacyDenied);
        }
        let resolved = self.resolve(raw)?;
        if self.privacy.blocks(resolved.relative()) {
            return Err(FsError::PrivacyDenied);
        }
        Ok(resolved)
    }

    /// Reads one resolved file without following a final reparse point.
    ///
    /// The read fails when the file is larger than `max_bytes`. It does not return a prefix.
    /// A protected path is rejected before the file is opened.
    pub fn read_bytes(&self, relative: &str, max_bytes: u64) -> Result<Vec<u8>, FsError> {
        let resolved = self.resolve_visible(relative)?;
        read_resolved_file(&resolved, max_bytes)
    }

    /// Resolves a relative path. Absolute paths, `..`, and reparse points are rejected.
    pub fn resolve(&self, raw: &str) -> Result<ResolvedPath, FsError> {
        let names = parse_relative(raw)?;
        if names.iter().any(|name| name.eq_ignore_ascii_case(".git")) {
            return Err(FsError::ProtectedPath {
                path: display_path(raw),
            });
        }
        let mut absolute = self.root.clone();
        self.confirm_directory(&absolute, raw)?;
        let mut relative_parts = Vec::new();
        let last = names.len().saturating_sub(1);
        for (index, name) in names.iter().enumerate() {
            if name == "." {
                continue;
            }
            let next = absolute.join(name);
            let meta = match std::fs::symlink_metadata(&next) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(FsError::NotFound {
                        path: display_path(raw),
                    });
                }
                Err(error) => {
                    return Err(FsError::Io {
                        path: display_path(raw),
                        message: error.to_string(),
                    });
                }
            };
            if is_reparse(&meta) {
                return Err(FsError::ReparseDenied {
                    path: display_path(raw),
                });
            }
            let canonical = canonicalize_inside(&next, raw)?;
            if !is_within(&self.root, &canonical) {
                return Err(FsError::OutsideWorkspace {
                    path: display_path(raw),
                });
            }
            let parent = canonical
                .parent()
                .ok_or_else(|| FsError::OutsideWorkspace {
                    path: display_path(raw),
                })?;
            if !paths_equivalent(parent, &absolute) {
                return Err(FsError::OutsideWorkspace {
                    path: display_path(raw),
                });
            }
            let is_last = index == last || names[index + 1..].iter().all(|item| item == ".");
            if !is_last && !meta.is_dir() {
                return Err(FsError::NotADirectory {
                    path: display_path(raw),
                });
            }
            absolute = canonical;
            relative_parts.push(component_name(&absolute, name)?);
        }
        let meta = std::fs::symlink_metadata(&absolute).map_err(|error| FsError::Io {
            path: display_path(raw),
            message: error.to_string(),
        })?;
        if is_reparse(&meta) {
            return Err(FsError::ReparseDenied {
                path: display_path(raw),
            });
        }
        if !is_within(&self.root, &absolute) {
            return Err(FsError::OutsideWorkspace {
                path: display_path(raw),
            });
        }
        let kind = if meta.is_dir() {
            ResolvedKind::Directory
        } else if meta.is_file() {
            ResolvedKind::File
        } else {
            return Err(FsError::Io {
                path: display_path(raw),
                message: "path is neither a file nor a directory".to_owned(),
            });
        };
        let identity = file_identity(&meta, raw)?;
        let relative = if relative_parts.is_empty() {
            ".".to_owned()
        } else {
            relative_parts.join("/")
        };
        Ok(ResolvedPath {
            absolute,
            relative,
            identity,
            kind,
        })
    }
}

fn component_name(canonical: &Path, fallback: &str) -> Result<String, FsError> {
    match canonical.file_name() {
        Some(name) => name
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| FsError::InvalidPath {
                message: "path component is not valid Unicode".to_owned(),
            }),
        None => Ok(fallback.to_owned()),
    }
}

fn canonicalize_inside(path: &Path, raw: &str) -> Result<PathBuf, FsError> {
    let canonical = std::fs::canonicalize(path).map_err(|error| FsError::Io {
        path: display_path(raw),
        message: error.to_string(),
    })?;
    Ok(simplify_verbatim(canonical))
}

fn parse_relative(raw: &str) -> Result<Vec<String>, FsError> {
    if raw.is_empty() || raw.chars().count() > MAX_PATH_CHARS {
        return Err(FsError::InvalidPath {
            message: "path length is not allowed".to_owned(),
        });
    }
    if raw.chars().any(|character| character.is_control()) {
        return Err(FsError::InvalidPath {
            message: "path contains a control character".to_owned(),
        });
    }
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(FsError::InvalidPath {
            message: "absolute paths are not allowed".to_owned(),
        });
    }
    if raw.contains(':') {
        return Err(FsError::InvalidPath {
            message: "drive prefixes and alternate data streams are not allowed".to_owned(),
        });
    }
    let parts: Vec<&str> = raw.split(['/', '\\']).collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(FsError::InvalidPath {
            message: "path contains an empty component".to_owned(),
        });
    }
    let mut names = Vec::with_capacity(parts.len());
    for part in parts {
        if part == "." {
            names.push(".".to_owned());
            continue;
        }
        if part == ".." {
            return Err(FsError::InvalidPath {
                message: "parent traversal is not allowed".to_owned(),
            });
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(FsError::InvalidPath {
                message: "path component ends with a dot or space".to_owned(),
            });
        }
        if is_reserved_device(part) {
            return Err(FsError::InvalidPath {
                message: "device names are not allowed".to_owned(),
            });
        }
        names.push(part.to_owned());
    }
    if names.is_empty() {
        return Err(FsError::InvalidPath {
            message: "path must not be empty".to_owned(),
        });
    }
    Ok(names)
}

fn is_reserved_device(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let bytes = upper.as_bytes();
    if bytes.len() == 4
        && (bytes.starts_with(b"COM") || bytes.starts_with(b"LPT"))
        && bytes[3].is_ascii_digit()
        && bytes[3] != b'0'
    {
        return true;
    }
    false
}

pub(crate) fn is_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

pub(crate) fn file_identity(meta: &std::fs::Metadata, raw: &str) -> Result<FileIdentity, FsError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let created = meta.creation_time();
        let modified = meta.last_write_time();
        if created == 0 || modified == 0 {
            return Err(FsError::UnverifiableIdentity {
                path: display_path(raw),
            });
        }
        Ok(FileIdentity {
            created,
            modified,
            len: meta.len(),
        })
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        let created = meta.dev();
        let modified = meta.ino();
        if modified == 0 {
            return Err(FsError::UnverifiableIdentity {
                path: display_path(raw),
            });
        }
        Ok(FileIdentity {
            created,
            modified,
            len: meta.len(),
        })
    }
}

impl WorkspaceSandbox {
    fn confirm_directory(&self, path: &Path, raw: &str) -> Result<(), FsError> {
        let meta = std::fs::symlink_metadata(path).map_err(|error| FsError::Io {
            path: display_path(raw),
            message: error.to_string(),
        })?;
        if is_reparse(&meta) {
            return Err(FsError::ReparseDenied {
                path: display_path(raw),
            });
        }
        if !meta.is_dir() {
            return Err(FsError::NotADirectory {
                path: display_path(raw),
            });
        }
        Ok(())
    }
}

/// Opens `path` for reading. On Windows the final component is not followed.
pub(crate) fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// Creates a new file. Fails if the name already exists, including as a reparse point.
pub(crate) fn create_new_nofollow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

/// Reads a resolved file without following a final reparse point.
pub(crate) fn read_resolved_file(
    resolved: &ResolvedPath,
    max_bytes: u64,
) -> Result<Vec<u8>, FsError> {
    if !resolved.is_file() {
        return Err(FsError::NotAFile {
            path: resolved.relative().to_owned(),
        });
    }
    let raw = resolved.relative();
    let file = open_read_nofollow(resolved.absolute()).map_err(|error| FsError::Io {
        path: raw.to_owned(),
        message: error.to_string(),
    })?;
    let meta = file.metadata().map_err(|error| FsError::Io {
        path: raw.to_owned(),
        message: error.to_string(),
    })?;
    if is_reparse(&meta) {
        return Err(FsError::ReparseDenied {
            path: raw.to_owned(),
        });
    }
    let identity = file_identity(&meta, raw)?;
    if identity != resolved.identity() {
        return Err(FsError::IdentityChanged {
            path: raw.to_owned(),
        });
    }
    if !meta.is_file() {
        return Err(FsError::NotAFile {
            path: raw.to_owned(),
        });
    }
    if meta.len() > max_bytes {
        return Err(FsError::TooLarge {
            path: raw.to_owned(),
            limit: max_bytes,
        });
    }
    let mut bytes = Vec::new();
    use std::io::Read;
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| FsError::Io {
            path: raw.to_owned(),
            message: error.to_string(),
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(FsError::TooLarge {
            path: raw.to_owned(),
            limit: max_bytes,
        });
    }
    let after = std::fs::symlink_metadata(resolved.absolute()).map_err(|error| FsError::Io {
        path: raw.to_owned(),
        message: error.to_string(),
    })?;
    if is_reparse(&after) || file_identity(&after, raw)? != identity || after.len() != meta.len() {
        return Err(FsError::FileChanged {
            path: raw.to_owned(),
        });
    }
    Ok(bytes)
}
