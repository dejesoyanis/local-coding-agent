//! Single-file unified diff preparation and approval-gated application.
//!
//! Prepare reads the file and builds the new bytes in memory. It does not create a
//! temporary file and it does not change the target. Apply writes only after a grant
//! whose binding matches this prepared action, and only if the file identity and hash
//! are still the ones that were prepared.

use std::collections::HashSet;
use std::fmt;
#[cfg(not(windows))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(not(windows))]
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::fs::limits::FsLimits;
use crate::fs::read::privacy_gate;
use crate::fs_error::{FsError, display_path};
use crate::pathutil::paths_equivalent;
use crate::privacy::deny_overrides;
use crate::sandbox::{FileIdentity, WorkspaceSandbox, read_resolved_file};
#[cfg(not(windows))]
use crate::sandbox::{create_new_nofollow, file_identity, is_reparse};

/// In-process record of approval bindings that have already been used.
///
/// The record is not stored on disk. Ending the process drops every grant.
#[derive(Debug, Default)]
pub struct ApprovalLedger {
    used: Mutex<HashSet<[u8; 32]>>,
}

impl ApprovalLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            used: Mutex::new(HashSet::new()),
        }
    }
}

/// Grant produced from a confirmation line and one prepared patch.
///
/// The value is not [`Clone`]. Applying it consumes the binding in the ledger.
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovalGrant {
    action_id: u64,
    binding: [u8; 32],
}

impl ApprovalGrant {
    /// Issues a grant when `line` is exactly the prepared confirmation line.
    ///
    /// A mismatched line, including model text that merely contains the word approve,
    /// is rejected. This function does not write.
    pub fn issue(prepared: &PreparedPatch, line: &str) -> Result<Self, FsError> {
        if line != prepared.confirmation_line() {
            return Err(FsError::ApprovalRejected);
        }
        Ok(Self {
            action_id: prepared.action_id,
            binding: prepared.binding,
        })
    }
}

/// NTFS file id captured at prepare time. Zeros mean this platform has no file id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BoundFileId {
    /// Volume serial from `FileIdInfo`.
    pub volume_serial: u64,
    /// 128-bit file id.
    pub file_id: [u8; 16],
}

/// A patch that has been applied in memory and is waiting for approval.
pub struct PreparedPatch {
    action_id: u64,
    workspace_root: PathBuf,
    relative_path: String,
    identity: FileIdentity,
    platform: BoundFileId,
    original_hash: [u8; 32],
    new_hash: [u8; 32],
    patch_hash: [u8; 32],
    new_bytes: Vec<u8>,
    patch_text: String,
    diff: String,
    binding: [u8; 32],
    line_ending: &'static str,
}

impl fmt::Debug for PreparedPatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedPatch")
            .field("action_id", &self.action_id)
            .field("relative_path", &self.relative_path)
            .field("original_hash", &hex_encode(&self.original_hash))
            .field("new_hash", &hex_encode(&self.new_hash))
            .finish_non_exhaustive()
    }
}

impl PreparedPatch {
    /// Controller action identity.
    #[must_use]
    pub const fn action_id(&self) -> u64 {
        self.action_id
    }

    /// Canonical workspace root captured at prepare time.
    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    /// Workspace-relative target.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// SHA-256 of the file bytes that were read.
    #[must_use]
    pub fn original_hash_hex(&self) -> String {
        hex_encode(&self.original_hash)
    }

    /// SHA-256 of the bytes that would be written.
    #[must_use]
    pub fn new_hash_hex(&self) -> String {
        hex_encode(&self.new_hash)
    }

    /// Unified diff preview. The envelope uses LF. File bytes keep `line_ending`.
    #[must_use]
    pub fn diff(&self) -> &str {
        &self.diff
    }

    /// `lf` or `crlf`. Existing lines are not converted.
    #[must_use]
    pub const fn line_ending(&self) -> &'static str {
        self.line_ending
    }

    /// SHA-256 bytes of the file that was read.
    #[must_use]
    pub(crate) fn original_hash(&self) -> [u8; 32] {
        self.original_hash
    }

    /// SHA-256 bytes that would be written.
    #[must_use]
    pub(crate) fn new_hash(&self) -> [u8; 32] {
        self.new_hash
    }

    /// SHA-256 bytes of the unified diff text.
    #[must_use]
    pub(crate) fn patch_hash(&self) -> [u8; 32] {
        self.patch_hash
    }

    /// Proposed file bytes. They are not included in [`Debug`].
    #[must_use]
    pub(crate) fn new_bytes(&self) -> &[u8] {
        &self.new_bytes
    }

    /// Unified diff text that was applied in memory.
    #[must_use]
    pub(crate) fn patch_text(&self) -> &str {
        &self.patch_text
    }

    /// File id captured for the verified apply.
    #[must_use]
    pub(crate) fn platform_id(&self) -> BoundFileId {
        self.platform
    }

    /// Timestamp identity captured for the in-process binding.
    #[must_use]
    pub(crate) fn file_identity(&self) -> FileIdentity {
        self.identity
    }

    /// Exact line the user must type to approve this action in-process.
    #[must_use]
    pub fn confirmation_line(&self) -> String {
        format!(
            "approve {} {}",
            self.action_id,
            &hex_encode(&self.binding)[..16]
        )
    }
}

/// Result of a successful apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyResult {
    /// Workspace-relative path.
    pub path: String,
    /// SHA-256 of the bytes read back after the replace.
    pub new_hash: String,
}

pub(crate) fn prepare_patch(
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
    action_id: u64,
    path: &str,
    patch: &str,
) -> Result<PreparedPatch, FsError> {
    if !limits.write_enabled() {
        return Err(FsError::ToolDisabled {
            tool: "apply_patch".to_owned(),
        });
    }
    if patch.len() > 64 * 1024 {
        return Err(FsError::InvalidPatch {
            message: "patch text exceeds 65536 bytes".to_owned(),
        });
    }
    let (header_path, hunks) = parse_unified(patch)?;
    if !paths_match(&header_path, path) {
        return Err(FsError::InvalidPatch {
            message: "patch path does not match the requested path".to_owned(),
        });
    }
    let resolved = sandbox.resolve_visible(path)?;
    deny_overrides(&[privacy_gate(sandbox, resolved.relative())])?;
    if !resolved.is_file() {
        return Err(FsError::NotAFile {
            path: display_path(path),
        });
    }
    if contains_protected(resolved.relative()) {
        return Err(FsError::ProtectedPath {
            path: resolved.relative().to_owned(),
        });
    }
    let original = read_resolved_file(sandbox, &resolved, limits.max_file_size_bytes())?;
    let text = decode_text(&original, resolved.relative())?;
    let (ending, lines) = split_source(text)?;
    let updated = apply_hunks(&lines, &hunks)?;
    let new_text = join_lines(&updated, ending);
    let new_bytes = new_text.into_bytes();
    if new_bytes.len() as u64 > limits.max_file_size_bytes() {
        return Err(FsError::TooLarge {
            path: resolved.relative().to_owned(),
            limit: limits.max_file_size_bytes(),
        });
    }
    let original_hash = sha256(&original);
    let new_hash = sha256(&new_bytes);
    let patch_hash = sha256(patch.as_bytes());
    let platform = capture_platform(sandbox.root(), resolved.relative())?;
    let binding = compute_binding(
        action_id,
        &sandbox.root().to_string_lossy(),
        resolved.relative(),
        resolved.identity(),
        platform,
        &original_hash,
        &new_hash,
        &patch_hash,
    );
    let diff = render_diff(resolved.relative(), &hunks);
    Ok(PreparedPatch {
        action_id,
        workspace_root: sandbox.root().to_path_buf(),
        relative_path: resolved.relative().to_owned(),
        identity: resolved.identity(),
        platform,
        original_hash,
        new_hash,
        patch_hash,
        new_bytes,
        patch_text: patch.to_owned(),
        diff,
        binding,
        line_ending: ending.label(),
    })
}

/// A single fault point for tests. [`ApplyFault::None`] is the production value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyFault {
    /// No fault. This is the only value the CLI constructs.
    None,
    /// After the proposal digest and workspace checks, before approval is stored.
    AfterValidation,
    /// After approval is stored, before the apply starts.
    AfterApproval,
    /// After the original bytes are sealed and before the target is staged.
    AfterIntent,
    /// After the temporary file is created.
    AfterTempCreate,
    /// After the temporary file holds the byte image, before it is flushed.
    AfterWrite,
    /// After the temporary file was flushed and read back.
    AfterStageFlush,
    /// Immediately before the verified handle is overwritten.
    BeforeRename,
    /// After the first target `WriteFile` and before the file length is adjusted.
    DuringPublish,
    /// Immediately after the verified handle has been flushed.
    AfterRename,
    /// Before the handle is read back.
    BeforeReadback,
    /// The read-back is treated as a mismatch after the bytes were published.
    DuringReadback,
    /// After the read-back matched, before the applied state is stored.
    AfterVerification,
    /// After the applied state is stored, before the success audit line.
    BeforeAudit,
}

impl ApplyFault {
    /// The production setting.
    #[must_use]
    pub const fn none() -> Self {
        Self::None
    }

    const fn phase_name(self) -> Option<&'static str> {
        Some(match self {
            Self::None => return None,
            Self::AfterValidation => "after_validation",
            Self::AfterApproval => "after_approval",
            Self::AfterIntent => "after_intent",
            Self::AfterTempCreate => "after_temp_create",
            Self::AfterWrite => "after_write",
            Self::AfterStageFlush => "after_stage_flush",
            Self::BeforeRename => "before_rename",
            Self::DuringPublish => "during_publish",
            Self::AfterRename => "after_rename",
            Self::BeforeReadback => "before_readback",
            Self::DuringReadback => "during_readback",
            Self::AfterVerification => "after_verification",
            Self::BeforeAudit => "before_audit",
        })
    }

    /// Parses a test-harness point name. Production code does not call this.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "after_validation" => Self::AfterValidation,
            "after_approval" => Self::AfterApproval,
            "after_intent" => Self::AfterIntent,
            "after_temp_create" => Self::AfterTempCreate,
            "after_write" => Self::AfterWrite,
            "after_stage_flush" => Self::AfterStageFlush,
            "before_rename" => Self::BeforeRename,
            "during_publish" => Self::DuringPublish,
            "after_rename" => Self::AfterRename,
            "before_readback" => Self::BeforeReadback,
            "during_readback" => Self::DuringReadback,
            "after_verification" => Self::AfterVerification,
            "before_audit" => Self::BeforeAudit,
            _ => return None,
        })
    }
}

/// Parks the calling thread at one fault point after writing `ready`.
///
/// The `lca` binary does not construct this. A test process writes the ready file and
/// then waits to be killed. There is no environment variable that arms it.
#[derive(Debug)]
pub struct KillHold {
    point: ApplyFault,
    ready: PathBuf,
}

impl KillHold {
    /// Holds at `point` and creates `ready` when that point is reached.
    #[must_use]
    pub fn new(point: ApplyFault, ready: PathBuf) -> Self {
        Self { point, ready }
    }

    pub(crate) fn park_at(&self, point: ApplyFault) {
        if self.point != point {
            return;
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.ready)
        {
            use std::io::Write;
            let name = point.phase_name().unwrap_or("hold");
            let _ = file.write_all(name.as_bytes());
            let _ = file.sync_all();
        }
        std::thread::park();
    }
}

pub(crate) fn apply_granted(
    sandbox: &WorkspaceSandbox,
    prepared: &PreparedPatch,
    grant: ApprovalGrant,
    ledger: &ApprovalLedger,
) -> Result<ApplyResult, FsError> {
    apply_granted_controlled(
        sandbox,
        prepared,
        grant,
        ledger,
        ApplyFault::None,
        None,
        &mut |_| Ok(()),
        &mut |_| Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_granted_controlled(
    sandbox: &WorkspaceSandbox,
    prepared: &PreparedPatch,
    grant: ApprovalGrant,
    ledger: &ApprovalLedger,
    fault: ApplyFault,
    hold: Option<&KillHold>,
    preimage: &mut dyn FnMut(&[u8]) -> Result<(), FsError>,
    audit: &mut dyn FnMut(&str) -> Result<(), FsError>,
) -> Result<ApplyResult, FsError> {
    if grant.action_id != prepared.action_id || grant.binding != prepared.binding {
        return Err(FsError::ApprovalMismatch);
    }
    if sha256(prepared.patch_text.as_bytes()) != prepared.patch_hash {
        return Err(FsError::ApprovalMismatch);
    }
    if !paths_equivalent(sandbox.root(), &prepared.workspace_root) {
        return Err(FsError::ApprovalMismatch);
    }
    deny_overrides(&[privacy_gate(sandbox, &prepared.relative_path)])?;
    let mut used = ledger.used.lock().map_err(|_| FsError::LedgerUnavailable)?;
    if used.contains(&prepared.binding) {
        return Err(FsError::ApprovalConsumed);
    }
    let resolved = sandbox.resolve(&prepared.relative_path)?;
    if !resolved.is_file() {
        return Err(FsError::NotAFile {
            path: prepared.relative_path.clone(),
        });
    }
    if resolved.identity() != prepared.identity {
        return Err(FsError::IdentityChanged {
            path: prepared.relative_path.clone(),
        });
    }
    let current = read_capped(sandbox, &resolved, &prepared.relative_path)?;
    if sha256(&current) != prepared.original_hash {
        return Err(FsError::Conflict {
            path: prepared.relative_path.clone(),
        });
    }
    let text = decode_text(&current, &prepared.relative_path)?;
    let (ending, lines) = split_source(text)?;
    let (_header, hunks) = parse_unified(&prepared.patch_text)?;
    let updated = apply_hunks(&lines, &hunks)?;
    let replay = join_lines(&updated, ending).into_bytes();
    if replay != prepared.new_bytes || sha256(&replay) != prepared.new_hash {
        return Err(FsError::Conflict {
            path: prepared.relative_path.clone(),
        });
    }

    #[cfg(windows)]
    {
        apply_ntfs(prepared, &mut used, fault, hold, preimage, audit)?;
        Ok(ApplyResult {
            path: prepared.relative_path.clone(),
            new_hash: hex_encode(&prepared.new_hash),
        })
    }
    #[cfg(not(windows))]
    {
        refuse_armed_fault(fault)?;
        let _ = (hold, preimage);
        let _ = audit;
        let parent = resolved
            .absolute()
            .parent()
            .ok_or_else(|| FsError::WriteFailed {
                path: prepared.relative_path.clone(),
                message: "target has no parent directory".to_owned(),
            })?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let temp_path = parent.join(format!(
            ".lca-apply-{}-{}-{nanos}.tmp",
            prepared.action_id,
            std::process::id()
        ));
        let mut temp = create_new_nofollow(&temp_path).map_err(|error| FsError::WriteFailed {
            path: prepared.relative_path.clone(),
            message: error.to_string(),
        })?;
        let temp_meta = temp.metadata().map_err(|error| FsError::WriteFailed {
            path: prepared.relative_path.clone(),
            message: error.to_string(),
        })?;
        if is_reparse(&temp_meta) {
            drop(temp);
            let _ = std::fs::remove_file(&temp_path);
            return Err(FsError::ReparseDenied {
                path: prepared.relative_path.clone(),
            });
        }
        let mut cleanup = TempCleanup {
            path: &temp_path,
            armed: true,
        };
        temp.write_all(&prepared.new_bytes)
            .map_err(|error| FsError::WriteFailed {
                path: prepared.relative_path.clone(),
                message: error.to_string(),
            })?;
        temp.sync_all().map_err(|error| FsError::WriteFailed {
            path: prepared.relative_path.clone(),
            message: error.to_string(),
        })?;
        drop(temp);

        let again =
            std::fs::symlink_metadata(resolved.absolute()).map_err(|error| FsError::Io {
                path: prepared.relative_path.clone(),
                message: error.to_string(),
            })?;
        if is_reparse(&again)
            || file_identity(&again, &prepared.relative_path)? != prepared.identity
        {
            return Err(FsError::IdentityChanged {
                path: prepared.relative_path.clone(),
            });
        }
        let reread = read_capped(sandbox, &resolved, &prepared.relative_path)?;
        if sha256(&reread) != prepared.original_hash {
            return Err(FsError::Conflict {
                path: prepared.relative_path.clone(),
            });
        }

        used.insert(prepared.binding);
        std::fs::rename(&temp_path, resolved.absolute()).map_err(|error| FsError::WriteFailed {
            path: prepared.relative_path.clone(),
            message: error.to_string(),
        })?;
        cleanup.armed = false;

        let written = sandbox.resolve(&prepared.relative_path)?;
        let bytes =
            read_resolved_file(sandbox, &written, READ_CAP).map_err(|_| FsError::VerifyFailed {
                path: prepared.relative_path.clone(),
            })?;
        if sha256(&bytes) != prepared.new_hash {
            return Err(FsError::VerifyFailed {
                path: prepared.relative_path.clone(),
            });
        }
        Ok(ApplyResult {
            path: prepared.relative_path.clone(),
            new_hash: hex_encode(&prepared.new_hash),
        })
    }
}

const READ_CAP: u64 = 16 * 1024 * 1024;

fn read_capped(
    sandbox: &WorkspaceSandbox,
    resolved: &crate::sandbox::ResolvedPath,
    path: &str,
) -> Result<Vec<u8>, FsError> {
    match read_resolved_file(sandbox, resolved, READ_CAP) {
        Ok(bytes) => Ok(bytes),
        Err(FsError::TooLarge { .. }) => Err(FsError::Conflict {
            path: path.to_owned(),
        }),
        Err(error) => Err(error),
    }
}

fn decode_text<'a>(bytes: &'a [u8], path: &str) -> Result<&'a str, FsError> {
    if bytes.contains(&0) {
        return Err(FsError::BinaryFile {
            path: path.to_owned(),
        });
    }
    std::str::from_utf8(bytes).map_err(|_| FsError::InvalidUtf8 {
        path: path.to_owned(),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LineEnding {
    Lf,
    Crlf,
}

impl LineEnding {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Lf => "\n",
            Self::Crlf => "\r\n",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Lf => "lf",
            Self::Crlf => "crlf",
        }
    }
}

fn split_source(text: &str) -> Result<(LineEnding, Vec<String>), FsError> {
    if text.is_empty() {
        return Ok((LineEnding::Lf, Vec::new()));
    }
    let ending = classify_ending(text)?;
    let separator = ending.as_str();
    if !text.ends_with(separator) {
        return Err(FsError::UnsupportedLayout {
            message: "file does not end with its line ending".to_owned(),
        });
    }
    let trimmed = &text[..text.len() - separator.len()];
    if trimmed.is_empty() {
        return Ok((ending, vec![String::new()]));
    }
    Ok((
        ending,
        trimmed.split(separator).map(str::to_owned).collect(),
    ))
}

fn classify_ending(text: &str) -> Result<LineEnding, FsError> {
    let crlf = text.contains("\r\n");
    let stripped = text.replace("\r\n", "");
    if stripped.contains('\r') || (crlf && stripped.contains('\n')) {
        return Err(FsError::UnsupportedLayout {
            message: "mixed line endings are rejected".to_owned(),
        });
    }
    if crlf {
        Ok(LineEnding::Crlf)
    } else if text.contains('\n') {
        Ok(LineEnding::Lf)
    } else {
        Err(FsError::UnsupportedLayout {
            message: "file has no trailing newline".to_owned(),
        })
    }
}

fn join_lines(lines: &[String], ending: LineEnding) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(line);
        out.push_str(ending.as_str());
    }
    out
}

enum HunkLine {
    Context(String),
    Delete(String),
    Add(String),
}

struct Hunk {
    old_start: usize,
    old_len: usize,
    new_len: usize,
    lines: Vec<HunkLine>,
}

fn apply_hunks(lines: &[String], hunks: &[Hunk]) -> Result<Vec<String>, FsError> {
    let mut output = Vec::new();
    let mut cursor = 0usize;
    for hunk in hunks {
        let start = if hunk.old_len == 0 {
            hunk.old_start
        } else {
            hunk.old_start
                .checked_sub(1)
                .ok_or_else(|| FsError::InvalidPatch {
                    message: "hunk start is zero".to_owned(),
                })?
        };
        if start < cursor || start > lines.len() {
            return Err(FsError::ContextMismatch {
                message: "hunk does not line up with the file".to_owned(),
            });
        }
        output.extend(lines[cursor..start].iter().cloned());
        cursor = start;
        let mut old_seen = 0usize;
        let mut new_seen = 0usize;
        for line in &hunk.lines {
            match line {
                HunkLine::Context(text) | HunkLine::Delete(text) => {
                    let current = lines.get(cursor).ok_or_else(|| FsError::ContextMismatch {
                        message: format!("missing context around line {}", cursor + 1),
                    })?;
                    if current != text {
                        return Err(FsError::ContextMismatch {
                            message: format!("context mismatch around line {}", cursor + 1),
                        });
                    }
                    if matches!(line, HunkLine::Context(_)) {
                        output.push(current.clone());
                        new_seen += 1;
                    }
                    cursor += 1;
                    old_seen += 1;
                }
                HunkLine::Add(text) => {
                    if text.contains('\n') || text.contains('\r') {
                        return Err(FsError::InvalidPatch {
                            message: "added line contains a newline".to_owned(),
                        });
                    }
                    output.push(text.clone());
                    new_seen += 1;
                }
            }
        }
        if old_seen != hunk.old_len || new_seen != hunk.new_len {
            return Err(FsError::InvalidPatch {
                message: "hunk line counts do not match the header".to_owned(),
            });
        }
    }
    output.extend(lines[cursor..].iter().cloned());
    Ok(output)
}

fn parse_unified(patch: &str) -> Result<(String, Vec<Hunk>), FsError> {
    let mut lines: Vec<&str> = patch.split('\n').collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    if lines.len() < 3 {
        return Err(FsError::InvalidPatch {
            message: "patch is missing a file header".to_owned(),
        });
    }
    let old_header = lines[0].trim_end_matches('\r');
    let new_header = lines[1].trim_end_matches('\r');
    let old_path = old_header
        .strip_prefix("--- ")
        .ok_or_else(|| FsError::InvalidPatch {
            message: "patch must start with a --- header".to_owned(),
        })?;
    let new_path = new_header
        .strip_prefix("+++ ")
        .ok_or_else(|| FsError::InvalidPatch {
            message: "patch is missing a +++ header".to_owned(),
        })?;
    if old_path == "/dev/null" || new_path == "/dev/null" {
        return Err(FsError::InvalidPatch {
            message: "creating or deleting a file is not supported".to_owned(),
        });
    }
    let old_rel = strip_diff_prefix(old_path);
    let new_rel = strip_diff_prefix(new_path);
    if !paths_match(old_rel, new_rel) {
        return Err(FsError::InvalidPatch {
            message: "patch headers name different paths".to_owned(),
        });
    }
    let mut hunks = Vec::new();
    let mut index = 2;
    while index < lines.len() {
        let header = lines[index].trim_end_matches('\r');
        if header.is_empty() {
            return Err(FsError::InvalidPatch {
                message: "unexpected blank line in the patch".to_owned(),
            });
        }
        let (old_start, old_len, new_len) = parse_hunk_header(header)?;
        index += 1;
        let mut body = Vec::new();
        let mut old_seen = 0usize;
        let mut new_seen = 0usize;
        while index < lines.len() && (old_seen < old_len || new_seen < new_len) {
            let raw = lines[index].trim_end_matches('\r');
            index += 1;
            if raw.starts_with('\\') {
                return Err(FsError::UnsupportedLayout {
                    message: "newline markers in the diff are rejected".to_owned(),
                });
            }
            let (prefix, text) = raw
                .split_at_checked(1)
                .ok_or_else(|| FsError::InvalidPatch {
                    message: "hunk line is missing a prefix".to_owned(),
                })?;
            match prefix {
                " " => {
                    body.push(HunkLine::Context(text.to_owned()));
                    old_seen += 1;
                    new_seen += 1;
                }
                "-" => {
                    body.push(HunkLine::Delete(text.to_owned()));
                    old_seen += 1;
                }
                "+" => {
                    body.push(HunkLine::Add(text.to_owned()));
                    new_seen += 1;
                }
                _ => {
                    return Err(FsError::InvalidPatch {
                        message: "hunk line prefix is not space, plus, or minus".to_owned(),
                    });
                }
            }
        }
        if old_seen != old_len || new_seen != new_len {
            return Err(FsError::InvalidPatch {
                message: "hunk ended before its header counts were satisfied".to_owned(),
            });
        }
        hunks.push(Hunk {
            old_start,
            old_len,
            new_len,
            lines: body,
        });
    }
    if hunks.is_empty() {
        return Err(FsError::InvalidPatch {
            message: "patch contains no hunks".to_owned(),
        });
    }
    Ok((old_rel.to_owned(), hunks))
}

fn parse_hunk_header(header: &str) -> Result<(usize, usize, usize), FsError> {
    let rest = header
        .strip_prefix("@@ ")
        .ok_or_else(|| FsError::InvalidPatch {
            message: "hunk header is malformed".to_owned(),
        })?;
    let (ranges, _) = rest
        .split_once(" @@")
        .ok_or_else(|| FsError::InvalidPatch {
            message: "hunk header is malformed".to_owned(),
        })?;
    let mut parts = ranges.split_whitespace();
    let old = parts.next().ok_or_else(|| FsError::InvalidPatch {
        message: "hunk header is missing the old range".to_owned(),
    })?;
    let new = parts.next().ok_or_else(|| FsError::InvalidPatch {
        message: "hunk header is missing the new range".to_owned(),
    })?;
    if parts.next().is_some() {
        return Err(FsError::InvalidPatch {
            message: "hunk header has extra fields".to_owned(),
        });
    }
    let old = old.strip_prefix('-').ok_or_else(|| FsError::InvalidPatch {
        message: "hunk old range is malformed".to_owned(),
    })?;
    let new = new.strip_prefix('+').ok_or_else(|| FsError::InvalidPatch {
        message: "hunk new range is malformed".to_owned(),
    })?;
    let (old_start, old_len) = parse_range(old)?;
    let (_new_start, new_len) = parse_range(new)?;
    if old_len == 0 && old_start > 1_000_000 {
        return Err(FsError::InvalidPatch {
            message: "hunk start is too large".to_owned(),
        });
    }
    Ok((old_start, old_len, new_len))
}

fn parse_range(text: &str) -> Result<(usize, usize), FsError> {
    let (start_text, len_text) = text.split_once(',').unwrap_or((text, "1"));
    let start = start_text
        .parse::<usize>()
        .map_err(|_| FsError::InvalidPatch {
            message: "hunk range is not an integer".to_owned(),
        })?;
    let len = len_text
        .parse::<usize>()
        .map_err(|_| FsError::InvalidPatch {
            message: "hunk range is not an integer".to_owned(),
        })?;
    Ok((start, len))
}

fn strip_diff_prefix(path: &str) -> &str {
    path.strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path)
}

fn paths_match(left: &str, right: &str) -> bool {
    let left: Vec<&str> = left
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let right: Vec<&str> = right
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if left.len() != right.len() {
        return false;
    }
    left.iter().zip(right.iter()).all(|(left, right)| {
        #[cfg(windows)]
        {
            left.eq_ignore_ascii_case(right)
        }
        #[cfg(not(windows))]
        {
            left == right
        }
    })
}

fn contains_protected(relative: &str) -> bool {
    relative
        .split('/')
        .any(|part| part.eq_ignore_ascii_case(".git") || part.eq_ignore_ascii_case("target"))
}

fn render_diff(path: &str, hunks: &[Hunk]) -> String {
    let mut out = String::new();
    out.push_str("--- a/");
    out.push_str(path);
    out.push('\n');
    out.push_str("+++ b/");
    out.push_str(path);
    out.push('\n');
    let mut new_cursor = 1usize;
    for hunk in hunks {
        let new_start = if hunk.new_len == 0 { 0 } else { new_cursor };
        out.push_str(&format!(
            "@@ -{},{} +{},{} @@\n",
            hunk.old_start, hunk.old_len, new_start, hunk.new_len
        ));
        for line in &hunk.lines {
            match line {
                HunkLine::Context(text) => {
                    out.push(' ');
                    out.push_str(text);
                    new_cursor += 1;
                }
                HunkLine::Delete(text) => {
                    out.push('-');
                    out.push_str(text);
                }
                HunkLine::Add(text) => {
                    out.push('+');
                    out.push_str(text);
                    new_cursor += 1;
                }
            }
            out.push('\n');
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn compute_binding(
    action_id: u64,
    workspace: &str,
    relative: &str,
    identity: FileIdentity,
    platform: BoundFileId,
    original_hash: &[u8; 32],
    new_hash: &[u8; 32],
    patch_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buffer = Vec::new();
    push_part(&mut buffer, b"LCA-01G-APPROVAL-V2");
    push_part(&mut buffer, &action_id.to_le_bytes());
    push_part(&mut buffer, workspace.as_bytes());
    push_part(&mut buffer, relative.as_bytes());
    push_part(&mut buffer, &identity.created().to_le_bytes());
    push_part(&mut buffer, &identity.modified().to_le_bytes());
    push_part(&mut buffer, &identity.len().to_le_bytes());
    push_part(&mut buffer, &platform.volume_serial.to_le_bytes());
    push_part(&mut buffer, &platform.file_id);
    push_part(&mut buffer, original_hash);
    push_part(&mut buffer, new_hash);
    push_part(&mut buffer, patch_hash);
    sha256(&buffer)
}

fn capture_platform(root: &Path, relative: &str) -> Result<BoundFileId, FsError> {
    let components: Vec<String> = relative
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect();
    match lca_platform::stat_tree(root, &components) {
        Ok(info) => {
            if info.is_reparse() {
                return Err(FsError::ReparseDenied {
                    path: relative.to_owned(),
                });
            }
            if info.file_id() == [0; 16] {
                return Err(FsError::UnverifiableIdentity {
                    path: relative.to_owned(),
                });
            }
            if !info.is_directory() && info.link_count() != 1 {
                return Err(FsError::HardlinkDenied {
                    path: relative.to_owned(),
                });
            }
            Ok(BoundFileId {
                volume_serial: info.volume_serial(),
                file_id: info.file_id(),
            })
        }
        Err(lca_platform::PlatformError::Unsupported) => Ok(BoundFileId {
            volume_serial: 0,
            file_id: [0; 16],
        }),
        Err(error) => Err(FsError::Io {
            path: relative.to_owned(),
            message: error.to_string(),
        }),
    }
}

#[cfg(not(windows))]
fn refuse_armed_fault(fault: ApplyFault) -> Result<(), FsError> {
    if let Some(point) = fault.phase_name() {
        Err(FsError::FaultInjected {
            point,
            published: false,
        })
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn apply_ntfs(
    prepared: &PreparedPatch,
    used: &mut std::collections::HashSet<[u8; 32]>,
    fault: ApplyFault,
    hold: Option<&KillHold>,
    preimage: &mut dyn FnMut(&[u8]) -> Result<(), FsError>,
    audit: &mut dyn FnMut(&str) -> Result<(), FsError>,
) -> Result<(), FsError> {
    if prepared.platform.file_id == [0; 16] {
        return Err(FsError::UnverifiableIdentity {
            path: prepared.relative_path.clone(),
        });
    }
    let components: Vec<String> = prepared
        .relative_path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect();
    let mut opened = lca_platform::open_tree(&prepared.workspace_root, &components)
        .map_err(|error| map_platform(&prepared.relative_path, error))?;
    let info = opened.info();
    if info.volume_serial() != prepared.platform.volume_serial
        || info.file_id() != prepared.platform.file_id
    {
        return Err(FsError::IdentityChanged {
            path: prepared.relative_path.clone(),
        });
    }
    if info.is_reparse() {
        return Err(FsError::ReparseDenied {
            path: prepared.relative_path.clone(),
        });
    }
    if info.link_count() != 1 {
        return Err(FsError::HardlinkDenied {
            path: prepared.relative_path.clone(),
        });
    }
    let current = opened
        .read(READ_CAP)
        .map_err(|error| map_platform(&prepared.relative_path, error))?;
    if sha256(&current) != prepared.original_hash {
        return Err(FsError::Conflict {
            path: prepared.relative_path.clone(),
        });
    }
    preimage(&current)?;
    if fault == ApplyFault::AfterIntent {
        return Err(FsError::FaultInjected {
            point: "after_intent",
            published: false,
        });
    }
    if let Some(hold) = hold {
        hold.park_at(ApplyFault::AfterIntent);
    }
    used.insert(prepared.binding);
    let mut injected = None;
    let mut audit_error = None;
    let mut hook = |phase: lca_platform::PublishPhase| -> Result<(), lca_platform::PlatformError> {
        let event = match phase {
            lca_platform::PublishPhase::AfterStageFlush => Some("stage_flushed"),
            lca_platform::PublishPhase::BeforeRename => Some("mutation_started"),
            lca_platform::PublishPhase::AfterRename => Some("mutation_published"),
            _ => None,
        };
        let holding = hold.is_some_and(|item| fault_matches(item.point, phase));
        if fault_matches(fault, phase) && !holding {
            injected = Some(fault.phase_name().unwrap_or("fault"));
            return Err(if phase == lca_platform::PublishPhase::DuringReadback {
                lca_platform::PlatformError::Verify
            } else {
                lca_platform::PlatformError::Injected
            });
        }
        if let Some(event) = event
            && let Err(error) = audit(event)
        {
            audit_error = Some(error);
            return Err(lca_platform::PlatformError::Io(
                "audit record could not be written".to_owned(),
            ));
        }
        if let Some(hold) = hold {
            hold.park_at(fault_phase(phase));
        }
        Ok(())
    };
    let replaced = opened.replace_with(
        &prepared.new_bytes,
        &prepared.workspace_root,
        &components,
        &mut hook,
    );
    let readback = replaced.map_err(|failure| {
        if let Some(error) = audit_error.take() {
            return error;
        }
        map_publish(&prepared.relative_path, failure, injected.take())
    })?;
    if sha256(&readback) != prepared.new_hash {
        return Err(FsError::VerifyFailed {
            path: prepared.relative_path.clone(),
        });
    }
    Ok(())
}

fn fault_phase(phase: lca_platform::PublishPhase) -> ApplyFault {
    match phase {
        lca_platform::PublishPhase::AfterTempCreate => ApplyFault::AfterTempCreate,
        lca_platform::PublishPhase::AfterWrite => ApplyFault::AfterWrite,
        lca_platform::PublishPhase::AfterStageFlush => ApplyFault::AfterStageFlush,
        lca_platform::PublishPhase::BeforeRename => ApplyFault::BeforeRename,
        lca_platform::PublishPhase::DuringPublish => ApplyFault::DuringPublish,
        lca_platform::PublishPhase::AfterRename => ApplyFault::AfterRename,
        lca_platform::PublishPhase::BeforeReadback => ApplyFault::BeforeReadback,
        lca_platform::PublishPhase::DuringReadback => ApplyFault::DuringReadback,
    }
}

fn fault_matches(fault: ApplyFault, phase: lca_platform::PublishPhase) -> bool {
    matches!(
        (fault, phase),
        (
            ApplyFault::AfterTempCreate,
            lca_platform::PublishPhase::AfterTempCreate
        ) | (
            ApplyFault::AfterWrite,
            lca_platform::PublishPhase::AfterWrite
        ) | (
            ApplyFault::AfterStageFlush,
            lca_platform::PublishPhase::AfterStageFlush
        ) | (
            ApplyFault::BeforeRename,
            lca_platform::PublishPhase::BeforeRename
        ) | (
            ApplyFault::DuringPublish,
            lca_platform::PublishPhase::DuringPublish
        ) | (
            ApplyFault::AfterRename,
            lca_platform::PublishPhase::AfterRename
        ) | (
            ApplyFault::BeforeReadback,
            lca_platform::PublishPhase::BeforeReadback
        ) | (
            ApplyFault::DuringReadback,
            lca_platform::PublishPhase::DuringReadback
        )
    )
}

fn map_publish(
    path: &str,
    failure: lca_platform::PublishFailure,
    injected: Option<&'static str>,
) -> FsError {
    let published = failure.published();
    match failure.error() {
        lca_platform::PlatformError::Verify => FsError::VerifyFailed {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::Injected => FsError::FaultInjected {
            point: injected.unwrap_or("fault"),
            published,
        },
        other => map_platform(path, other.clone()),
    }
}

fn map_platform(path: &str, error: lca_platform::PlatformError) -> FsError {
    match error {
        lca_platform::PlatformError::Unsupported => FsError::UnsupportedPlatform,
        lca_platform::PlatformError::Reparse => FsError::ReparseDenied {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::Hardlink => FsError::HardlinkDenied {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::Identity => FsError::IdentityChanged {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::NotFound => FsError::NotFound {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::NotFile => FsError::NotAFile {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::Verify => FsError::VerifyFailed {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::Injected => FsError::FaultInjected {
            point: "fault",
            published: false,
        },
        lca_platform::PlatformError::Sharing => FsError::WriteFailed {
            path: path.to_owned(),
            message: "target file is busy".to_owned(),
        },
        lca_platform::PlatformError::Acl => FsError::StoreUnavailable {
            message: "directory ACL is not restricted".to_owned(),
        },
        lca_platform::PlatformError::Protect => FsError::ProposalInvalid {
            message: "local protection check failed".to_owned(),
        },
        lca_platform::PlatformError::Io(message) => FsError::WriteFailed {
            path: path.to_owned(),
            message,
        },
    }
}

fn push_part(buffer: &mut Vec<u8>, part: &[u8]) {
    let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
    buffer.extend_from_slice(&len.to_le_bytes());
    buffer.extend_from_slice(part);
}

pub(crate) fn restore_prepared(stored: StoredPatch) -> PreparedPatch {
    let binding = compute_binding(
        stored.action_id,
        &stored.workspace_root.to_string_lossy(),
        &stored.relative_path,
        stored.identity,
        stored.platform,
        &stored.original_hash,
        &stored.new_hash,
        &stored.patch_hash,
    );
    PreparedPatch {
        action_id: stored.action_id,
        workspace_root: stored.workspace_root,
        relative_path: stored.relative_path,
        identity: stored.identity,
        platform: stored.platform,
        original_hash: stored.original_hash,
        new_hash: stored.new_hash,
        patch_hash: stored.patch_hash,
        new_bytes: stored.new_bytes,
        patch_text: stored.patch_text,
        diff: stored.diff,
        binding,
        line_ending: stored.line_ending,
    }
}

pub(crate) struct StoredPatch {
    pub action_id: u64,
    pub workspace_root: PathBuf,
    pub relative_path: String,
    pub identity: FileIdentity,
    pub platform: BoundFileId,
    pub original_hash: [u8; 32],
    pub new_hash: [u8; 32],
    pub patch_hash: [u8; 32],
    pub new_bytes: Vec<u8>,
    pub patch_text: String,
    pub diff: String,
    pub line_ending: &'static str,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg_attr(windows, allow(dead_code))]
struct TempCleanup<'a> {
    path: &'a Path,
    armed: bool,
}

impl Drop for TempCleanup<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}
