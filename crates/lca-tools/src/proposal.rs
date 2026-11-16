//! Persistent patch proposals.
//!
//! A proposal stores the exact new bytes outside the workspace. DPAPI binds the ciphertext
//! to the current Windows user. The directory ACL must stay owner-only. A SHA-256 digest
//! identifies the reviewed bytes; it is not an authentication key. `approve` writes only
//! through [`crate::fs::apply_granted`] after a fresh human confirmation.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::fs::{
    ApplyFault, ApplyResult, ApprovalGrant, ApprovalLedger, BoundFileId, FsLimits, PreparedPatch,
    StoredPatch, apply_granted_controlled, restore_prepared,
};
use crate::fs_error::FsError;
use crate::pathutil::paths_equivalent;
use crate::sandbox::{FileIdentity, WorkspaceSandbox};

const CONTRACT_VERSION: u32 = 1;
const TTL_SECS: u64 = 24 * 60 * 60;
const MAX_PATH: usize = 4096;
const MAX_PROPOSED: usize = 16 * 1024 * 1024;
const MAX_PATCH: usize = 64 * 1024;
const MAX_DIFF: usize = 256 * 1024;

/// One stored proposal the CLI can list without printing file bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalSummary {
    /// Proposal UUID.
    pub id: String,
    /// Workspace-relative target.
    pub path: String,
    /// Lifecycle state name.
    pub state: String,
    /// Unix expiry.
    pub expires_at: u64,
    /// SHA-256 of the original bytes.
    pub original_hash: String,
    /// SHA-256 of the proposed bytes.
    pub proposed_hash: String,
}

/// The review view. `diff` is the prepared unified diff, not a second patch engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalView {
    /// Identity and hashes.
    pub summary: ProposalSummary,
    /// Full proposal digest. Approval is bound to this value.
    pub digest: String,
    /// Exact confirmation line.
    pub confirmation: String,
    /// Unified diff.
    pub diff: String,
    /// Target volume serial.
    pub volume_serial: u64,
    /// Target file id, hex encoded.
    pub file_id: String,
    /// `matches_original`, `matches_proposed`, `changed`, `unreadable`, or `unchecked`.
    pub target_status: String,
}

/// Protected proposal directory.
#[derive(Debug, Clone)]
pub struct ProposalStore {
    root: PathBuf,
}

impl ProposalStore {
    /// Opens `root`, restricts its ACL, and fails closed when that cannot be done.
    pub fn open(root: &Path) -> Result<Self, FsError> {
        fs::create_dir_all(root).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        let store = Self {
            root: root.to_path_buf(),
        };
        store.protect_root()?;
        Ok(store)
    }

    /// `%LOCALAPPDATA%\lca`, or `LCA_STATE_DIR` when that variable is set.
    ///
    /// The variable only relocates the same protected store. It does not approve a write.
    pub fn user_local() -> Result<Self, FsError> {
        let root = if let Some(path) = std::env::var_os("LCA_STATE_DIR") {
            PathBuf::from(path)
        } else {
            let base =
                std::env::var_os("LOCALAPPDATA").ok_or_else(|| FsError::StoreUnavailable {
                    message: "LOCALAPPDATA is not set".to_owned(),
                })?;
            PathBuf::from(base).join("lca")
        };
        Self::open(&root)
    }

    /// Persists `prepared` and returns its id. The workspace file is not modified.
    pub fn save(
        &self,
        sandbox: &WorkspaceSandbox,
        prepared: &PreparedPatch,
    ) -> Result<ProposalSummary, FsError> {
        self.protect_root()?;
        if !lca_platform::verified_apply_supported() || prepared.platform_id().file_id == [0; 16] {
            return Err(FsError::UnsupportedPlatform);
        }
        let workspace = workspace_identity(sandbox)?;
        let now = unix_now();
        let id = Uuid::new_v4();
        let mut record = Record {
            id,
            action_id: prepared.action_id(),
            contract_version: CONTRACT_VERSION,
            workspace_volume: workspace.volume_serial,
            workspace_file_id: workspace.file_id,
            workspace_path: workspace.path.clone(),
            relative_path: prepared.relative_path().to_owned(),
            created_at: now,
            expires_at: now.saturating_add(TTL_SECS),
            original_hash: prepared.original_hash(),
            proposed_hash: prepared.new_hash(),
            patch_hash: prepared.patch_hash(),
            original_size: prepared.file_identity().len(),
            proposed_size: u64::try_from(prepared.new_bytes().len()).unwrap_or(u64::MAX),
            target_volume: prepared.platform_id().volume_serial,
            target_file_id: prepared.platform_id().file_id,
            identity_created: prepared.file_identity().created(),
            identity_modified: prepared.file_identity().modified(),
            identity_len: prepared.file_identity().len(),
            line_ending: u8::from(prepared.line_ending() == "crlf"),
            proposed: prepared.new_bytes().to_vec(),
            patch_text: prepared.patch_text().to_owned(),
            diff: prepared.diff().to_owned(),
            state: State::Prepared,
            digest: [0; 32],
        };
        record.digest = record.canonical_digest()?;
        self.write_record(&workspace, &record)?;
        self.audit(&workspace, "created", &record)?;
        Ok(record.summary())
    }

    /// Lists proposals for this workspace. Undecryptable files are reported as invalid.
    pub fn list(&self, sandbox: &WorkspaceSandbox) -> Result<Vec<ProposalSummary>, FsError> {
        self.protect_root()?;
        let workspace = workspace_identity(sandbox)?;
        let dir = self.proposal_dir(&workspace);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = fs::read_dir(&dir)
            .map_err(|error| FsError::StoreUnavailable {
                message: error.to_string(),
            })?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".lcap"))
            .collect::<Vec<_>>();
        names.sort();
        let mut summaries = Vec::new();
        for name in names {
            let id = name.trim_end_matches(".lcap");
            match self.load(&workspace, id) {
                Ok(record) => summaries.push(record.summary()),
                Err(_) => summaries.push(ProposalSummary {
                    id: id.to_owned(),
                    path: String::new(),
                    state: "invalid".to_owned(),
                    expires_at: 0,
                    original_hash: String::new(),
                    proposed_hash: String::new(),
                }),
            }
        }
        Ok(summaries)
    }

    /// Checks integrity, records that the diff was shown, and returns the review view.
    pub fn show(&self, sandbox: &WorkspaceSandbox, id: &str) -> Result<ProposalView, FsError> {
        self.with_record(sandbox, id, true, |record, workspace| {
            self.audit(workspace, "shown", record)?;
            let mut view = record.view();
            view.target_status = target_status(sandbox, record);
            Ok(view)
        })
    }

    /// Reconciles a crash and returns the state. It does not write the target file.
    pub fn status(&self, sandbox: &WorkspaceSandbox, id: &str) -> Result<ProposalSummary, FsError> {
        self.with_record(sandbox, id, true, |record, _workspace| Ok(record.summary()))
    }

    /// Marks a prepared or approved proposal rejected.
    pub fn reject(&self, sandbox: &WorkspaceSandbox, id: &str) -> Result<ProposalSummary, FsError> {
        self.with_record(sandbox, id, true, |record, workspace| {
            transition(record.state, State::Rejected)?;
            record.state = State::Rejected;
            self.write_record(workspace, record)?;
            self.audit(workspace, "rejected", record)?;
            Ok(record.summary())
        })
    }

    /// Applies one reviewed proposal. `line` must match the digest in `shown_digest`.
    ///
    /// The caller has to have read that digest from an interactive console. This function
    /// does not accept a model document as approval and does not call a model.
    pub fn approve(
        &self,
        sandbox: &WorkspaceSandbox,
        limits: &FsLimits,
        id: &str,
        shown_digest: &str,
        line: &str,
    ) -> Result<ApplyResult, FsError> {
        self.approve_with(sandbox, limits, id, shown_digest, line, ApplyFault::none())
    }

    /// Same as [`Self::approve`], with one deterministic fault point.
    ///
    /// [`ApplyFault::None`] is what production commands pass. Any other value is a test.
    pub fn approve_with(
        &self,
        sandbox: &WorkspaceSandbox,
        limits: &FsLimits,
        id: &str,
        shown_digest: &str,
        line: &str,
        fault: ApplyFault,
    ) -> Result<ApplyResult, FsError> {
        if !limits.write_enabled() {
            return Err(FsError::ToolDisabled {
                tool: "apply_patch".to_owned(),
            });
        }
        self.with_record(sandbox, id, true, |record, workspace| {
            if matches!(record.state, State::Prepared | State::Approved)
                && unix_now() >= record.expires_at
            {
                record.state = State::Expired;
                self.write_record(workspace, record)?;
                self.audit(workspace, "expired", record)?;
                return Err(FsError::ProposalExpired);
            }
            if !matches!(record.state, State::Prepared | State::Approved) {
                return Err(FsError::ApprovalConsumed);
            }
            if shown_digest != hex_encode(&record.digest) || shown_digest.len() != 64 {
                return Err(FsError::ApprovalMismatch);
            }
            let expected = format!("approve {} {}", record.id, &shown_digest[..16]);
            if line != expected {
                return Err(FsError::ApprovalRejected);
            }
            if fault == ApplyFault::AfterValidation {
                return Err(FsError::FaultInjected {
                    point: "after_validation",
                    published: false,
                });
            }
            let reloaded = self.load(workspace, &record.id.to_string())?;
            if reloaded.digest != record.digest {
                return Err(FsError::ApprovalMismatch);
            }
            transition(record.state, State::Approved)?;
            record.state = State::Approved;
            self.write_record(workspace, record)?;
            self.audit(workspace, "approved", record)?;
            if fault == ApplyFault::AfterApproval {
                return Err(FsError::FaultInjected {
                    point: "after_approval",
                    published: false,
                });
            }
            let again = self.load(workspace, &record.id.to_string())?;
            if again.digest != record.digest || again.state != State::Approved {
                return Err(FsError::ApprovalMismatch);
            }
            *record = again;
            transition(record.state, State::Applying)?;
            record.state = State::Applying;
            self.write_record(workspace, record)?;
            self.audit(workspace, "apply_started", record)?;
            let prepared = record.to_prepared(sandbox)?;
            let grant = ApprovalGrant::issue(&prepared, &prepared.confirmation_line())?;
            let outcome = {
                let mut trace = |event: &str| self.audit(workspace, event, record);
                apply_granted_controlled(
                    sandbox,
                    &prepared,
                    grant,
                    &ApprovalLedger::new(),
                    fault,
                    &mut trace,
                )
            };
            match outcome {
                Ok(result) => {
                    self.audit(workspace, "verified", record)?;
                    if fault == ApplyFault::AfterVerification {
                        return Err(FsError::FaultInjected {
                            point: "after_verification",
                            published: true,
                        });
                    }
                    record.state = State::Applied;
                    self.write_record(workspace, record)?;
                    if fault == ApplyFault::BeforeAudit {
                        return Err(FsError::FaultInjected {
                            point: "before_audit",
                            published: true,
                        });
                    }
                    self.audit(workspace, "apply_succeeded", record)?;
                    Ok(result)
                }
                Err(error) => {
                    record.state = state_after_failure(&error);
                    let event = match &error {
                        FsError::VerifyFailed { .. } => "verification_failed",
                        FsError::FaultInjected {
                            published: true, ..
                        } => "state_unclear",
                        FsError::Conflict { .. } | FsError::IdentityChanged { .. } => "conflict",
                        _ => "apply_failed",
                    };
                    self.write_record(workspace, record)?;
                    self.audit(workspace, event, record)?;
                    if matches!(record.state, State::Unclear) && event != "state_unclear" {
                        self.audit(workspace, "state_unclear", record)?;
                    }
                    Err(error)
                }
            }
        })
    }

    fn with_record<T>(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
        reconcile_file: bool,
        body: impl FnOnce(&mut Record, &WorkspaceIdentity) -> Result<T, FsError>,
    ) -> Result<T, FsError> {
        self.protect_root()?;
        let workspace = workspace_identity(sandbox)?;
        let parsed = Uuid::parse_str(id).map_err(|_| FsError::ProposalInvalid {
            message: "proposal id is not a UUID".to_owned(),
        })?;
        let lock_path = self.proposal_dir(&workspace).join(format!("{parsed}.lock"));
        let _lock = lca_platform::try_lock_exclusive(&lock_path).map_err(|error| {
            FsError::StoreUnavailable {
                message: error.to_string(),
            }
        })?;
        let mut record = self.load(&workspace, &parsed.to_string())?;
        if reconcile_file {
            self.reconcile(sandbox, &workspace, &mut record)?;
        }
        body(&mut record, &workspace)
    }

    fn reconcile(
        &self,
        sandbox: &WorkspaceSandbox,
        workspace: &WorkspaceIdentity,
        record: &mut Record,
    ) -> Result<(), FsError> {
        if matches!(record.state, State::Prepared | State::Approved)
            && unix_now() >= record.expires_at
        {
            record.state = State::Expired;
            self.write_record(workspace, record)?;
            self.audit(workspace, "expired", record)?;
            return Ok(());
        }
        if !matches!(record.state, State::Applying | State::Unclear) {
            return Ok(());
        }
        let next = classify_target(sandbox, record);
        if next == record.state {
            return Ok(());
        }
        let event = match next {
            State::Applied | State::Failed => "recovered",
            State::Unclear => "state_unclear",
            _ => "conflict",
        };
        record.state = next;
        self.write_record(workspace, record)?;
        self.audit(workspace, event, record)?;
        Ok(())
    }

    fn protect_root(&self) -> Result<(), FsError> {
        lca_platform::restrict_directory(&self.root).map_err(|_| FsError::StoreUnavailable {
            message: "proposal directory ACL could not be restricted".to_owned(),
        })?;
        lca_platform::require_restricted(&self.root).map_err(|_| FsError::StoreUnavailable {
            message: "proposal directory ACL is not restricted to the current user".to_owned(),
        })
    }

    fn proposal_dir(&self, workspace: &WorkspaceIdentity) -> PathBuf {
        self.root.join("proposals").join(workspace.key())
    }

    fn load(&self, workspace: &WorkspaceIdentity, id: &str) -> Result<Record, FsError> {
        let path = self.proposal_dir(workspace).join(format!("{id}.lcap"));
        let ciphertext = fs::read(&path).map_err(|_| FsError::ProposalInvalid {
            message: "proposal was not found".to_owned(),
        })?;
        let plaintext =
            lca_platform::unprotect(&ciphertext).map_err(|_| FsError::ProposalInvalid {
                message: "proposal protection check failed".to_owned(),
            })?;
        let record = Record::decode(&plaintext)?;
        if record.id.to_string() != id {
            return Err(FsError::ProposalInvalid {
                message: "proposal id does not match the file name".to_owned(),
            });
        }
        if record.canonical_digest()? != record.digest {
            return Err(FsError::ProposalInvalid {
                message: "proposal digest does not match its body".to_owned(),
            });
        }
        if record.workspace_volume != workspace.volume_serial
            || record.workspace_file_id != workspace.file_id
            || !paths_equivalent(
                Path::new(&record.workspace_path),
                Path::new(&workspace.path),
            )
        {
            return Err(FsError::WorkspaceMismatch);
        }
        Ok(record)
    }

    fn write_record(&self, workspace: &WorkspaceIdentity, record: &Record) -> Result<(), FsError> {
        let dir = self.proposal_dir(workspace);
        fs::create_dir_all(&dir).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        let plaintext = record.encode()?;
        let ciphertext =
            lca_platform::protect(&plaintext).map_err(|_| FsError::StoreUnavailable {
                message: "proposal bytes could not be protected".to_owned(),
            })?;
        let final_path = dir.join(format!("{}.lcap", record.id));
        let partial = dir.join(format!("{}.partial", record.id));
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&partial)
                .map_err(|error| FsError::StoreUnavailable {
                    message: error.to_string(),
                })?;
            file.write_all(&ciphertext)
                .map_err(|error| FsError::StoreUnavailable {
                    message: error.to_string(),
                })?;
            file.sync_all().map_err(|error| FsError::StoreUnavailable {
                message: error.to_string(),
            })?;
        }
        fs::rename(&partial, &final_path).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        Ok(())
    }

    fn audit(
        &self,
        workspace: &WorkspaceIdentity,
        event: &str,
        record: &Record,
    ) -> Result<(), FsError> {
        let dir = self.root.join("audit").join(workspace.key());
        fs::create_dir_all(&dir).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        let lock_path = dir.join("audit.lock");
        let _lock = lca_platform::try_lock_exclusive(&lock_path).map_err(|error| {
            FsError::StoreUnavailable {
                message: error.to_string(),
            }
        })?;
        let seq_path = dir.join("seq");
        let next = read_seq(&seq_path)?.saturating_add(1);
        let line = serde_json::json!({
            "seq": next,
            "event": event,
            "proposal_id": record.id.to_string(),
            "digest": hex_encode(&record.digest),
            "state": record.state.as_str(),
            "path": record.relative_path,
            "at": unix_now(),
        });
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("events.log"))
            .map_err(|error| FsError::StoreUnavailable {
                message: error.to_string(),
            })?;
        writeln!(file, "{line}").map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        file.sync_all().map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        fs::write(&seq_path, next.to_string()).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        Ok(())
    }
}

struct WorkspaceIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
    path: String,
}

impl WorkspaceIdentity {
    fn key(&self) -> String {
        let mut buffer = Vec::new();
        push_part(&mut buffer, b"LCA-01G-WORKSPACE-V1");
        push_part(&mut buffer, &self.volume_serial.to_le_bytes());
        push_part(&mut buffer, &self.file_id);
        push_part(&mut buffer, self.path.as_bytes());
        hex_encode(&sha256(&buffer))
    }
}

fn workspace_identity(sandbox: &WorkspaceSandbox) -> Result<WorkspaceIdentity, FsError> {
    let info = lca_platform::inspect(sandbox.root()).map_err(|error| match error {
        lca_platform::PlatformError::Unsupported => FsError::UnsupportedPlatform,
        other => FsError::StoreUnavailable {
            message: other.to_string(),
        },
    })?;
    if info.is_reparse() || !info.is_directory() || info.file_id() == [0; 16] {
        return Err(FsError::UnverifiableIdentity {
            path: ".".to_owned(),
        });
    }
    Ok(WorkspaceIdentity {
        volume_serial: info.volume_serial(),
        file_id: info.file_id(),
        path: sandbox.root().to_string_lossy().into_owned(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Prepared,
    Approved,
    Applying,
    Applied,
    Rejected,
    Expired,
    Conflict,
    Failed,
    Unclear,
}

impl State {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Approved => "approved",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Conflict => "conflict",
            Self::Failed => "failed",
            Self::Unclear => "unclear",
        }
    }

    fn from_byte(byte: u8) -> Result<Self, FsError> {
        Ok(match byte {
            1 => Self::Prepared,
            2 => Self::Approved,
            3 => Self::Applying,
            4 => Self::Applied,
            5 => Self::Rejected,
            6 => Self::Expired,
            7 => Self::Conflict,
            8 => Self::Failed,
            9 => Self::Unclear,
            _ => {
                return Err(FsError::ProposalInvalid {
                    message: "proposal state is not recognized".to_owned(),
                });
            }
        })
    }

    const fn to_byte(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Approved => 2,
            Self::Applying => 3,
            Self::Applied => 4,
            Self::Rejected => 5,
            Self::Expired => 6,
            Self::Conflict => 7,
            Self::Failed => 8,
            Self::Unclear => 9,
        }
    }
}

fn transition(from: State, to: State) -> Result<(), FsError> {
    let allowed = matches!(
        (from, to),
        (State::Prepared, State::Approved)
            | (State::Prepared, State::Rejected)
            | (State::Prepared, State::Expired)
            | (State::Approved, State::Applying)
            | (State::Approved, State::Rejected)
            | (State::Approved, State::Expired)
            | (State::Approved, State::Conflict)
            | (State::Applying, State::Applied)
            | (State::Applying, State::Failed)
            | (State::Applying, State::Conflict)
            | (State::Applying, State::Unclear)
            | (State::Unclear, State::Applied)
            | (State::Unclear, State::Failed)
    );
    if allowed {
        Ok(())
    } else {
        Err(FsError::ProposalInvalid {
            message: "proposal state transition is not allowed".to_owned(),
        })
    }
}

fn state_after_failure(error: &FsError) -> State {
    match error {
        FsError::VerifyFailed { .. } => State::Unclear,
        FsError::FaultInjected {
            published: true, ..
        } => State::Unclear,
        FsError::Conflict { .. } | FsError::IdentityChanged { .. } => State::Conflict,
        _ => State::Failed,
    }
}

fn classify_target(sandbox: &WorkspaceSandbox, record: &Record) -> State {
    let components: Vec<String> = record
        .relative_path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect();
    let info = match lca_platform::stat_tree(sandbox.root(), &components) {
        Ok(info) => info,
        Err(_) => return State::Unclear,
    };
    if info.is_reparse()
        || info.is_directory()
        || info.link_count() != 1
        || info.file_id() == [0; 16]
    {
        return State::Unclear;
    }
    let bytes = match sandbox.read_bytes(&record.relative_path, MAX_PROPOSED as u64) {
        Ok(bytes) => bytes,
        Err(_) => return State::Unclear,
    };
    let hash = sha256(&bytes);
    let same_object =
        info.file_id() == record.target_file_id && info.volume_serial() == record.target_volume;
    if hash == record.proposed_hash && same_object {
        State::Applied
    } else if hash == record.original_hash && same_object {
        State::Failed
    } else {
        State::Unclear
    }
}

struct Record {
    id: Uuid,
    action_id: u64,
    contract_version: u32,
    workspace_volume: u64,
    workspace_file_id: [u8; 16],
    workspace_path: String,
    relative_path: String,
    created_at: u64,
    expires_at: u64,
    original_hash: [u8; 32],
    proposed_hash: [u8; 32],
    patch_hash: [u8; 32],
    original_size: u64,
    proposed_size: u64,
    target_volume: u64,
    target_file_id: [u8; 16],
    identity_created: u64,
    identity_modified: u64,
    identity_len: u64,
    line_ending: u8,
    proposed: Vec<u8>,
    patch_text: String,
    diff: String,
    state: State,
    digest: [u8; 32],
}

impl Record {
    fn canonical_digest(&self) -> Result<[u8; 32], FsError> {
        Ok(sha256(&self.canonical()?))
    }

    fn canonical(&self) -> Result<Vec<u8>, FsError> {
        let mut buffer = Vec::new();
        push_part(&mut buffer, b"LCA-01G-PROPOSAL-V1");
        push_part(&mut buffer, &self.contract_version.to_le_bytes());
        push_part(&mut buffer, self.id.as_bytes());
        push_part(&mut buffer, &self.action_id.to_le_bytes());
        push_part(&mut buffer, &self.workspace_volume.to_le_bytes());
        push_part(&mut buffer, &self.workspace_file_id);
        push_part(&mut buffer, self.workspace_path.as_bytes());
        push_part(&mut buffer, self.relative_path.as_bytes());
        push_part(&mut buffer, &self.created_at.to_le_bytes());
        push_part(&mut buffer, &self.expires_at.to_le_bytes());
        push_part(&mut buffer, &self.original_hash);
        push_part(&mut buffer, &self.proposed_hash);
        push_part(&mut buffer, &self.patch_hash);
        push_part(&mut buffer, &self.original_size.to_le_bytes());
        push_part(&mut buffer, &self.proposed_size.to_le_bytes());
        push_part(&mut buffer, &self.target_volume.to_le_bytes());
        push_part(&mut buffer, &self.target_file_id);
        push_part(&mut buffer, &self.identity_created.to_le_bytes());
        push_part(&mut buffer, &self.identity_modified.to_le_bytes());
        push_part(&mut buffer, &self.identity_len.to_le_bytes());
        push_part(&mut buffer, &[self.line_ending]);
        push_part(&mut buffer, &self.proposed);
        push_part(&mut buffer, self.patch_text.as_bytes());
        push_part(&mut buffer, self.diff.as_bytes());
        Ok(buffer)
    }

    fn encode(&self) -> Result<Vec<u8>, FsError> {
        let mut body = self.canonical()?;
        body.push(self.state.to_byte());
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    fn decode(bytes: &[u8]) -> Result<Self, FsError> {
        if bytes.len() < 33 {
            return Err(FsError::ProposalInvalid {
                message: "proposal body is truncated".to_owned(),
            });
        }
        let (body, tail) = bytes.split_at(bytes.len() - 33);
        let state = State::from_byte(tail[0])?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&tail[1..]);
        let mut cursor = body;
        let label = read_part(&mut cursor, 64)?;
        if label != b"LCA-01G-PROPOSAL-V1" {
            return Err(FsError::ProposalInvalid {
                message: "proposal contract label is not recognized".to_owned(),
            });
        }
        let contract_version = read_u32(&mut cursor)?;
        if contract_version != CONTRACT_VERSION {
            return Err(FsError::ProposalInvalid {
                message: "proposal contract version is not supported".to_owned(),
            });
        }
        let id_bytes = read_array::<16>(&mut cursor)?;
        let id = Uuid::from_bytes(id_bytes);
        let action_id = read_u64(&mut cursor)?;
        let workspace_volume = read_u64(&mut cursor)?;
        let workspace_file_id = read_array::<16>(&mut cursor)?;
        let workspace_path = read_text(&mut cursor, MAX_PATH)?;
        let relative_path = read_text(&mut cursor, MAX_PATH)?;
        let created_at = read_u64(&mut cursor)?;
        let expires_at = read_u64(&mut cursor)?;
        let original_hash = read_array::<32>(&mut cursor)?;
        let proposed_hash = read_array::<32>(&mut cursor)?;
        let patch_hash = read_array::<32>(&mut cursor)?;
        let original_size = read_u64(&mut cursor)?;
        let proposed_size = read_u64(&mut cursor)?;
        let target_volume = read_u64(&mut cursor)?;
        let target_file_id = read_array::<16>(&mut cursor)?;
        let identity_created = read_u64(&mut cursor)?;
        let identity_modified = read_u64(&mut cursor)?;
        let identity_len = read_u64(&mut cursor)?;
        let ending = read_part(&mut cursor, 8)?;
        if ending.len() != 1 {
            return Err(FsError::ProposalInvalid {
                message: "proposal line ending is invalid".to_owned(),
            });
        }
        let proposed = read_part(&mut cursor, MAX_PROPOSED)?.to_vec();
        let patch_text = read_text(&mut cursor, MAX_PATCH)?;
        let diff = read_text(&mut cursor, MAX_DIFF)?;
        if !cursor.is_empty() {
            return Err(FsError::ProposalInvalid {
                message: "proposal body has trailing bytes".to_owned(),
            });
        }
        if proposed.len() as u64 != proposed_size {
            return Err(FsError::ProposalInvalid {
                message: "proposal size does not match its bytes".to_owned(),
            });
        }
        Ok(Self {
            id,
            action_id,
            contract_version,
            workspace_volume,
            workspace_file_id,
            workspace_path,
            relative_path,
            created_at,
            expires_at,
            original_hash,
            proposed_hash,
            patch_hash,
            original_size,
            proposed_size,
            target_volume,
            target_file_id,
            identity_created,
            identity_modified,
            identity_len,
            line_ending: ending[0],
            proposed,
            patch_text,
            diff,
            state,
            digest,
        })
    }

    fn summary(&self) -> ProposalSummary {
        ProposalSummary {
            id: self.id.to_string(),
            path: self.relative_path.clone(),
            state: self.state.as_str().to_owned(),
            expires_at: self.expires_at,
            original_hash: hex_encode(&self.original_hash),
            proposed_hash: hex_encode(&self.proposed_hash),
        }
    }

    fn view(&self) -> ProposalView {
        let digest = hex_encode(&self.digest);
        ProposalView {
            confirmation: format!("approve {} {}", self.id, &digest[..16]),
            digest,
            diff: self.diff.clone(),
            volume_serial: self.target_volume,
            file_id: hex_encode(&self.target_file_id),
            target_status: "unchecked".to_owned(),
            summary: self.summary(),
        }
    }

    fn to_prepared(&self, sandbox: &WorkspaceSandbox) -> Result<PreparedPatch, FsError> {
        if sha256(&self.proposed) != self.proposed_hash
            || sha256(self.patch_text.as_bytes()) != self.patch_hash
        {
            return Err(FsError::ProposalInvalid {
                message: "stored proposal bytes do not match their hashes".to_owned(),
            });
        }
        let line_ending = match self.line_ending {
            0 => "lf",
            1 => "crlf",
            _ => {
                return Err(FsError::ProposalInvalid {
                    message: "proposal line ending is invalid".to_owned(),
                });
            }
        };
        Ok(restore_prepared(StoredPatch {
            action_id: self.action_id,
            workspace_root: sandbox.root().to_path_buf(),
            relative_path: self.relative_path.clone(),
            identity: FileIdentity::from_parts(
                self.identity_created,
                self.identity_modified,
                self.identity_len,
            ),
            platform: BoundFileId {
                volume_serial: self.target_volume,
                file_id: self.target_file_id,
            },
            original_hash: self.original_hash,
            new_hash: self.proposed_hash,
            patch_hash: self.patch_hash,
            new_bytes: self.proposed.clone(),
            patch_text: self.patch_text.clone(),
            diff: self.diff.clone(),
            line_ending,
        }))
    }
}

fn push_part(buffer: &mut Vec<u8>, part: &[u8]) {
    let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
    buffer.extend_from_slice(&len.to_le_bytes());
    buffer.extend_from_slice(part);
}

fn read_part<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8], FsError> {
    if input.len() < 8 {
        return Err(FsError::ProposalInvalid {
            message: "proposal body is truncated".to_owned(),
        });
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&input[..8]);
    let len = usize::try_from(u64::from_le_bytes(raw)).map_err(|_| FsError::ProposalInvalid {
        message: "proposal field is too large".to_owned(),
    })?;
    if len > max {
        return Err(FsError::ProposalInvalid {
            message: "proposal field exceeds its limit".to_owned(),
        });
    }
    *input = &input[8..];
    if input.len() < len {
        return Err(FsError::ProposalInvalid {
            message: "proposal body is truncated".to_owned(),
        });
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

fn read_text(input: &mut &[u8], max: usize) -> Result<String, FsError> {
    let bytes = read_part(input, max)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| FsError::ProposalInvalid {
        message: "proposal text is not UTF-8".to_owned(),
    })
}

fn read_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], FsError> {
    let bytes = read_part(input, N)?;
    if bytes.len() != N {
        return Err(FsError::ProposalInvalid {
            message: "proposal field has the wrong size".to_owned(),
        });
    }
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

fn read_u32(input: &mut &[u8]) -> Result<u32, FsError> {
    let bytes = read_array::<4>(input)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(input: &mut &[u8]) -> Result<u64, FsError> {
    let bytes = read_array::<8>(input)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_seq(path: &Path) -> Result<u64, FsError> {
    if !path.exists() {
        return Ok(0);
    }
    let mut file = File::open(path).map_err(|error| FsError::StoreUnavailable {
        message: error.to_string(),
    })?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
    if text.trim().is_empty() {
        return Ok(0);
    }
    text.trim()
        .parse::<u64>()
        .map_err(|_| FsError::StoreUnavailable {
            message: "audit sequence is corrupt".to_owned(),
        })
}

fn target_status(sandbox: &WorkspaceSandbox, record: &Record) -> String {
    let max = u64::try_from(MAX_PROPOSED).unwrap_or(u64::MAX);
    match sandbox.read_bytes(&record.relative_path, max) {
        Ok(bytes) => {
            let hash = sha256(&bytes);
            if hash == record.original_hash {
                "matches_original".to_owned()
            } else if hash == record.proposed_hash {
                "matches_proposed".to_owned()
            } else {
                "changed".to_owned()
            }
        }
        Err(_) => "unreadable".to_owned(),
    }
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(all(windows, test))]
fn audit_text(state: &Path) -> String {
    let mut found = String::new();
    let audit = state.join("audit");
    let Ok(workspaces) = fs::read_dir(audit) else {
        return found;
    };
    for workspace in workspaces.flatten() {
        if let Ok(bytes) = fs::read(workspace.path().join("events.log")) {
            found.push_str(&String::from_utf8_lossy(&bytes));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{
        ActionIdFactory, ActionSource, ToolRegistry, propose_actions, validate_batch,
    };
    use crate::fs::{FsLimitValues, execute_validated};
    use crate::sandbox::WorkspaceSandbox;
    use serde_json::json;

    fn temp_workspace(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("lca-proposal-{label}-{nanos}"));
        fs::create_dir_all(&path).expect("temp");
        path
    }

    fn prepare(root: &Path) -> (WorkspaceSandbox, PreparedPatch) {
        fs::write(root.join("notes.txt"), "alpha\n").expect("seed");
        let sandbox = WorkspaceSandbox::new(root).expect("sandbox");
        let patch = "--- a/notes.txt\n+++ b/notes.txt\n@@ -1,1 +1,1 @@\n-alpha\n+beta\n";
        let registry = ToolRegistry::workspace().expect("registry");
        let proposed = propose_actions(
            &ActionIdFactory::new(),
            ActionSource::Native,
            [(
                "apply_patch".to_owned(),
                json!({"path": "notes.txt", "patch": patch}),
            )],
        );
        let batch = validate_batch(&registry, &proposed).expect("batch");
        let limits = FsLimits::try_new(FsLimitValues {
            read_enabled: true,
            write_enabled: true,
            max_file_size_bytes: 1024 * 1024,
            max_response_bytes: 256 * 1024,
            max_directory_entries: 100,
            max_search_matches: 20,
            max_search_files: 100,
            max_search_total_bytes: 1024 * 1024,
        })
        .expect("limits");
        let outcome = execute_validated(&batch.actions()[0], &sandbox, &limits).expect("prepare");
        let crate::fs::FsOutcome::Prepared(prepared) = outcome else {
            panic!("prepared");
        };
        (sandbox, *prepared)
    }

    fn limits() -> FsLimits {
        FsLimits::try_new(FsLimitValues {
            read_enabled: true,
            write_enabled: true,
            max_file_size_bytes: 1024 * 1024,
            max_response_bytes: 256 * 1024,
            max_directory_entries: 100,
            max_search_matches: 20,
            max_search_files: 100,
            max_search_total_bytes: 1024 * 1024,
        })
        .expect("limits")
    }

    #[test]
    fn transitions_are_single_use() {
        assert!(transition(State::Prepared, State::Approved).is_ok());
        assert!(transition(State::Approved, State::Applying).is_ok());
        assert!(transition(State::Applying, State::Applied).is_ok());
        assert!(transition(State::Applied, State::Applying).is_err());
        assert!(transition(State::Rejected, State::Approved).is_err());
        assert!(transition(State::Failed, State::Applying).is_err());
        assert!(transition(State::Expired, State::Approved).is_err());
        assert!(transition(State::Conflict, State::Applying).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn a_proposal_survives_another_store_and_rejects_tampering() {
        let root = temp_workspace("round");
        let state = temp_workspace("state");
        let (sandbox, prepared) = prepare(&root);
        assert_eq!(fs::read(root.join("notes.txt")).expect("bytes"), b"alpha\n");
        let store = ProposalStore::open(&state).expect("store");
        let saved = store.save(&sandbox, &prepared).expect("save");
        let listed = store.list(&sandbox).expect("list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, saved.id);
        let view = store.show(&sandbox, &saved.id).expect("show");
        assert!(view.diff.contains("-alpha"));
        assert!(view.file_id.chars().any(|character| character != '0'));
        let wrong = store.approve(&sandbox, &limits(), &saved.id, &view.digest, "approve");
        assert_eq!(wrong.expect_err("model").kind(), "approval_rejected");
        assert_eq!(fs::read(root.join("notes.txt")).expect("still"), b"alpha\n");
        let path = state
            .join("proposals")
            .join(workspace_identity(&sandbox).expect("id").key())
            .join(format!("{}.lcap", saved.id));
        let mut bytes = fs::read(&path).expect("blob");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x3c;
        fs::write(&path, &bytes).expect("tamper");
        let tampered = store.show(&sandbox, &saved.id).expect_err("tampered");
        assert_eq!(tampered.kind(), "proposal_invalid");
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(state);
    }

    #[cfg(windows)]
    #[test]
    fn approve_is_single_use_and_a_changed_target_conflicts() {
        let root = temp_workspace("apply");
        let state = temp_workspace("apply-state");
        let (sandbox, prepared) = prepare(&root);
        let store = ProposalStore::open(&state).expect("store");
        let saved = store.save(&sandbox, &prepared).expect("save");
        let view = store.show(&sandbox, &saved.id).expect("show");
        fs::write(root.join("notes.txt"), "changed\n").expect("edit");
        let conflict = store
            .approve(
                &sandbox,
                &limits(),
                &saved.id,
                &view.digest,
                &view.confirmation,
            )
            .expect_err("conflict");
        assert!(
            matches!(
                conflict.kind(),
                "conflict" | "identity_changed" | "context_mismatch"
            ),
            "{conflict:?}"
        );
        assert_eq!(
            fs::read(root.join("notes.txt")).expect("kept"),
            b"changed\n"
        );
        let status = store.status(&sandbox, &saved.id).expect("status");
        assert_ne!(status.state, "prepared");
        fs::write(root.join("notes.txt"), "alpha\n").expect("restore");
        let second = store.approve(
            &sandbox,
            &limits(),
            &saved.id,
            &view.digest,
            &view.confirmation,
        );
        assert!(second.is_err(), "a consumed proposal must not apply");
        assert_eq!(fs::read(root.join("notes.txt")).expect("once"), b"alpha\n");

        let root_ok = temp_workspace("ok");
        let (sandbox_ok, prepared_ok) = prepare(&root_ok);
        let saved_ok = store.save(&sandbox_ok, &prepared_ok).expect("save ok");
        let view_ok = store.show(&sandbox_ok, &saved_ok.id).expect("show ok");
        store
            .approve(
                &sandbox_ok,
                &limits(),
                &saved_ok.id,
                &view_ok.digest,
                &view_ok.confirmation,
            )
            .expect("apply");
        assert_eq!(fs::read(root_ok.join("notes.txt")).expect("new"), b"beta\n");
        let again = store.approve(
            &sandbox_ok,
            &limits(),
            &saved_ok.id,
            &view_ok.digest,
            &view_ok.confirmation,
        );
        assert_eq!(again.expect_err("twice").kind(), "approval_consumed");
        assert_eq!(
            fs::read(root_ok.join("notes.txt")).expect("stable"),
            b"beta\n"
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(root_ok);
        let _ = fs::remove_dir_all(state);
    }

    #[cfg(windows)]
    #[test]
    fn a_copied_workspace_cannot_reuse_the_proposal() {
        let root = temp_workspace("origin");
        let copy = temp_workspace("copy");
        let state = temp_workspace("copy-state");
        let (sandbox, prepared) = prepare(&root);
        fs::write(copy.join("notes.txt"), "alpha\n").expect("copy file");
        let store = ProposalStore::open(&state).expect("store");
        let saved = store.save(&sandbox, &prepared).expect("save");
        let other = WorkspaceSandbox::new(&copy).expect("other");
        let error = store.show(&other, &saved.id).expect_err("other workspace");
        assert_eq!(error.kind(), "proposal_invalid");
        assert_eq!(fs::read(copy.join("notes.txt")).expect("copy"), b"alpha\n");
        assert_eq!(
            fs::read(root.join("notes.txt")).expect("origin"),
            b"alpha\n"
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(copy);
        let _ = fs::remove_dir_all(state);
    }

    #[cfg(windows)]
    #[test]
    fn applying_state_is_reconciled_without_a_second_write() {
        let root = temp_workspace("crash");
        let state = temp_workspace("crash-state");
        let (sandbox, prepared) = prepare(&root);
        let store = ProposalStore::open(&state).expect("store");
        let saved = store.save(&sandbox, &prepared).expect("save");
        let workspace = workspace_identity(&sandbox).expect("workspace");
        let mut record = store.load(&workspace, &saved.id).expect("load");
        record.state = State::Applying;
        store.write_record(&workspace, &record).expect("force");
        fs::write(root.join("notes.txt"), "beta\n").expect("exchanged");
        let status = store.status(&sandbox, &saved.id).expect("status");
        assert_eq!(status.state, "applied");
        let denied = store.show(&sandbox, &saved.id).expect("show");
        let apply = store.approve(
            &sandbox,
            &limits(),
            &saved.id,
            &denied.digest,
            &denied.confirmation,
        );
        assert!(apply.is_err());
        assert_eq!(
            fs::read(root.join("notes.txt")).expect("no rewrite"),
            b"beta\n"
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(state);
    }

    #[cfg(windows)]
    #[test]
    fn every_fault_point_records_the_bytes_that_are_actually_present() {
        use crate::fs::ApplyFault;
        let points = [
            ApplyFault::AfterValidation,
            ApplyFault::AfterApproval,
            ApplyFault::AfterTempCreate,
            ApplyFault::AfterWrite,
            ApplyFault::BeforeRename,
            ApplyFault::AfterRename,
            ApplyFault::BeforeReadback,
            ApplyFault::DuringReadback,
            ApplyFault::AfterVerification,
            ApplyFault::BeforeAudit,
        ];
        for fault in points {
            let root = temp_workspace("fault");
            let state = temp_workspace("fault-state");
            let (sandbox, prepared) = prepare(&root);
            let store = ProposalStore::open(&state).expect("store");
            let saved = store.save(&sandbox, &prepared).expect("save");
            let view = store.show(&sandbox, &saved.id).expect("show");
            let error = store
                .approve_with(
                    &sandbox,
                    &limits(),
                    &saved.id,
                    &view.digest,
                    &view.confirmation,
                    fault,
                )
                .expect_err("fault");
            let bytes = fs::read(root.join("notes.txt")).expect("bytes");
            let log_before = audit_text(&state);
            let temps: Vec<_> = fs::read_dir(&root)
                .expect("dir")
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.contains(".lca-") || name.ends_with(".tmp"))
                .collect();
            assert!(temps.is_empty(), "{fault:?} left {temps:?}");
            match fault {
                ApplyFault::AfterValidation => {
                    assert_eq!(error.kind(), "fault_injected");
                    assert_eq!(bytes, b"alpha\n");
                    assert_eq!(
                        store.status(&sandbox, &saved.id).expect("status").state,
                        "prepared"
                    );
                }
                ApplyFault::AfterApproval => {
                    assert_eq!(bytes, b"alpha\n");
                    assert_eq!(
                        store.status(&sandbox, &saved.id).expect("status").state,
                        "approved"
                    );
                }
                ApplyFault::AfterTempCreate | ApplyFault::AfterWrite | ApplyFault::BeforeRename => {
                    assert_eq!(bytes, b"alpha\n");
                    assert_eq!(
                        store.status(&sandbox, &saved.id).expect("status").state,
                        "failed",
                        "{fault:?} {error}"
                    );
                }
                ApplyFault::AfterRename
                | ApplyFault::BeforeReadback
                | ApplyFault::DuringReadback => {
                    assert_eq!(bytes, b"beta\n", "{fault:?} {error}");
                    if fault == ApplyFault::DuringReadback {
                        assert_eq!(error.kind(), "verify_failed", "{error}");
                        assert!(log_before.contains("verification_failed"), "{log_before}");
                    } else {
                        assert!(log_before.contains("state_unclear"), "{log_before}");
                    }
                    assert!(log_before.contains("\"state\":\"unclear\""), "{log_before}");
                    let status = store.status(&sandbox, &saved.id).expect("status");
                    assert_eq!(status.state, "applied", "{fault:?} was not recovered");
                    let again = store.approve(
                        &sandbox,
                        &limits(),
                        &saved.id,
                        &view.digest,
                        &view.confirmation,
                    );
                    assert!(again.is_err(), "recovery must not write again");
                    assert_eq!(fs::read(root.join("notes.txt")).expect("stable"), b"beta\n");
                }
                ApplyFault::AfterVerification => {
                    assert_eq!(bytes, b"beta\n");
                    assert!(log_before.contains("verified"), "{log_before}");
                    assert_eq!(
                        store.status(&sandbox, &saved.id).expect("status").state,
                        "applied"
                    );
                    assert_eq!(fs::read(root.join("notes.txt")).expect("stable"), b"beta\n");
                }
                ApplyFault::BeforeAudit => {
                    assert_eq!(bytes, b"beta\n");
                    assert!(log_before.contains("verified"), "{log_before}");
                    assert!(!log_before.contains("apply_succeeded"), "{log_before}");
                    assert_eq!(
                        store.status(&sandbox, &saved.id).expect("status").state,
                        "applied"
                    );
                }
                ApplyFault::None => unreachable!("production fault is not in this table"),
            }
            let _ = fs::remove_dir_all(root);
            let _ = fs::remove_dir_all(state);
        }
    }
}
