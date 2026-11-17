//! Independent restoration of a sealed preimage.
//!
//! A restoration has its own id, digest, and confirmation line. The proposal approval
//! line is not accepted. The bytes come from the publication evidence file. The write
//! goes through the verified in-place publisher. This module does not delete that
//! evidence, and it does not start a second write when the outcome is unclear.

use std::cell::RefCell;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    Evidence, ProposalStore, Record, State, TTL_SECS, durable_bytes, hex_encode, push_part, sha256,
    unix_now, workspace_identity,
};
use crate::fs::{
    ApplyFault, ApplyResult, ApprovalLedger, BoundFileId, FsLimits, KillHold,
    RESTORATION_IMAGE_MARKER, StoredPatch, apply_image_controlled, restore_prepared,
};
use crate::fs_error::FsError;
use crate::sandbox::{FileIdentity, WorkspaceSandbox};

const CONTRACT_VERSION: u32 = 1;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const SOURCE_LABEL: &str = "sealed-publication-evidence";

const ATTEMPT_INTENT: u8 = 1;
const ATTEMPT_STAGED: u8 = 2;
const ATTEMPT_MUTATION: u8 = 3;
const ATTEMPT_PUBLISHED: u8 = 4;
const ATTEMPT_VERIFIED: u8 = 5;
const VERIFY_UNKNOWN: u8 = 0;
const VERIFY_MATCH: u8 = 1;
const VERIFY_MISMATCH: u8 = 2;
const RECOVERY_NONE: u8 = 0;
const RECOVERY_RESTORED: u8 = 1;
const RECOVERY_FAILED: u8 = 2;
const RECOVERY_UNCLEAR: u8 = 3;

/// Stored restoration identity. The diff and the file bytes are not included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorationSummary {
    /// Restoration UUID.
    pub id: String,
    /// Proposal whose sealed preimage is the source.
    pub source_proposal_id: String,
    /// Workspace-relative target.
    pub path: String,
    /// Lifecycle state name.
    pub state: String,
    /// Unix expiry.
    pub expires_at: u64,
    /// SHA-256 of the target bytes captured at prepare.
    pub current_sha256: String,
    /// SHA-256 of the bytes that would be written.
    pub restored_sha256: String,
    /// SHA-256 of the immutable publication-evidence preimage.
    pub original_evidence_sha256: String,
    /// Target file id captured at prepare, hex encoded.
    pub file_id: String,
    /// Attempt phase, or `absent`.
    pub attempt_phase: String,
}

/// Review view for one restoration. Approval is bound to `digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorationView {
    /// Identity and hashes.
    pub summary: RestorationSummary,
    /// Full restoration digest.
    pub digest: String,
    /// Exact confirmation line. It starts with `restore `.
    pub confirmation: String,
    /// Display diff from the bound current bytes to the sealed original.
    pub diff: String,
    /// Where the restored bytes come from.
    pub source: String,
    /// `matches_bound`, `matches_restored`, `changed`, or `unreadable`.
    pub target_status: String,
    /// SHA-256 of the bytes read now, or `unreadable`.
    pub live_sha256: String,
    /// Target volume serial captured at prepare.
    pub volume_serial: u64,
    /// Publication-evidence attempt id.
    pub source_attempt_id: String,
}

/// This milestone does not delete publication evidence.
#[must_use]
pub(crate) fn publication_evidence_may_be_deleted(
    _proposal: State,
    _restoration: Option<RestorationState>,
) -> bool {
    false
}

impl ProposalStore {
    /// Builds one restoration from sealed publication evidence. The target is not written.
    pub fn prepare_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        proposal_id: &str,
    ) -> Result<RestorationSummary, FsError> {
        if !lca_platform::verified_apply_supported() {
            return Err(FsError::UnsupportedPlatform);
        }
        self.with_record(sandbox, proposal_id, true, |record, workspace| {
            admit_source_state(record.state)?;
            let evidence = validated_evidence(self, workspace, record)?;
            let target = read_target(sandbox, &record.relative_path)?;
            admit_source_bytes(record, &target)?;
            if target.volume != record.target_volume || target.file_id != record.target_file_id {
                return Err(FsError::IdentityChanged {
                    path: record.relative_path.clone(),
                });
            }
            if self.blocking_restoration(workspace, record.id)?.is_some() {
                return Err(FsError::RestorationRejected {
                    message: "a restoration for this proposal is already open".to_owned(),
                });
            }
            debug_assert!(!publication_evidence_may_be_deleted(record.state, None));
            let now = unix_now();
            let id = Uuid::new_v4();
            let mut restoration = RestorationRecord {
                id,
                contract_version: CONTRACT_VERSION,
                source_proposal_id: record.id,
                source_digest: record.digest,
                action_id: action_id_from(id),
                workspace_volume: workspace.volume_serial,
                workspace_file_id: workspace.file_id,
                workspace_path: workspace.path.clone(),
                relative_path: record.relative_path.clone(),
                target_volume: target.volume,
                target_file_id: target.file_id,
                identity_created: target.identity.created(),
                identity_modified: target.identity.modified(),
                identity_len: target.identity.len(),
                current_sha256: target.hash,
                restored_sha256: evidence.original_hash,
                original_evidence_sha256: evidence.source_digest(),
                source_attempt_id: evidence.attempt_id,
                created_at: now,
                expires_at: now.saturating_add(TTL_SECS),
                current_bytes: target.bytes,
                restored_bytes: evidence.original,
                state: RestorationState::Prepared,
                digest: [0; 32],
            };
            if sha256(&restoration.restored_bytes) != record.original_hash {
                return Err(FsError::RestorationRejected {
                    message: "original evidence does not match the sealed hash".to_owned(),
                });
            }
            restoration.digest = restoration.canonical_digest()?;
            self.write_restoration(workspace, &restoration)?;
            self.audit_restoration(workspace, "restoration_prepared", &restoration)?;
            Ok(self.restoration_summary(workspace, &restoration))
        })
    }

    /// Checks the restoration digest, records that it was shown, and returns the review.
    pub fn show_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
    ) -> Result<RestorationView, FsError> {
        self.with_restoration(sandbox, id, false, |record, workspace| {
            self.audit_restoration(workspace, "restoration_shown", record)?;
            Ok(self.restoration_view(sandbox, workspace, record))
        })
    }

    /// Reconciles `Restoring` or `Unclear` from the target bytes. It does not write them.
    pub fn status_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
    ) -> Result<RestorationSummary, FsError> {
        self.with_restoration(sandbox, id, true, |record, workspace| {
            Ok(self.restoration_summary(workspace, record))
        })
    }

    /// Reconciles one restoration and records recovery. It does not write the target.
    pub fn recover_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
    ) -> Result<RestorationSummary, FsError> {
        self.with_restoration(sandbox, id, true, |record, workspace| {
            let _ = self.mark_attempt_recovery(workspace, record);
            self.audit_restoration(workspace, "restoration_recovered", record)?;
            Ok(self.restoration_summary(workspace, record))
        })
    }

    /// Marks a prepared or approved restoration rejected. It does not write the target.
    pub fn reject_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
    ) -> Result<RestorationSummary, FsError> {
        self.with_restoration(sandbox, id, true, |record, workspace| {
            transition(record.state, RestorationState::Rejected)?;
            record.state = RestorationState::Rejected;
            self.write_restoration(workspace, record)?;
            self.audit_restoration(workspace, "restoration_rejected", record)?;
            Ok(self.restoration_summary(workspace, record))
        })
    }

    /// Restores one reviewed preimage. `line` must be the restoration confirmation line.
    ///
    /// A proposal approval line is rejected. This function does not call a model.
    pub fn approve_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        limits: &FsLimits,
        id: &str,
        shown_digest: &str,
        line: &str,
    ) -> Result<ApplyResult, FsError> {
        self.approve_restoration_inner(
            sandbox,
            limits,
            id,
            shown_digest,
            line,
            ApplyFault::none(),
            None,
        )
    }

    /// Same as [`Self::approve_restoration`], with one deterministic fault point.
    pub fn approve_restoration_with(
        &self,
        sandbox: &WorkspaceSandbox,
        limits: &FsLimits,
        id: &str,
        shown_digest: &str,
        line: &str,
        fault: ApplyFault,
    ) -> Result<ApplyResult, FsError> {
        self.approve_restoration_inner(sandbox, limits, id, shown_digest, line, fault, None)
    }

    /// Restores until `hold` and then parks. The `lca` binary does not call this.
    pub fn approve_restoration_holding(
        &self,
        sandbox: &WorkspaceSandbox,
        limits: &FsLimits,
        id: &str,
        shown_digest: &str,
        line: &str,
        hold: &KillHold,
    ) -> Result<ApplyResult, FsError> {
        self.approve_restoration_inner(
            sandbox,
            limits,
            id,
            shown_digest,
            line,
            ApplyFault::none(),
            Some(hold),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn approve_restoration_inner(
        &self,
        sandbox: &WorkspaceSandbox,
        limits: &FsLimits,
        id: &str,
        shown_digest: &str,
        line: &str,
        fault: ApplyFault,
        hold: Option<&KillHold>,
    ) -> Result<ApplyResult, FsError> {
        if !limits.write_enabled() {
            return Err(FsError::ToolDisabled {
                tool: "apply_patch".to_owned(),
            });
        }
        if !lca_platform::verified_apply_supported() {
            return Err(FsError::UnsupportedPlatform);
        }
        self.with_restoration(sandbox, id, true, |record, workspace| {
            if record.state != RestorationState::Prepared {
                return Err(FsError::ApprovalConsumed);
            }
            if shown_digest != hex_encode(&record.digest) || shown_digest.len() != 64 {
                return Err(FsError::ApprovalMismatch);
            }
            let expected = confirmation_line(record);
            if line != expected || !line.starts_with("restore ") {
                return Err(FsError::ApprovalRejected);
            }
            let proposal = self.load(workspace, &record.source_proposal_id.to_string())?;
            let evidence = validated_evidence(self, workspace, &proposal)?;
            if evidence.source_digest() != record.original_evidence_sha256
                || evidence.attempt_id != record.source_attempt_id
                || evidence.original != record.restored_bytes
                || proposal.digest != record.source_digest
                || proposal.relative_path != record.relative_path
            {
                return self.fail_restoration(
                    workspace,
                    record,
                    RestorationState::Failed,
                    FsError::RestorationRejected {
                        message: "original evidence no longer matches the restoration".to_owned(),
                    },
                );
            }
            if let Err(error) = self.recheck_target(sandbox, record) {
                let state = if matches!(
                    error,
                    FsError::Conflict { .. } | FsError::IdentityChanged { .. }
                ) {
                    RestorationState::Conflict
                } else {
                    RestorationState::Failed
                };
                return self.fail_restoration(workspace, record, state, error);
            }
            if let Some(hold) = hold {
                hold.park_at(ApplyFault::AfterValidation);
            }
            if fault == ApplyFault::AfterValidation {
                return Err(FsError::FaultInjected {
                    point: "after_validation",
                    published: false,
                });
            }
            transition(record.state, RestorationState::Approved)?;
            record.state = RestorationState::Approved;
            self.write_restoration(workspace, record)?;
            self.audit_restoration(workspace, "restoration_approved", record)?;
            if let Some(hold) = hold {
                hold.park_at(ApplyFault::AfterApproval);
            }
            if fault == ApplyFault::AfterApproval {
                return Err(FsError::FaultInjected {
                    point: "after_approval",
                    published: false,
                });
            }
            let again = self.load_restoration(workspace, &record.id.to_string())?;
            if again.digest != record.digest || again.state != RestorationState::Approved {
                return Err(FsError::ApprovalMismatch);
            }
            *record = again;
            if let Err(error) = self.recheck_target(sandbox, record) {
                let state = if matches!(
                    error,
                    FsError::Conflict { .. } | FsError::IdentityChanged { .. }
                ) {
                    RestorationState::Conflict
                } else {
                    RestorationState::Failed
                };
                return self.fail_restoration(workspace, record, state, error);
            }
            let fresh = validated_evidence(self, workspace, &proposal)?;
            if fresh.original != record.restored_bytes
                || fresh.source_digest() != record.original_evidence_sha256
            {
                return self.fail_restoration(
                    workspace,
                    record,
                    RestorationState::Failed,
                    FsError::RestorationRejected {
                        message: "original evidence no longer matches the restoration".to_owned(),
                    },
                );
            }
            transition(record.state, RestorationState::Restoring)?;
            record.state = RestorationState::Restoring;
            self.write_restoration(workspace, record)?;
            self.audit_restoration(workspace, "restoration_started", record)?;
            let prepared = image_from(sandbox, record)?;
            let grant = crate::fs::ApprovalGrant::issue_restoration(&prepared, line, &expected)?;
            let sealed = RefCell::new(None);
            let outcome = {
                let mut preimage = |bytes: &[u8]| {
                    if sha256(bytes) != record.current_sha256 {
                        return Err(FsError::Conflict {
                            path: record.relative_path.clone(),
                        });
                    }
                    let attempt = Attempt::intent(record, bytes);
                    self.write_attempt(workspace, &attempt)?;
                    *sealed.borrow_mut() = Some(attempt);
                    Ok(())
                };
                let mut trace = |event: &str| {
                    if let Some(attempt) = sealed.borrow_mut().as_mut() {
                        attempt.observe(event);
                        self.write_attempt(workspace, attempt)?;
                    }
                    Ok(())
                };
                apply_image_controlled(
                    sandbox,
                    &prepared,
                    grant,
                    &ApprovalLedger::new(),
                    fault,
                    hold,
                    &mut preimage,
                    &mut trace,
                )
            };
            match outcome {
                Ok(result) => {
                    self.audit_restoration(workspace, "restoration_verified", record)?;
                    if let Err(error) =
                        self.note_attempt_verified(sandbox, workspace, record, &sealed)
                    {
                        record.state = RestorationState::Unclear;
                        self.write_restoration(workspace, record)?;
                        self.audit_restoration(workspace, "restoration_unclear", record)?;
                        return Err(error);
                    }
                    if let Some(hold) = hold {
                        hold.park_at(ApplyFault::AfterVerification);
                    }
                    if fault == ApplyFault::AfterVerification {
                        return Err(FsError::FaultInjected {
                            point: "after_verification",
                            published: true,
                        });
                    }
                    transition(record.state, RestorationState::Restored)?;
                    record.state = RestorationState::Restored;
                    self.write_restoration(workspace, record)?;
                    if let Some(hold) = hold {
                        hold.park_at(ApplyFault::BeforeAudit);
                    }
                    if fault == ApplyFault::BeforeAudit {
                        return Err(FsError::FaultInjected {
                            point: "before_audit",
                            published: true,
                        });
                    }
                    self.audit_restoration(workspace, "restoration_restored", record)?;
                    Ok(result)
                }
                Err(error) => {
                    let state = state_after_failure(&error);
                    self.fail_restoration(workspace, record, state, error)
                }
            }
        })
    }

    fn recheck_target(
        &self,
        sandbox: &WorkspaceSandbox,
        record: &RestorationRecord,
    ) -> Result<(), FsError> {
        let _ = self;
        let target = read_target(sandbox, &record.relative_path)?;
        if target.volume != record.target_volume || target.file_id != record.target_file_id {
            return Err(FsError::IdentityChanged {
                path: record.relative_path.clone(),
            });
        }
        if target.identity.created() != record.identity_created
            || target.identity.modified() != record.identity_modified
            || target.identity.len() != record.identity_len
        {
            return Err(FsError::IdentityChanged {
                path: record.relative_path.clone(),
            });
        }
        if target.hash != record.current_sha256 {
            return Err(FsError::Conflict {
                path: record.relative_path.clone(),
            });
        }
        Ok(())
    }

    fn fail_restoration<T>(
        &self,
        workspace: &super::WorkspaceIdentity,
        record: &mut RestorationRecord,
        state: RestorationState,
        error: FsError,
    ) -> Result<T, FsError> {
        transition(record.state, state)?;
        record.state = state;
        self.write_restoration(workspace, record)?;
        let event = match state {
            RestorationState::Unclear => "restoration_unclear",
            _ => "restoration_failed",
        };
        self.audit_restoration(workspace, event, record)?;
        if matches!(record.state, RestorationState::Unclear) && event != "restoration_unclear" {
            self.audit_restoration(workspace, "restoration_unclear", record)?;
        }
        Err(error)
    }

    fn with_restoration<T>(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
        reconcile_file: bool,
        body: impl FnOnce(&mut RestorationRecord, &super::WorkspaceIdentity) -> Result<T, FsError>,
    ) -> Result<T, FsError> {
        self.protect_root()?;
        let workspace = workspace_identity(sandbox)?;
        let parsed = Uuid::parse_str(id).map_err(|_| FsError::RestorationRejected {
            message: "restoration id is not a UUID".to_owned(),
        })?;
        let peeked = self.load_restoration(&workspace, &parsed.to_string())?;
        let dir = self.proposal_dir(&workspace);
        let proposal_lock = dir.join(format!("{}.lock", peeked.source_proposal_id));
        let _proposal = lca_platform::try_lock_exclusive(&proposal_lock).map_err(|error| {
            FsError::StoreUnavailable {
                message: error.to_string(),
            }
        })?;
        let restoration_lock = dir.join(format!("{parsed}.rlock"));
        let _restoration =
            lca_platform::try_lock_exclusive(&restoration_lock).map_err(|error| {
                FsError::StoreUnavailable {
                    message: error.to_string(),
                }
            })?;
        let mut record = self.load_restoration(&workspace, &parsed.to_string())?;
        if reconcile_file {
            self.reconcile_restoration(sandbox, &workspace, &mut record)?;
        }
        body(&mut record, &workspace)
    }

    fn reconcile_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        workspace: &super::WorkspaceIdentity,
        record: &mut RestorationRecord,
    ) -> Result<(), FsError> {
        if matches!(
            record.state,
            RestorationState::Prepared | RestorationState::Approved
        ) && unix_now() >= record.expires_at
        {
            transition(record.state, RestorationState::Expired)?;
            record.state = RestorationState::Expired;
            self.write_restoration(workspace, record)?;
            self.audit_restoration(workspace, "restoration_expired", record)?;
            return Ok(());
        }
        if !matches!(
            record.state,
            RestorationState::Restoring | RestorationState::Unclear
        ) {
            return Ok(());
        }
        let next = classify_restoration(sandbox, record);
        if next == record.state {
            return Ok(());
        }
        transition(record.state, next)?;
        record.state = next;
        self.write_restoration(workspace, record)?;
        let event = match next {
            RestorationState::Restored | RestorationState::Failed => "restoration_recovered",
            RestorationState::Unclear => "restoration_unclear",
            _ => "restoration_recovered",
        };
        self.audit_restoration(workspace, event, record)?;
        Ok(())
    }

    fn blocking_restoration(
        &self,
        workspace: &super::WorkspaceIdentity,
        proposal_id: Uuid,
    ) -> Result<Option<Uuid>, FsError> {
        let dir = self.proposal_dir(workspace);
        if !dir.exists() {
            return Ok(None);
        }
        let entries = fs::read_dir(&dir).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| FsError::StoreUnavailable {
                message: error.to_string(),
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".lcar") else {
                continue;
            };
            let record = self.load_restoration(workspace, id)?;
            if record.source_proposal_id == proposal_id
                && matches!(
                    record.state,
                    RestorationState::Prepared
                        | RestorationState::Approved
                        | RestorationState::Restoring
                )
            {
                return Ok(Some(record.id));
            }
        }
        Ok(None)
    }

    fn load_restoration(
        &self,
        workspace: &super::WorkspaceIdentity,
        id: &str,
    ) -> Result<RestorationRecord, FsError> {
        let path = self.restoration_path(workspace, id);
        let ciphertext = fs::read(&path).map_err(|_| FsError::RestorationRejected {
            message: "restoration was not found".to_owned(),
        })?;
        let plaintext =
            lca_platform::unprotect(&ciphertext).map_err(|_| FsError::RestorationRejected {
                message: "restoration protection check failed".to_owned(),
            })?;
        let record = RestorationRecord::decode(&plaintext)?;
        if record.id.to_string() != id {
            return Err(FsError::RestorationRejected {
                message: "restoration id does not match the file name".to_owned(),
            });
        }
        if record.canonical_digest()? != record.digest {
            return Err(FsError::RestorationRejected {
                message: "restoration digest does not match its body".to_owned(),
            });
        }
        if sha256(&record.current_bytes) != record.current_sha256
            || sha256(&record.restored_bytes) != record.restored_sha256
        {
            return Err(FsError::RestorationRejected {
                message: "restoration bytes do not match their hashes".to_owned(),
            });
        }
        if record.workspace_volume != workspace.volume_serial
            || record.workspace_file_id != workspace.file_id
            || !crate::pathutil::paths_equivalent(
                Path::new(&record.workspace_path),
                Path::new(&workspace.path),
            )
        {
            return Err(FsError::WorkspaceMismatch);
        }
        Ok(record)
    }

    fn write_restoration(
        &self,
        workspace: &super::WorkspaceIdentity,
        record: &RestorationRecord,
    ) -> Result<(), FsError> {
        let plaintext = record.encode()?;
        let ciphertext =
            lca_platform::protect(&plaintext).map_err(|_| FsError::StoreUnavailable {
                message: "restoration bytes could not be protected".to_owned(),
            })?;
        let dir = self.proposal_dir(workspace);
        fs::create_dir_all(&dir).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        durable_bytes(
            &self.restoration_path(workspace, &record.id.to_string()),
            &ciphertext,
        )
    }

    fn restoration_path(&self, workspace: &super::WorkspaceIdentity, id: &str) -> PathBuf {
        self.proposal_dir(workspace).join(format!("{id}.lcar"))
    }

    fn attempt_path(&self, workspace: &super::WorkspaceIdentity, id: &str) -> PathBuf {
        self.proposal_dir(workspace).join(format!("{id}.lrae"))
    }

    fn write_attempt(
        &self,
        workspace: &super::WorkspaceIdentity,
        attempt: &Attempt,
    ) -> Result<(), FsError> {
        let plaintext = attempt.encode()?;
        let ciphertext =
            lca_platform::protect(&plaintext).map_err(|_| FsError::StoreUnavailable {
                message: "restoration attempt could not be protected".to_owned(),
            })?;
        let dir = self.proposal_dir(workspace);
        fs::create_dir_all(&dir).map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        durable_bytes(
            &self.attempt_path(workspace, &attempt.restoration_id.to_string()),
            &ciphertext,
        )
    }

    fn read_attempt(
        &self,
        workspace: &super::WorkspaceIdentity,
        id: &str,
    ) -> Result<Option<Attempt>, FsError> {
        let path = self.attempt_path(workspace, id);
        if !path.exists() {
            return Ok(None);
        }
        let ciphertext = fs::read(&path).map_err(|_| FsError::RestorationRejected {
            message: "restoration attempt could not be read".to_owned(),
        })?;
        let plaintext =
            lca_platform::unprotect(&ciphertext).map_err(|_| FsError::RestorationRejected {
                message: "restoration attempt protection check failed".to_owned(),
            })?;
        Ok(Some(Attempt::decode(&plaintext)?))
    }

    fn note_attempt_verified(
        &self,
        sandbox: &WorkspaceSandbox,
        workspace: &super::WorkspaceIdentity,
        record: &RestorationRecord,
        sealed: &RefCell<Option<Attempt>>,
    ) -> Result<(), FsError> {
        let mut sealed_attempt = sealed.borrow_mut();
        let Some(attempt) = sealed_attempt.as_mut() else {
            return Ok(());
        };
        attempt.phase = ATTEMPT_VERIFIED;
        attempt.verification = VERIFY_MATCH;
        attempt.publication_complete = 1;
        attempt.updated_at = unix_now();
        if let Ok(target) = read_target(sandbox, &record.relative_path) {
            attempt.file_id_after = target.file_id;
            if target.file_id != record.target_file_id
                || target.volume != record.target_volume
                || target.hash != record.restored_sha256
            {
                attempt.verification = VERIFY_MISMATCH;
                self.write_attempt(workspace, attempt)?;
                return Err(FsError::VerifyFailed {
                    path: record.relative_path.clone(),
                });
            }
        }
        self.write_attempt(workspace, attempt)
    }

    fn mark_attempt_recovery(
        &self,
        workspace: &super::WorkspaceIdentity,
        record: &RestorationRecord,
    ) -> Result<(), FsError> {
        let Some(mut attempt) = self.read_attempt(workspace, &record.id.to_string())? else {
            return Ok(());
        };
        attempt.recovery = match record.state {
            RestorationState::Restored => RECOVERY_RESTORED,
            RestorationState::Failed => RECOVERY_FAILED,
            RestorationState::Unclear => RECOVERY_UNCLEAR,
            _ => RECOVERY_NONE,
        };
        attempt.updated_at = unix_now();
        self.write_attempt(workspace, &attempt)
    }

    fn restoration_summary(
        &self,
        workspace: &super::WorkspaceIdentity,
        record: &RestorationRecord,
    ) -> RestorationSummary {
        let phase = self
            .read_attempt(workspace, &record.id.to_string())
            .ok()
            .flatten()
            .map(|attempt| attempt.phase_name().to_owned())
            .unwrap_or_else(|| "absent".to_owned());
        RestorationSummary {
            id: record.id.to_string(),
            source_proposal_id: record.source_proposal_id.to_string(),
            path: record.relative_path.clone(),
            state: record.state.as_str().to_owned(),
            expires_at: record.expires_at,
            current_sha256: hex_encode(&record.current_sha256),
            restored_sha256: hex_encode(&record.restored_sha256),
            original_evidence_sha256: hex_encode(&record.original_evidence_sha256),
            file_id: hex_encode(&record.target_file_id),
            attempt_phase: phase,
        }
    }

    fn restoration_view(
        &self,
        sandbox: &WorkspaceSandbox,
        workspace: &super::WorkspaceIdentity,
        record: &RestorationRecord,
    ) -> RestorationView {
        let (target_status, live_sha256) = match read_target(sandbox, &record.relative_path) {
            Ok(target) => {
                let same = target.file_id == record.target_file_id
                    && target.volume == record.target_volume;
                let status = if !same {
                    "changed"
                } else if target.hash == record.current_sha256 {
                    "matches_bound"
                } else if target.hash == record.restored_sha256 {
                    "matches_restored"
                } else {
                    "changed"
                };
                (status.to_owned(), hex_encode(&target.hash))
            }
            Err(_) => ("unreadable".to_owned(), "unreadable".to_owned()),
        };
        RestorationView {
            digest: hex_encode(&record.digest),
            confirmation: confirmation_line(record),
            diff: bound_diff(
                &record.relative_path,
                &record.current_bytes,
                &record.restored_bytes,
            ),
            source: SOURCE_LABEL.to_owned(),
            target_status,
            live_sha256,
            volume_serial: record.target_volume,
            source_attempt_id: record.source_attempt_id.to_string(),
            summary: self.restoration_summary(workspace, record),
        }
    }

    #[cfg(test)]
    fn testing_expire_restoration(
        &self,
        sandbox: &WorkspaceSandbox,
        id: &str,
    ) -> Result<(), FsError> {
        self.with_restoration(sandbox, id, false, |record, workspace| {
            record.expires_at = 1;
            record.digest = record.canonical_digest()?;
            self.write_restoration(workspace, record)
        })
    }

    fn audit_restoration(
        &self,
        workspace: &super::WorkspaceIdentity,
        event: &str,
        record: &RestorationRecord,
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
        let next = super::read_seq(&seq_path)?.saturating_add(1);
        let line = serde_json::json!({
            "seq": next,
            "event": event,
            "restoration_id": record.id.to_string(),
            "source_proposal_id": record.source_proposal_id.to_string(),
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
        let mut seq = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&seq_path)
            .map_err(|error| FsError::StoreUnavailable {
                message: error.to_string(),
            })?;
        write!(seq, "{next}").map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        seq.sync_all().map_err(|error| FsError::StoreUnavailable {
            message: error.to_string(),
        })?;
        Ok(())
    }
}

fn validated_evidence(
    store: &ProposalStore,
    workspace: &super::WorkspaceIdentity,
    record: &Record,
) -> Result<Evidence, FsError> {
    let evidence = match store.read_evidence(workspace, &record.id.to_string()) {
        Ok(Some(evidence)) => evidence,
        Ok(None) => {
            return Err(FsError::RestorationRejected {
                message: "original evidence is missing".to_owned(),
            });
        }
        Err(_) => {
            return Err(FsError::RestorationRejected {
                message: "original evidence is invalid".to_owned(),
            });
        }
    };
    if evidence.proposal_id != record.id {
        return Err(FsError::RestorationRejected {
            message: "original evidence is bound to a different proposal".to_owned(),
        });
    }
    if evidence.digest != record.digest {
        return Err(FsError::RestorationRejected {
            message: "original evidence does not match the proposal digest".to_owned(),
        });
    }
    if evidence.strategy != 1 {
        return Err(FsError::RestorationRejected {
            message: "original evidence strategy is not recognized".to_owned(),
        });
    }
    if evidence.target_volume != record.target_volume
        || evidence.file_id_before != record.target_file_id
    {
        return Err(FsError::RestorationRejected {
            message: "original evidence is bound to a different file".to_owned(),
        });
    }
    if evidence.original_hash != record.original_hash
        || sha256(&evidence.original) != evidence.original_hash
        || evidence.proposed_hash != record.proposed_hash
    {
        return Err(FsError::RestorationRejected {
            message: "original evidence does not match the sealed hash".to_owned(),
        });
    }
    Ok(evidence)
}

fn admit_source_state(state: State) -> Result<(), FsError> {
    if matches!(state, State::Applied) {
        return Err(FsError::RestorationRejected {
            message: "an applied proposal is not treated as damaged".to_owned(),
        });
    }
    if matches!(state, State::Conflict) {
        return Err(FsError::RestorationRejected {
            message: "a conflicted proposal is not a restoration source".to_owned(),
        });
    }
    if !matches!(state, State::Unclear | State::Failed) {
        return Err(FsError::RestorationRejected {
            message: "proposal state does not allow restoration".to_owned(),
        });
    }
    Ok(())
}

fn admit_source_bytes(record: &Record, target: &TargetNow) -> Result<(), FsError> {
    if target.hash == record.original_hash {
        return Err(FsError::RestorationRejected {
            message: "target already matches the sealed original".to_owned(),
        });
    }
    if target.hash == record.proposed_hash {
        return Err(FsError::RestorationRejected {
            message: "target matches the proposed bytes and is not treated as damaged".to_owned(),
        });
    }
    Ok(())
}

struct TargetNow {
    bytes: Vec<u8>,
    hash: [u8; 32],
    volume: u64,
    file_id: [u8; 16],
    identity: FileIdentity,
}

fn read_target(sandbox: &WorkspaceSandbox, relative: &str) -> Result<TargetNow, FsError> {
    let resolved = sandbox.resolve_visible(relative)?;
    if !resolved.is_file() {
        return Err(FsError::NotAFile {
            path: relative.to_owned(),
        });
    }
    let components: Vec<String> = relative
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_owned)
        .collect();
    let info = lca_platform::stat_tree(sandbox.root(), &components)
        .map_err(|error| map_platform(relative, error))?;
    if info.is_reparse() {
        return Err(FsError::ReparseDenied {
            path: relative.to_owned(),
        });
    }
    if info.is_directory() {
        return Err(FsError::NotAFile {
            path: relative.to_owned(),
        });
    }
    if info.link_count() != 1 {
        return Err(FsError::HardlinkDenied {
            path: relative.to_owned(),
        });
    }
    if info.file_id() == [0; 16] {
        return Err(FsError::UnverifiableIdentity {
            path: relative.to_owned(),
        });
    }
    let bytes = sandbox.read_bytes(relative, MAX_BYTES as u64)?;
    Ok(TargetNow {
        hash: sha256(&bytes),
        bytes,
        volume: info.volume_serial(),
        file_id: info.file_id(),
        identity: resolved.identity(),
    })
}

fn map_platform(path: &str, error: lca_platform::PlatformError) -> FsError {
    match error {
        lca_platform::PlatformError::Reparse => FsError::ReparseDenied {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::Hardlink => FsError::HardlinkDenied {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::NotFile => FsError::NotAFile {
            path: path.to_owned(),
        },
        lca_platform::PlatformError::NotFound => FsError::NotFound {
            path: path.to_owned(),
        },
        other => FsError::Io {
            path: path.to_owned(),
            message: other.to_string(),
        },
    }
}

fn image_from(
    sandbox: &WorkspaceSandbox,
    record: &RestorationRecord,
) -> Result<crate::fs::PreparedPatch, FsError> {
    let patch_text = format!("{RESTORATION_IMAGE_MARKER}{}\n", record.id);
    let patch_hash = sha256(patch_text.as_bytes());
    Ok(restore_prepared(StoredPatch {
        action_id: record.action_id,
        workspace_root: sandbox.root().to_path_buf(),
        relative_path: record.relative_path.clone(),
        identity: FileIdentity::from_parts(
            record.identity_created,
            record.identity_modified,
            record.identity_len,
        ),
        platform: BoundFileId {
            volume_serial: record.target_volume,
            file_id: record.target_file_id,
        },
        original_hash: record.current_sha256,
        new_hash: record.restored_sha256,
        patch_hash,
        new_bytes: record.restored_bytes.clone(),
        patch_text,
        diff: String::new(),
        line_ending: "lf",
    }))
}

fn confirmation_line(record: &RestorationRecord) -> String {
    let digest = hex_encode(&record.digest);
    format!("restore {} {}", record.id, &digest[..16])
}

fn action_id_from(id: Uuid) -> u64 {
    let bytes = id.as_bytes();
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(raw)
}

fn classify_restoration(
    sandbox: &WorkspaceSandbox,
    record: &RestorationRecord,
) -> RestorationState {
    let Ok(target) = read_target(sandbox, &record.relative_path) else {
        return RestorationState::Unclear;
    };
    let same = target.file_id == record.target_file_id && target.volume == record.target_volume;
    if !same {
        return RestorationState::Unclear;
    }
    if target.hash == record.restored_sha256 {
        RestorationState::Restored
    } else if target.hash == record.current_sha256 {
        RestorationState::Failed
    } else {
        RestorationState::Unclear
    }
}

fn state_after_failure(error: &FsError) -> RestorationState {
    match error {
        FsError::VerifyFailed { .. } => RestorationState::Unclear,
        FsError::FaultInjected {
            published: true, ..
        } => RestorationState::Unclear,
        FsError::Conflict { .. } | FsError::IdentityChanged { .. } => RestorationState::Conflict,
        _ => RestorationState::Failed,
    }
}

fn bound_diff(path: &str, current: &[u8], restored: &[u8]) -> String {
    let (Ok(old), Ok(new)) = (std::str::from_utf8(current), std::str::from_utf8(restored)) else {
        return format!(
            "binary replacement of {} bytes with {} bytes\n",
            current.len(),
            restored.len()
        );
    };
    if old.contains('\0') || new.contains('\0') {
        return format!(
            "binary replacement of {} bytes with {} bytes\n",
            current.len(),
            restored.len()
        );
    }
    let old_lines = split_lines(old);
    let new_lines = split_lines(new);
    let mut out = format!(
        "--- a/{path}\n+++ b/{path}\n@@ -1,{} +1,{} @@\n",
        old_lines.len(),
        new_lines.len()
    );
    for line in &old_lines {
        out.push('-');
        out.push_str(line);
        out.push('\n');
    }
    for line in &new_lines {
        out.push('+');
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn split_lines(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(index) = rest.find('\n') {
            let (line, tail) = rest.split_at(index);
            lines.push(line.strip_suffix('\r').unwrap_or(line));
            rest = &tail[1..];
        } else {
            lines.push(rest.strip_suffix('\r').unwrap_or(rest));
            break;
        }
    }
    lines
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestorationState {
    Prepared,
    Approved,
    Restoring,
    Restored,
    Rejected,
    Expired,
    Conflict,
    Failed,
    Unclear,
}

impl RestorationState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Approved => "approved",
            Self::Restoring => "restoring",
            Self::Restored => "restored",
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
            3 => Self::Restoring,
            4 => Self::Restored,
            5 => Self::Rejected,
            6 => Self::Expired,
            7 => Self::Conflict,
            8 => Self::Failed,
            9 => Self::Unclear,
            _ => {
                return Err(FsError::RestorationRejected {
                    message: "restoration state is not recognized".to_owned(),
                });
            }
        })
    }

    const fn to_byte(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Approved => 2,
            Self::Restoring => 3,
            Self::Restored => 4,
            Self::Rejected => 5,
            Self::Expired => 6,
            Self::Conflict => 7,
            Self::Failed => 8,
            Self::Unclear => 9,
        }
    }
}

fn transition(from: RestorationState, to: RestorationState) -> Result<(), FsError> {
    let allowed = matches!(
        (from, to),
        (RestorationState::Prepared, RestorationState::Approved)
            | (RestorationState::Prepared, RestorationState::Rejected)
            | (RestorationState::Prepared, RestorationState::Expired)
            | (RestorationState::Prepared, RestorationState::Failed)
            | (RestorationState::Prepared, RestorationState::Conflict)
            | (RestorationState::Approved, RestorationState::Restoring)
            | (RestorationState::Approved, RestorationState::Rejected)
            | (RestorationState::Approved, RestorationState::Expired)
            | (RestorationState::Approved, RestorationState::Failed)
            | (RestorationState::Approved, RestorationState::Conflict)
            | (RestorationState::Restoring, RestorationState::Restored)
            | (RestorationState::Restoring, RestorationState::Failed)
            | (RestorationState::Restoring, RestorationState::Conflict)
            | (RestorationState::Restoring, RestorationState::Unclear)
            | (RestorationState::Unclear, RestorationState::Restored)
            | (RestorationState::Unclear, RestorationState::Failed)
    );
    if allowed {
        Ok(())
    } else {
        Err(FsError::RestorationRejected {
            message: "restoration state transition is not allowed".to_owned(),
        })
    }
}

struct RestorationRecord {
    id: Uuid,
    contract_version: u32,
    source_proposal_id: Uuid,
    source_digest: [u8; 32],
    action_id: u64,
    workspace_volume: u64,
    workspace_file_id: [u8; 16],
    workspace_path: String,
    relative_path: String,
    target_volume: u64,
    target_file_id: [u8; 16],
    identity_created: u64,
    identity_modified: u64,
    identity_len: u64,
    current_sha256: [u8; 32],
    restored_sha256: [u8; 32],
    original_evidence_sha256: [u8; 32],
    source_attempt_id: Uuid,
    created_at: u64,
    expires_at: u64,
    current_bytes: Vec<u8>,
    restored_bytes: Vec<u8>,
    state: RestorationState,
    digest: [u8; 32],
}

impl RestorationRecord {
    fn canonical_digest(&self) -> Result<[u8; 32], FsError> {
        Ok(sha256(&self.canonical()?))
    }

    fn canonical(&self) -> Result<Vec<u8>, FsError> {
        let mut body = Vec::new();
        push_part(&mut body, b"LCA-01J-RESTORATION-V1");
        push_part(&mut body, &self.contract_version.to_le_bytes());
        push_part(&mut body, self.id.as_bytes());
        push_part(&mut body, self.source_proposal_id.as_bytes());
        push_part(&mut body, &self.source_digest);
        push_part(&mut body, &self.action_id.to_le_bytes());
        push_part(&mut body, &self.workspace_volume.to_le_bytes());
        push_part(&mut body, &self.workspace_file_id);
        push_part(&mut body, self.workspace_path.as_bytes());
        push_part(&mut body, self.relative_path.as_bytes());
        push_part(&mut body, &self.target_volume.to_le_bytes());
        push_part(&mut body, &self.target_file_id);
        push_part(&mut body, &self.identity_created.to_le_bytes());
        push_part(&mut body, &self.identity_modified.to_le_bytes());
        push_part(&mut body, &self.identity_len.to_le_bytes());
        push_part(&mut body, &self.current_sha256);
        push_part(&mut body, &self.restored_sha256);
        push_part(&mut body, &self.original_evidence_sha256);
        push_part(&mut body, self.source_attempt_id.as_bytes());
        push_part(&mut body, &self.created_at.to_le_bytes());
        push_part(&mut body, &self.expires_at.to_le_bytes());
        push_part(&mut body, &self.current_bytes);
        push_part(&mut body, &self.restored_bytes);
        Ok(body)
    }

    fn encode(&self) -> Result<Vec<u8>, FsError> {
        if self.contract_version != CONTRACT_VERSION {
            return Err(FsError::RestorationRejected {
                message: "restoration contract version is not supported".to_owned(),
            });
        }
        let mut body = self.canonical()?;
        body.push(self.state.to_byte());
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    fn decode(bytes: &[u8]) -> Result<Self, FsError> {
        if bytes.len() < 33 {
            return Err(FsError::RestorationRejected {
                message: "restoration body is truncated".to_owned(),
            });
        }
        let (body, tail) = bytes.split_at(bytes.len() - 33);
        let state = RestorationState::from_byte(tail[0])?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&tail[1..]);
        let mut cursor = body;
        let label = read_part(&mut cursor, 64)?;
        if label != b"LCA-01J-RESTORATION-V1" {
            return Err(FsError::RestorationRejected {
                message: "restoration contract label is not recognized".to_owned(),
            });
        }
        let contract_version = read_u32(&mut cursor)?;
        if contract_version != CONTRACT_VERSION {
            return Err(FsError::RestorationRejected {
                message: "restoration contract version is not supported".to_owned(),
            });
        }
        let id = Uuid::from_bytes(read_array::<16>(&mut cursor)?);
        let source_proposal_id = Uuid::from_bytes(read_array::<16>(&mut cursor)?);
        let source_digest = read_array::<32>(&mut cursor)?;
        let action_id = read_u64(&mut cursor)?;
        let workspace_volume = read_u64(&mut cursor)?;
        let workspace_file_id = read_array::<16>(&mut cursor)?;
        let workspace_path = read_text(&mut cursor, 4096)?;
        let relative_path = read_text(&mut cursor, 4096)?;
        let target_volume = read_u64(&mut cursor)?;
        let target_file_id = read_array::<16>(&mut cursor)?;
        let identity_created = read_u64(&mut cursor)?;
        let identity_modified = read_u64(&mut cursor)?;
        let identity_len = read_u64(&mut cursor)?;
        let current_sha256 = read_array::<32>(&mut cursor)?;
        let restored_sha256 = read_array::<32>(&mut cursor)?;
        let original_evidence_sha256 = read_array::<32>(&mut cursor)?;
        let source_attempt_id = Uuid::from_bytes(read_array::<16>(&mut cursor)?);
        let created_at = read_u64(&mut cursor)?;
        let expires_at = read_u64(&mut cursor)?;
        let current_bytes = read_part(&mut cursor, MAX_BYTES)?.to_vec();
        let restored_bytes = read_part(&mut cursor, MAX_BYTES)?.to_vec();
        if !cursor.is_empty() {
            return Err(FsError::RestorationRejected {
                message: "restoration body has trailing bytes".to_owned(),
            });
        }
        Ok(Self {
            id,
            contract_version,
            source_proposal_id,
            source_digest,
            action_id,
            workspace_volume,
            workspace_file_id,
            workspace_path,
            relative_path,
            target_volume,
            target_file_id,
            identity_created,
            identity_modified,
            identity_len,
            current_sha256,
            restored_sha256,
            original_evidence_sha256,
            source_attempt_id,
            created_at,
            expires_at,
            current_bytes,
            restored_bytes,
            state,
            digest,
        })
    }
}

struct Attempt {
    restoration_id: Uuid,
    digest: [u8; 32],
    attempt_id: Uuid,
    target_volume: u64,
    file_id_before: [u8; 16],
    file_id_after: [u8; 16],
    current_hash: [u8; 32],
    restored_hash: [u8; 32],
    preimage: Vec<u8>,
    phase: u8,
    stage_complete: u8,
    mutation_started: u8,
    publication_complete: u8,
    verification: u8,
    recovery: u8,
    sealed_at: u64,
    updated_at: u64,
}

impl Attempt {
    fn intent(record: &RestorationRecord, preimage: &[u8]) -> Self {
        let now = unix_now();
        Self {
            restoration_id: record.id,
            digest: record.digest,
            attempt_id: Uuid::new_v4(),
            target_volume: record.target_volume,
            file_id_before: record.target_file_id,
            file_id_after: [0; 16],
            current_hash: record.current_sha256,
            restored_hash: record.restored_sha256,
            preimage: preimage.to_vec(),
            phase: ATTEMPT_INTENT,
            stage_complete: 0,
            mutation_started: 0,
            publication_complete: 0,
            verification: VERIFY_UNKNOWN,
            recovery: RECOVERY_NONE,
            sealed_at: now,
            updated_at: now,
        }
    }

    fn observe(&mut self, event: &str) {
        match event {
            "stage_flushed" => {
                self.phase = ATTEMPT_STAGED;
                self.stage_complete = 1;
            }
            "mutation_started" => {
                self.phase = ATTEMPT_MUTATION;
                self.mutation_started = 1;
            }
            "mutation_published" => {
                self.phase = ATTEMPT_PUBLISHED;
                self.publication_complete = 1;
            }
            "verification_failed" => {
                self.verification = VERIFY_MISMATCH;
            }
            _ => {}
        }
        self.updated_at = unix_now();
    }

    fn phase_name(&self) -> &'static str {
        match self.phase {
            ATTEMPT_INTENT => "intent",
            ATTEMPT_STAGED => "staged",
            ATTEMPT_MUTATION => "mutation_started",
            ATTEMPT_PUBLISHED => "published",
            ATTEMPT_VERIFIED => "verified",
            _ => "unknown",
        }
    }

    fn encode(&self) -> Result<Vec<u8>, FsError> {
        if sha256(&self.preimage) != self.current_hash {
            return Err(FsError::StoreUnavailable {
                message: "restoration attempt does not match the bound hash".to_owned(),
            });
        }
        let mut body = Vec::new();
        push_part(&mut body, b"LCA-01J-ATTEMPT-V1");
        push_part(&mut body, self.restoration_id.as_bytes());
        push_part(&mut body, &self.digest);
        push_part(&mut body, self.attempt_id.as_bytes());
        push_part(&mut body, &self.target_volume.to_le_bytes());
        push_part(&mut body, &self.file_id_before);
        push_part(&mut body, &self.file_id_after);
        push_part(&mut body, &self.current_hash);
        push_part(&mut body, &self.restored_hash);
        push_part(&mut body, &self.preimage);
        push_part(&mut body, &[self.phase]);
        push_part(&mut body, &[self.stage_complete]);
        push_part(&mut body, &[self.mutation_started]);
        push_part(&mut body, &[self.publication_complete]);
        push_part(&mut body, &[self.verification]);
        push_part(&mut body, &[self.recovery]);
        push_part(&mut body, &self.sealed_at.to_le_bytes());
        push_part(&mut body, &self.updated_at.to_le_bytes());
        let digest = Sha256::digest(&body);
        body.extend_from_slice(&digest);
        Ok(body)
    }

    fn decode(bytes: &[u8]) -> Result<Self, FsError> {
        if bytes.len() < 32 {
            return Err(FsError::RestorationRejected {
                message: "restoration attempt is truncated".to_owned(),
            });
        }
        let (body, tail) = bytes.split_at(bytes.len() - 32);
        let mut expected = [0u8; 32];
        expected.copy_from_slice(tail);
        if Sha256::digest(body).as_slice() != expected {
            return Err(FsError::RestorationRejected {
                message: "restoration attempt digest does not match".to_owned(),
            });
        }
        let mut cursor = body;
        let label = read_part(&mut cursor, 64)?;
        if label != b"LCA-01J-ATTEMPT-V1" {
            return Err(FsError::RestorationRejected {
                message: "restoration attempt label is not recognized".to_owned(),
            });
        }
        let restoration_id = Uuid::from_bytes(read_array::<16>(&mut cursor)?);
        let digest = read_array::<32>(&mut cursor)?;
        let attempt_id = Uuid::from_bytes(read_array::<16>(&mut cursor)?);
        let target_volume = read_u64(&mut cursor)?;
        let file_id_before = read_array::<16>(&mut cursor)?;
        let file_id_after = read_array::<16>(&mut cursor)?;
        let current_hash = read_array::<32>(&mut cursor)?;
        let restored_hash = read_array::<32>(&mut cursor)?;
        let preimage = read_part(&mut cursor, MAX_BYTES)?.to_vec();
        let phase = read_byte(&mut cursor)?;
        let stage_complete = read_byte(&mut cursor)?;
        let mutation_started = read_byte(&mut cursor)?;
        let publication_complete = read_byte(&mut cursor)?;
        let verification = read_byte(&mut cursor)?;
        let recovery = read_byte(&mut cursor)?;
        let sealed_at = read_u64(&mut cursor)?;
        let updated_at = read_u64(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(FsError::RestorationRejected {
                message: "restoration attempt has trailing bytes".to_owned(),
            });
        }
        if sha256(&preimage) != current_hash {
            return Err(FsError::RestorationRejected {
                message: "restoration attempt does not match the bound hash".to_owned(),
            });
        }
        Ok(Self {
            restoration_id,
            digest,
            attempt_id,
            target_volume,
            file_id_before,
            file_id_after,
            current_hash,
            restored_hash,
            preimage,
            phase,
            stage_complete,
            mutation_started,
            publication_complete,
            verification,
            recovery,
            sealed_at,
            updated_at,
        })
    }
}

fn read_part<'a>(input: &mut &'a [u8], max: usize) -> Result<&'a [u8], FsError> {
    if input.len() < 8 {
        return Err(FsError::RestorationRejected {
            message: "restoration body is truncated".to_owned(),
        });
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&input[..8]);
    let len =
        usize::try_from(u64::from_le_bytes(raw)).map_err(|_| FsError::RestorationRejected {
            message: "restoration field is too large".to_owned(),
        })?;
    if len > max {
        return Err(FsError::RestorationRejected {
            message: "restoration field exceeds its limit".to_owned(),
        });
    }
    *input = &input[8..];
    if input.len() < len {
        return Err(FsError::RestorationRejected {
            message: "restoration body is truncated".to_owned(),
        });
    }
    let (head, tail) = input.split_at(len);
    *input = tail;
    Ok(head)
}

fn read_text(input: &mut &[u8], max: usize) -> Result<String, FsError> {
    let bytes = read_part(input, max)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| FsError::RestorationRejected {
        message: "restoration text is not UTF-8".to_owned(),
    })
}

fn read_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], FsError> {
    let bytes = read_part(input, N)?;
    if bytes.len() != N {
        return Err(FsError::RestorationRejected {
            message: "restoration field has the wrong size".to_owned(),
        });
    }
    let mut array = [0u8; N];
    array.copy_from_slice(bytes);
    Ok(array)
}

fn read_u32(input: &mut &[u8]) -> Result<u32, FsError> {
    Ok(u32::from_le_bytes(read_array::<4>(input)?))
}

fn read_u64(input: &mut &[u8]) -> Result<u64, FsError> {
    Ok(u64::from_le_bytes(read_array::<8>(input)?))
}

fn read_byte(input: &mut &[u8]) -> Result<u8, FsError> {
    let bytes = read_part(input, 8)?;
    if bytes.len() != 1 {
        return Err(FsError::RestorationRejected {
            message: "restoration field has the wrong size".to_owned(),
        });
    }
    Ok(bytes[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_reject_a_second_mutation() {
        assert!(transition(RestorationState::Prepared, RestorationState::Approved).is_ok());
        assert!(transition(RestorationState::Approved, RestorationState::Restoring).is_ok());
        assert!(transition(RestorationState::Restoring, RestorationState::Restored).is_ok());
        assert!(transition(RestorationState::Restoring, RestorationState::Unclear).is_ok());
        assert!(transition(RestorationState::Unclear, RestorationState::Restored).is_ok());
        assert!(transition(RestorationState::Restored, RestorationState::Restoring).is_err());
        assert!(transition(RestorationState::Failed, RestorationState::Restoring).is_err());
        assert!(transition(RestorationState::Rejected, RestorationState::Approved).is_err());
        assert!(transition(RestorationState::Conflict, RestorationState::Restoring).is_err());
        assert!(transition(RestorationState::Expired, RestorationState::Approved).is_err());
        assert!(transition(RestorationState::Approved, RestorationState::Approved).is_err());
        for state in [
            State::Applying,
            State::Unclear,
            State::Failed,
            State::Applied,
            State::Prepared,
        ] {
            assert!(!publication_evidence_may_be_deleted(
                state,
                Some(RestorationState::Unclear)
            ));
        }
    }

    #[cfg(windows)]
    #[test]
    fn an_expired_restoration_cannot_be_approved() {
        use crate::action::{
            ActionIdFactory, ActionSource, ToolRegistry, propose_actions, validate_batch,
        };
        use crate::fs::{ApplyFault, FsLimitValues, FsLimits, execute_validated};
        use crate::sandbox::WorkspaceSandbox;
        use serde_json::json;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("lca-expire-ws-{nanos}"));
        let state = std::env::temp_dir().join(format!("lca-expire-store-{nanos}"));
        std::fs::create_dir_all(&root).expect("root");
        std::fs::write(root.join("notes.txt"), "alpha\n").expect("seed");
        let sandbox = WorkspaceSandbox::new(&root).expect("sandbox");
        let store = ProposalStore::open(&state).expect("store");
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
        let saved = store.save(&sandbox, &prepared).expect("save");
        let view = store.show(&sandbox, &saved.id).expect("show");
        let _ = store
            .approve_with(
                &sandbox,
                &limits,
                &saved.id,
                &view.digest,
                &view.confirmation,
                ApplyFault::DuringPublish,
            )
            .expect_err("tear");
        let _ = store.recover(&sandbox, &saved.id);
        let before = std::fs::read(root.join("notes.txt")).expect("torn");
        let restoration = store
            .prepare_restoration(&sandbox, &saved.id)
            .expect("restoration");
        store
            .testing_expire_restoration(&sandbox, &restoration.id)
            .expect("expire");
        let status = store
            .status_restoration(&sandbox, &restoration.id)
            .expect("status");
        assert_eq!(status.state, "expired");
        let error = store
            .approve_restoration(
                &sandbox,
                &limits,
                &restoration.id,
                &restoration.current_sha256,
                "restore expired",
            )
            .expect_err("approve");
        assert_eq!(error.kind(), "approval_consumed");
        assert_eq!(std::fs::read(root.join("notes.txt")).expect("kept"), before);
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn an_unknown_contract_version_is_rejected() {
        let mut record = sample_record();
        record.contract_version = 2;
        record.digest = record.canonical_digest().expect("digest");
        let encoded = record.canonical().expect("body");
        let mut bytes = encoded;
        bytes.push(record.state.to_byte());
        bytes.extend_from_slice(&record.digest);
        let error = match RestorationRecord::decode(&bytes) {
            Ok(_) => panic!("version 2 was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), "restoration_rejected");
    }

    fn sample_record() -> RestorationRecord {
        let id = Uuid::nil();
        RestorationRecord {
            id,
            contract_version: CONTRACT_VERSION,
            source_proposal_id: Uuid::nil(),
            source_digest: [7; 32],
            action_id: 1,
            workspace_volume: 1,
            workspace_file_id: [2; 16],
            workspace_path: "C:/workspace".to_owned(),
            relative_path: "notes.txt".to_owned(),
            target_volume: 1,
            target_file_id: [3; 16],
            identity_created: 1,
            identity_modified: 2,
            identity_len: 6,
            current_sha256: sha256(b"beta\n\n"),
            restored_sha256: sha256(b"alpha\n"),
            original_evidence_sha256: [9; 32],
            source_attempt_id: Uuid::nil(),
            created_at: 10,
            expires_at: 20,
            current_bytes: b"beta\n\n".to_vec(),
            restored_bytes: b"alpha\n".to_vec(),
            state: RestorationState::Prepared,
            digest: [0; 32],
        }
    }
}
