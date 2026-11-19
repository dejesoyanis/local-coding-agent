//! Typed worker principal and the cross-identity invariants.
//!
//! Nothing in this module reads a password or a Windows token. Callers pass a
//! snapshot that was taken from a token handle. A SID copied out of a worker
//! message stays [`Verification::SidOnly`] and cannot satisfy the boundary.

use std::path::{Path, PathBuf};

/// Credential Manager target. The harness reads it and never writes it.
pub(super) const CREDENTIAL_TARGET: &str = "LCA-01N-Worker";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SecurityId(String);

impl SecurityId {
    pub(super) fn parse(text: &str) -> Option<Self> {
        if valid_sid(text) {
            Some(Self(text.to_owned()))
        } else {
            None
        }
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TokenKind {
    Primary,
    Impersonation,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Integrity {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    Other(u32),
}

impl Integrity {
    pub(super) const fn from_rid(rid: u32) -> Self {
        match rid {
            0 => Self::Untrusted,
            4096 => Self::Low,
            8192 => Self::Medium,
            8448 => Self::MediumPlus,
            12288 => Self::High,
            16384 => Self::System,
            other => Self::Other(other),
        }
    }

    pub(super) const fn bypasses_medium(self) -> bool {
        match self {
            Self::High | Self::System => true,
            Self::Other(rid) => rid > 8192,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TokenPrivilege {
    pub name: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LogonId {
    pub low: u32,
    pub high: i32,
}

impl LogonId {
    pub(super) const fn nonzero(self) -> bool {
        self.low != 0 || self.high != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TokenSource {
    pub name: String,
    pub low: u32,
    pub high: i32,
}

/// How the snapshot was obtained. A worker message cannot produce the stronger states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Verification {
    Unverified,
    SidOnly,
    TokenObserved,
    AccessChecked,
    Rejected,
}

impl Verification {
    pub(super) const fn token_proven(self) -> bool {
        matches!(self, Self::TokenObserved | Self::AccessChecked)
    }

    pub(super) const fn access_proven(self) -> bool {
        matches!(self, Self::AccessChecked)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PrincipalSnapshot {
    pub user_sid: SecurityId,
    pub logon_sid: Option<SecurityId>,
    pub token_type: TokenKind,
    pub integrity: Integrity,
    pub enabled_groups: Vec<SecurityId>,
    pub restricted_groups: Vec<SecurityId>,
    pub privileges: Vec<TokenPrivilege>,
    pub authentication_id: LogonId,
    pub token_source: TokenSource,
    pub verification: Verification,
}

impl PrincipalSnapshot {
    pub(super) fn public_summary(&self) -> String {
        format!(
            "sid_well_formed=1 sid_len={} logon_sid={} token_type={} integrity={:?} enabled_groups={} restricted_groups={} privileges={} dangerous={} auth_nonzero={} source_len={} verification={:?}",
            self.user_sid.as_str().len(),
            u8::from(self.logon_sid.is_some()),
            match self.token_type {
                TokenKind::Primary => 1,
                TokenKind::Impersonation => 2,
                TokenKind::Unknown => 0,
            },
            self.integrity,
            self.enabled_groups.len(),
            self.restricted_groups.len(),
            self.privileges.len(),
            u8::from(
                self.privileges
                    .iter()
                    .any(|item| dangerous_privilege(&item.name))
            ),
            u8::from(self.authentication_id.nonzero()),
            self.token_source.name.len(),
            self.verification
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Finding {
    Holds,
    Violated,
    Inconclusive,
}

pub(super) struct Invariant {
    pub id: &'static str,
    pub finding: Finding,
}

/// Measurements the broker made. `None` means that measurement was not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Evidence {
    pub store_readable: Option<bool>,
    pub store_writable: Option<bool>,
    pub evidence_readable: Option<bool>,
    pub evidence_writable: Option<bool>,
    pub restoration_readable: Option<bool>,
    pub restoration_writable: Option<bool>,
    pub host_readable: Option<bool>,
    pub host_writable: Option<bool>,
    pub registered_only: Option<bool>,
    pub path_authorized: Option<bool>,
    pub implicit_handles: Option<bool>,
    pub restart_new_session: Option<bool>,
    pub abort_contained: Option<bool>,
    pub worker_minted: Option<bool>,
    pub boundary_claimed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    /// A different user SID was started and the access checks held.
    Validated,
    /// A worker started, and at least one decisive check is missing or failed.
    Partial,
    /// No separate principal was started.
    NotEstablished,
}

pub(super) fn evaluate(
    broker: &PrincipalSnapshot,
    worker: &PrincipalSnapshot,
    evidence: &Evidence,
) -> Vec<Invariant> {
    vec![
        Invariant {
            id: "INV-01",
            finding: distinct_sid(broker, worker),
        },
        Invariant {
            id: "INV-02",
            finding: groups_are_unprivileged(worker),
        },
        Invariant {
            id: "INV-03",
            finding: privileges_are_safe(worker),
        },
        Invariant {
            id: "INV-04",
            finding: denied_pair(
                worker,
                evidence.store_readable,
                evidence.store_writable,
                evidence.evidence_readable,
                evidence.evidence_writable,
                evidence.restoration_readable,
                evidence.restoration_writable,
            ),
        },
        Invariant {
            id: "INV-05",
            finding: denied_pair(
                worker,
                evidence.host_readable,
                evidence.host_writable,
                Some(false),
                Some(false),
                Some(false),
                Some(false),
            ),
        },
        Invariant {
            id: "INV-06",
            finding: flag(evidence.registered_only, true),
        },
        Invariant {
            id: "INV-07",
            finding: flag(evidence.path_authorized.map(|value| !value), true),
        },
        Invariant {
            id: "INV-08",
            finding: flag(evidence.implicit_handles.map(|value| !value), true),
        },
        Invariant {
            id: "INV-09",
            finding: flag(evidence.restart_new_session, true),
        },
        Invariant {
            id: "INV-10",
            finding: flag(evidence.abort_contained, true),
        },
        Invariant {
            id: "INV-11",
            finding: not_sid_alone(worker, evidence.boundary_claimed),
        },
        Invariant {
            id: "INV-12",
            finding: flag(evidence.worker_minted.map(|value| !value), true),
        },
    ]
}

pub(super) fn finding(items: &[Invariant], id: &str) -> Finding {
    items
        .iter()
        .find(|item| item.id == id)
        .map(|item| item.finding)
        .unwrap_or(Finding::Inconclusive)
}

pub(super) fn decide_gate(worker_started: bool, findings: &[Invariant]) -> Gate {
    if !worker_started {
        return Gate::NotEstablished;
    }
    let mut missing = false;
    let mut violated = false;
    for id in ["INV-01", "INV-04", "INV-05", "INV-06", "INV-08", "INV-11"] {
        match finding(findings, id) {
            Finding::Holds => {}
            Finding::Violated => violated = true,
            Finding::Inconclusive => missing = true,
        }
    }
    if violated || missing {
        Gate::Partial
    } else {
        Gate::Validated
    }
}

pub(super) fn restarted_session(
    previous: &str,
    next: &str,
    previous_luid: (u32, i32),
    next_luid: (u32, i32),
) -> bool {
    previous != next && previous_luid != next_luid && previous_luid != (0, 0) && next_luid != (0, 0)
}

pub(super) const fn abort_contains(terminated: bool, workers_left: u32) -> bool {
    terminated && workers_left == 0
}

pub(super) const fn hardlink_is_violation(created: bool, target_protected: bool) -> bool {
    created && target_protected
}

fn distinct_sid(broker: &PrincipalSnapshot, worker: &PrincipalSnapshot) -> Finding {
    if !broker.verification.token_proven() || !worker.verification.token_proven() {
        return Finding::Inconclusive;
    }
    if broker.user_sid.as_str() == worker.user_sid.as_str() {
        Finding::Violated
    } else {
        Finding::Holds
    }
}

fn groups_are_unprivileged(worker: &PrincipalSnapshot) -> Finding {
    if !worker.verification.token_proven() {
        return Finding::Inconclusive;
    }
    if worker.integrity.bypasses_medium()
        || worker
            .enabled_groups
            .iter()
            .any(|sid| privileged_group(sid.as_str()))
    {
        Finding::Violated
    } else {
        Finding::Holds
    }
}

fn privileges_are_safe(worker: &PrincipalSnapshot) -> Finding {
    if !worker.verification.token_proven() {
        return Finding::Inconclusive;
    }
    if worker
        .privileges
        .iter()
        .any(|item| dangerous_privilege(&item.name))
    {
        Finding::Violated
    } else {
        Finding::Holds
    }
}

fn denied_pair(
    worker: &PrincipalSnapshot,
    first_read: Option<bool>,
    first_write: Option<bool>,
    second_read: Option<bool>,
    second_write: Option<bool>,
    third_read: Option<bool>,
    third_write: Option<bool>,
) -> Finding {
    if !worker.verification.access_proven() {
        return Finding::Inconclusive;
    }
    match (
        first_read,
        first_write,
        second_read,
        second_write,
        third_read,
        third_write,
    ) {
        (Some(false), Some(false), Some(false), Some(false), Some(false), Some(false)) => {
            Finding::Holds
        }
        (Some(true), _, _, _, _, _)
        | (_, Some(true), _, _, _, _)
        | (_, _, Some(true), _, _, _)
        | (_, _, _, Some(true), _, _)
        | (_, _, _, _, Some(true), _)
        | (_, _, _, _, _, Some(true)) => Finding::Violated,
        _ => Finding::Inconclusive,
    }
}

fn flag(value: Option<bool>, expected: bool) -> Finding {
    match value {
        Some(actual) if actual == expected => Finding::Holds,
        Some(_) => Finding::Violated,
        None => Finding::Inconclusive,
    }
}

fn not_sid_alone(worker: &PrincipalSnapshot, boundary_claimed: bool) -> Finding {
    if worker.verification.access_proven() && !boundary_claimed {
        Finding::Holds
    } else if boundary_claimed && !worker.verification.access_proven() {
        Finding::Violated
    } else {
        Finding::Inconclusive
    }
}

pub(super) fn privileged_group(sid: &str) -> bool {
    const NAMED: &[&str] = &[
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-32-547",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
        "S-1-5-32-552",
        "S-1-5-32-569",
        "S-1-5-32-580",
    ];
    if NAMED.contains(&sid) {
        return true;
    }
    let mut parts = sid.split('-');
    if parts.next() != Some("S")
        || parts.next() != Some("1")
        || parts.next() != Some("5")
        || parts.next() != Some("21")
    {
        return false;
    }
    let rest: Vec<&str> = parts.collect();
    rest.len() == 4 && matches!(rest.last().copied(), Some("512" | "518" | "519"))
}

pub(super) fn dangerous_privilege(name: &str) -> bool {
    matches!(
        name,
        "SeDebugPrivilege"
            | "SeTcbPrivilege"
            | "SeAssignPrimaryTokenPrivilege"
            | "SeBackupPrivilege"
            | "SeRestorePrivilege"
            | "SeTakeOwnershipPrivilege"
            | "SeLoadDriverPrivilege"
            | "SeCreateTokenPrivilege"
            | "SeImpersonatePrivilege"
            | "SeRelabelPrivilege"
            | "SeTrustedCredManAccessPrivilege"
            | "SeSecurityPrivilege"
            | "SeManageVolumePrivilege"
            | "SeCreatePermanentPrivilege"
            | "SeEnableDelegationPrivilege"
            | "SeSyncAgentPrivilege"
    )
}

fn valid_sid(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("S-1-") else {
        return false;
    };
    let mut count = 0;
    for part in rest.split('-') {
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        count += 1;
    }
    count >= 2
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HandleUse {
    StandardNull,
    ReportWrite,
    FixtureRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct HandleGrant {
    pub use_kind: HandleUse,
    pub access: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LaunchSpec {
    pub account: String,
    pub executable: PathBuf,
    pub working_directory: PathBuf,
    pub handles: Vec<HandleGrant>,
    pub inherit_unlisted: bool,
    pub endpoint: String,
    pub timeout_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchFault {
    Executable,
    Account,
    Handle,
    Endpoint,
    Timeout,
    Directory,
}

pub(super) fn validate_launch(spec: &LaunchSpec, allowed: &Path) -> Result<(), LaunchFault> {
    if !valid_account(&spec.account) {
        return Err(LaunchFault::Account);
    }
    if spec.executable != allowed || blocked_executable(&spec.executable) {
        return Err(LaunchFault::Executable);
    }
    if !directory_ok(&spec.working_directory) {
        return Err(LaunchFault::Directory);
    }
    if spec.inherit_unlisted || !spec.handles.iter().all(|grant| mask_ok(*grant)) {
        return Err(LaunchFault::Handle);
    }
    if !endpoint_ok(&spec.endpoint) {
        return Err(LaunchFault::Endpoint);
    }
    if spec.timeout_ms == 0 || spec.timeout_ms > 60_000 {
        return Err(LaunchFault::Timeout);
    }
    Ok(())
}

pub(super) fn valid_account(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && !value.eq_ignore_ascii_case("password")
}

fn directory_ok(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, std::path::Component::ParentDir))
}

fn blocked_executable(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some(
            "cmd.exe"
                | "powershell.exe"
                | "pwsh.exe"
                | "cargo.exe"
                | "rustc.exe"
                | "cmd"
                | "powershell"
        )
    )
}

fn mask_ok(grant: HandleGrant) -> bool {
    const FILE_WRITE_DATA: u32 = 0x2;
    const DELETE: u32 = 0x0001_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    let sensitive = FILE_WRITE_DATA | DELETE | WRITE_DAC | WRITE_OWNER;
    match grant.use_kind {
        HandleUse::StandardNull => true,
        HandleUse::FixtureRead => grant.access != 0 && grant.access & sensitive == 0,
        HandleUse::ReportWrite => {
            grant.access != 0 && grant.access & (WRITE_DAC | WRITE_OWNER) == 0
        }
    }
}

fn endpoint_ok(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix(r"\\.\pipe\lca-01n-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

pub(super) fn worker_command_line(executable: &Path) -> Vec<u16> {
    let mut line = String::from("\"");
    line.push_str(&executable.display().to_string());
    line.push_str("\" principal_probe::cross_identity_child --exact");
    line.encode_utf16().chain(Some(0)).collect()
}

pub(super) fn worker_environment(pairs: &[(&str, &str)]) -> Result<Vec<u16>, &'static str> {
    let mut block = Vec::new();
    for (key, value) in pairs {
        if forbidden_env_key(key) || value.to_ascii_lowercase().contains("password") {
            return Err("secret");
        }
        if key.bytes().any(|byte| byte == 0) || value.bytes().any(|byte| byte == 0) {
            return Err("secret");
        }
        block.extend(key.encode_utf16());
        block.push(u16::from(b'='));
        block.extend(value.encode_utf16());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn forbidden_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper.contains("PASSWORD")
        || upper.contains("SECRET")
        || upper.contains("PWD")
        || upper.contains("TOKEN")
        || upper.contains("CRED")
}

/// Password bytes. `Debug` is redacted. The buffer is cleared on drop.
pub(super) struct Password(Vec<u16>);

impl Password {
    pub(super) fn from_units(units: Vec<u16>) -> Self {
        Self(units)
    }

    pub(super) fn as_wide(&self) -> &[u16] {
        &self.0
    }

    pub(super) fn is_empty(&self) -> bool {
        self.0.iter().all(|unit| *unit == 0)
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("redacted")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct OsFailure {
    pub step: &'static str,
    pub code: u32,
}

impl OsFailure {
    pub(super) fn public_text(self) -> String {
        format!("step={} code={}", self.step, self.code)
    }
}

pub(super) fn sample_principal(sid: &str, verification: Verification) -> PrincipalSnapshot {
    PrincipalSnapshot {
        user_sid: sid_unchecked(sid),
        logon_sid: Some(sid_unchecked("S-1-5-5-1-2")),
        token_type: TokenKind::Primary,
        integrity: Integrity::Medium,
        enabled_groups: vec![sid_unchecked("S-1-5-32-545")],
        restricted_groups: Vec::new(),
        privileges: vec![TokenPrivilege {
            name: "SeChangeNotifyPrivilege".to_owned(),
            enabled: true,
        }],
        authentication_id: LogonId { low: 1, high: 0 },
        token_source: TokenSource {
            name: "User32".to_owned(),
            low: 1,
            high: 0,
        },
        verification,
    }
}

pub(super) fn sid(text: &str) -> SecurityId {
    sid_unchecked(text)
}

fn sid_unchecked(text: &str) -> SecurityId {
    SecurityId::parse(text).unwrap_or_else(|| SecurityId(text.to_owned()))
}

pub(super) fn denied_evidence() -> Evidence {
    Evidence {
        store_readable: Some(false),
        store_writable: Some(false),
        evidence_readable: Some(false),
        evidence_writable: Some(false),
        restoration_readable: Some(false),
        restoration_writable: Some(false),
        host_readable: Some(false),
        host_writable: Some(false),
        registered_only: Some(true),
        path_authorized: Some(false),
        implicit_handles: Some(false),
        restart_new_session: Some(true),
        abort_contained: Some(true),
        worker_minted: Some(false),
        boundary_claimed: false,
    }
}

pub(super) fn unknown_evidence() -> Evidence {
    Evidence {
        store_readable: None,
        store_writable: None,
        evidence_readable: None,
        evidence_writable: None,
        restoration_readable: None,
        restoration_writable: None,
        host_readable: None,
        host_writable: None,
        registered_only: None,
        path_authorized: None,
        implicit_handles: None,
        restart_new_session: None,
        abort_contained: None,
        worker_minted: None,
        boundary_claimed: false,
    }
}
