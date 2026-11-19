//! Windows observations for the cross-identity harness.
//!
//! Token fields are read with `GetTokenInformation`. A SID string supplied by a
//! caller is not accepted here. No account is created and no production ACL is edited.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::Credentials::{
    CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
};
use windows_sys::Win32::Security::{
    AccessCheck, AllocateAndInitializeSid, CheckTokenMembership, CopySid, DuplicateTokenEx,
    FreeSid, GENERIC_MAPPING, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, InitializeSecurityDescriptor, LOGON32_LOGON_INTERACTIVE,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, LookupAccountNameW, LookupPrivilegeNameW, PRIVILEGE_SET,
    SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES,
    SID_IDENTIFIER_AUTHORITY, SecurityIdentification, SetSecurityDescriptorDacl,
    SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, TOKEN_DUPLICATE, TOKEN_GROUPS,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_SOURCE, TOKEN_STATISTICS, TOKEN_USER, TokenGroups,
    TokenImpersonation, TokenIntegrityLevel, TokenPrimary, TokenPrivileges, TokenRestrictedSids,
    TokenSource, TokenStatistics, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::contract::{
    Integrity, LogonId, Password, PrincipalSnapshot, SecurityId, TokenKind, TokenPrivilege,
    TokenSource, Verification,
};

const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
const FILE_READ_DATA: u32 = 0x1;
const GRANT: i32 = 1;
const TRUSTEE_IS_SID: i32 = 0;
const TRUSTEE_IS_USER: i32 = 1;
const SE_FILE_OBJECT: i32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL: u32 = 0x8000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ERROR_NONE_MAPPED: u32 = 1332;
const ERROR_NOT_FOUND: u32 = 1168;

pub(super) enum Secret {
    Absent(u32),
    Empty,
    Mismatch,
    Present(Password),
}

pub(super) fn current_principal() -> Result<PrincipalSnapshot, u32> {
    let token = open_current_token(TOKEN_QUERY)?;
    let snapshot = snapshot_token(token);
    close(token);
    snapshot
}

pub(super) fn snapshot_token(token: HANDLE) -> Result<PrincipalSnapshot, u32> {
    let user = token_user(token).ok_or(11u32)?;
    let text = sid_text(user.as_ptr()).map_err(|code| 100 + code)?;
    let user_sid = SecurityId::parse(&text).ok_or(12u32)?;
    let stats = token_stats(token).ok_or(13u32)?;
    let source = token_source(token);
    let kind = if stats.TokenType == TokenPrimary {
        TokenKind::Primary
    } else if stats.TokenType == TokenImpersonation {
        TokenKind::Impersonation
    } else {
        TokenKind::Unknown
    };
    Ok(PrincipalSnapshot {
        user_sid,
        logon_sid: logon_sid(token).and_then(|text| SecurityId::parse(&text)),
        token_type: kind,
        integrity: Integrity::from_rid(integrity_rid(token)),
        enabled_groups: group_sids(token, TokenGroups, true),
        restricted_groups: group_sids(token, TokenRestrictedSids, false),
        privileges: privilege_list(token),
        authentication_id: LogonId {
            low: stats.AuthenticationId.LowPart,
            high: stats.AuthenticationId.HighPart,
        },
        token_source: source,
        verification: Verification::TokenObserved,
    })
}

pub(super) fn access_check_probe() -> Result<String, u32> {
    let primary = open_current_token(TOKEN_QUERY | TOKEN_DUPLICATE)?;
    let impersonation = duplicate_identification(primary)?;
    let user = token_user(primary).ok_or(1u32)?;
    let foreign = allocate_sid(&[0, 0, 0, 0, 0, 5], &[21, 1, 2, 3, 99])?;
    let foreign_denied = access_allowed(
        impersonation,
        user.as_ptr(),
        foreign.as_ptr(),
        FILE_READ_DATA,
    )? == 0;
    let self_allowed =
        access_allowed(impersonation, user.as_ptr(), user.as_ptr(), FILE_READ_DATA)? == 1;
    let admin = member_of(primary, &[0, 0, 0, 0, 0, 5], &[32, 544]);
    let owner = owner_probe()?;
    close(impersonation);
    close(primary);
    Ok(format!(
        "foreign_denied={} self_allowed={} admin={} {owner}",
        u8::from(foreign_denied),
        u8::from(self_allowed),
        u8::from(admin)
    ))
}

pub(super) fn same_user_pipe_probe() -> Result<String, u32> {
    let snapshot = current_principal()?;
    let sid = current_sid_bytes()?;
    let name = pipe_name("self");
    let pipe = create_pipe(&name, &sid, None)?;
    let client_name = name.clone();
    let client = std::thread::spawn(move || pipe_client(&client_name));
    let connected = connect_pipe(pipe);
    let observed = if connected {
        observe_client(pipe, 1)
    } else {
        None
    };
    let mut broker =
        super::broker::Broker::new(snapshot.user_sid.as_str(), b"fixture-bytes".to_vec());
    let now = unix_ms();
    let clean = super::broker::request("session-none", "req-self", "ping", "", now, now + 1_000);
    let peer = observed.clone().unwrap_or_else(empty_peer);
    let decision = super::broker::label(&broker.decide(&clean, &peer, now));
    let smuggled = clean.replacen('}', ",\"user_sid\":\"S-1-5-21-9-8-7-1001\"}", 1);
    let smuggled_label = super::broker::label(&broker.decide(&smuggled, &peer, now));
    close(pipe);
    let _ = client.join();
    let match_sid = observed
        .as_ref()
        .is_some_and(|item| item.user_sid == snapshot.user_sid.as_str());
    Ok(format!(
        "observed_sid_match={} message_sid_used=0 decision={decision} smuggled={smuggled_label} impersonation={}",
        u8::from(match_sid),
        u8::from(observed.as_ref().is_some_and(|item| item.impersonation_ok))
    ))
}

pub(super) fn same_user_hardlink_probe() -> Result<String, u32> {
    let dir = temp_dir("link");
    let file = dir.join("owned.txt");
    fs::write(&file, b"owned").map_err(|_| 1u32)?;
    let link = dir.join("alias.txt");
    let code = hardlink(&link, &file);
    let _ = fs::remove_dir_all(&dir);
    Ok(format!("same_user_hardlink={code} cross_identity=0"))
}

pub(super) fn lookup_account(account: &str) -> Result<String, u32> {
    let sid = lookup_raw(account)?;
    sid_text(sid.as_ptr().cast())
}

pub(super) fn read_secret(account: &str) -> Secret {
    let mut wide = wide(super::contract::CREDENTIAL_TARGET);
    let mut raw = ptr::null_mut();
    let ok = unsafe { CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) };
    if ok == 0 || raw.is_null() {
        let code = unsafe { GetLastError() };
        return Secret::Absent(if code == 0 { ERROR_NOT_FOUND } else { code });
    }
    let credential = unsafe { &*raw };
    let user = wide_ptr_to_string(credential.UserName);
    let password = password_from(credential);
    zero_blob(credential);
    unsafe { CredFree(raw.cast()) };
    wide.fill(0);
    if !user_matches(&user, account) {
        return Secret::Mismatch;
    }
    if password.is_empty() {
        Secret::Empty
    } else {
        Secret::Present(password)
    }
}

pub(super) fn logon(account: &str, password: &Password) -> Result<HANDLE, u32> {
    let mut user = wide(account);
    let mut domain = wide(".");
    let mut token = ptr::null_mut();
    let ok = unsafe {
        LogonUserW(
            user.as_ptr(),
            domain.as_ptr(),
            password.as_wide().as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    user.fill(0);
    domain.fill(0);
    if ok == 0 || token.is_null() {
        Err(unsafe { GetLastError() })
    } else {
        Ok(token)
    }
}

pub(super) fn privileged_snapshot(snapshot: &PrincipalSnapshot) -> bool {
    snapshot.integrity.bypasses_medium()
        || snapshot
            .enabled_groups
            .iter()
            .any(|sid| super::contract::privileged_group(sid.as_str()))
        || snapshot
            .privileges
            .iter()
            .any(|item| super::contract::dangerous_privilege(&item.name))
}

pub(super) fn protect_user(path: &Path) -> Result<(), u32> {
    let user = current_sid_bytes()?;
    let system = allocate_sid(&[0, 0, 0, 0, 0, 5], &[18])?;
    let mut entries = [
        ace(user.as_ptr(), GENERIC_ALL),
        ace(system.as_ptr(), GENERIC_ALL),
    ];
    apply_dacl(path, &mut entries)
}

pub(super) fn grant_account(path: &Path, account: &str, access: u32) -> Result<(), u32> {
    let user = current_sid_bytes()?;
    let worker = lookup_sid_bytes(account)?;
    let system = allocate_sid(&[0, 0, 0, 0, 0, 5], &[18])?;
    let mut entries = [
        ace(user.as_ptr(), GENERIC_ALL),
        ace(system.as_ptr(), GENERIC_ALL),
        ace(worker.as_ptr(), access),
    ];
    apply_dacl(path, &mut entries)
}

pub(super) fn create_worker_pipe(name: &str, worker_sid: &str) -> Result<HANDLE, u32> {
    let worker = lookup_sid_bytes(worker_sid)?;
    create_pipe(name, &current_sid_bytes()?, Some(&worker))
}

pub(super) fn connect_pipe(pipe: HANDLE) -> bool {
    let ok = unsafe { windows_sys::Win32::System::Pipes::ConnectNamedPipe(pipe, ptr::null_mut()) };
    ok != 0 || unsafe { GetLastError() } == 535
}

pub(super) fn observe_client(
    pipe: HANDLE,
    pipe_instance: u64,
) -> Option<super::broker::ObservedPeer> {
    let mut pid = 0u32;
    if unsafe { windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(pipe, &mut pid) }
        == 0
    {
        return None;
    }
    let impersonated = impersonation_facts(pipe);
    let process = process_facts(pid);
    let user_sid = process
        .as_ref()
        .map(|facts| facts.sid.clone())
        .unwrap_or_default();
    let impersonation_sid = impersonated
        .as_ref()
        .map(|facts| facts.sid.clone())
        .unwrap_or_default();
    let (logon_low, logon_high) = process
        .as_ref()
        .map(|facts| (facts.low, facts.high))
        .unwrap_or((0, 0));
    let impersonation_ok = match (&impersonated, &process) {
        (Some(impersonated), Some(process)) => {
            impersonated.sid == process.sid
                && impersonated.low == process.low
                && impersonated.high == process.high
                && !process.sid.is_empty()
        }
        _ => false,
    };
    Some(super::broker::ObservedPeer {
        pid,
        user_sid,
        logon_low,
        logon_high,
        pipe_instance,
        impersonation_sid,
        impersonation_ok,
    })
}

pub(super) fn read_frame(pipe: HANDLE) -> Result<Vec<u8>, u32> {
    let mut buffer = vec![0u8; 2048];
    let mut read = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            pipe,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).unwrap_or(0),
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 || read == 0 {
        return Err(if ok == 0 {
            unsafe { GetLastError() }
        } else {
            0
        });
    }
    buffer.truncate(usize::try_from(read).unwrap_or(0));
    Ok(buffer)
}

pub(super) fn write_frame(pipe: HANDLE, bytes: &[u8]) -> Result<(), u32> {
    let mut written = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            pipe,
            bytes.as_ptr().cast(),
            u32::try_from(bytes.len()).unwrap_or(0),
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

pub(super) fn open_process_token(process: HANDLE) -> Result<HANDLE, u32> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(token)
    }
}

pub(super) fn close(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
}

pub(super) fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(0))
        .unwrap_or(0)
}

pub(super) fn pipe_name(label: &str) -> String {
    format!(
        r"\\.\pipe\lca-01n-{}-{}-{label}",
        std::process::id(),
        unix_ms()
    )
}

fn empty_peer() -> super::broker::ObservedPeer {
    super::broker::ObservedPeer {
        pid: 0,
        user_sid: String::new(),
        logon_low: 0,
        logon_high: 0,
        pipe_instance: 1,
        impersonation_sid: String::new(),
        impersonation_ok: false,
    }
}

struct Facts {
    sid: String,
    low: u32,
    high: i32,
}

fn impersonation_facts(pipe: HANDLE) -> Option<Facts> {
    if unsafe { windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient(pipe) } == 0 {
        return None;
    }
    let mut token = ptr::null_mut();
    let opened = unsafe {
        windows_sys::Win32::System::Threading::OpenThreadToken(
            windows_sys::Win32::System::Threading::GetCurrentThread(),
            TOKEN_QUERY,
            1,
            &mut token,
        )
    };
    let facts = if opened == 0 {
        None
    } else {
        let facts = facts_of(token);
        close(token);
        facts
    };
    unsafe { windows_sys::Win32::Security::RevertToSelf() };
    facts
}

fn process_facts(pid: u32) -> Option<Facts> {
    let process = unsafe { windows_sys::Win32::System::Threading::OpenProcess(0x1000, 0, pid) };
    if process.is_null() {
        return None;
    }
    let token = open_process_token(process).ok();
    close(process);
    let token = token?;
    let facts = facts_of(token);
    close(token);
    facts
}

fn facts_of(token: HANDLE) -> Option<Facts> {
    let user = token_user(token)?;
    let sid = sid_text(user.as_ptr()).ok()?;
    let stats = token_stats(token)?;
    Some(Facts {
        sid,
        low: stats.AuthenticationId.LowPart,
        high: stats.AuthenticationId.HighPart,
    })
}

fn pipe_client(name: &str) -> u32 {
    let wide_name = wide(name);
    let mut handle = INVALID_HANDLE_VALUE;
    for _ in 0..50 {
        handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                FILE_GENERIC_READ | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE,
                0,
                ptr::null(),
                3,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return unsafe { GetLastError() };
    }
    let now = unix_ms();
    let message = super::broker::request("session-none", "req-self", "ping", "", now, now + 1_000);
    let _ = write_frame(handle, message.as_bytes());
    let _ = read_frame(handle);
    close(handle);
    0
}

fn owner_probe() -> Result<String, u32> {
    let dir = temp_dir("acl");
    let file = dir.join("owned.txt");
    fs::write(&file, b"owned").map_err(|_| 1u32)?;
    protect_user(&file)?;
    let name = wide_path(&file);
    let mut owner = ptr::null_mut();
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let owner_text = if code == 0 && !owner.is_null() {
        sid_text(owner).unwrap_or_default()
    } else {
        String::new()
    };
    let user = current_principal()
        .map(|item| item.user_sid.as_str().to_owned())
        .unwrap_or_default();
    let aces = if dacl.is_null() {
        0
    } else {
        u32::from(unsafe { (*dacl.cast::<windows_sys::Win32::Security::ACL>()).AceCount })
    };
    if !descriptor.is_null() {
        unsafe { LocalFree(descriptor.cast()) };
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(format!(
        "owner_match={} ace_count={aces} query={code}",
        u8::from(!owner_text.is_empty() && owner_text == user)
    ))
}

fn access_allowed(
    token: HANDLE,
    owner: *mut c_void,
    sid: *mut c_void,
    desired: u32,
) -> Result<u8, u32> {
    let mut entries = [ace(sid, desired)];
    let dacl = build_dacl(&mut entries).map_err(|code| 1_000 + code)?;
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    if unsafe {
        InitializeSecurityDescriptor(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        unsafe { LocalFree(dacl.cast()) };
        return Err(2_000 + unsafe { GetLastError() });
    }
    if unsafe {
        SetSecurityDescriptorDacl(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            1,
            dacl.cast(),
            0,
        )
    } == 0
    {
        unsafe { LocalFree(dacl.cast()) };
        return Err(3_000 + unsafe { GetLastError() });
    }
    if unsafe {
        SetSecurityDescriptorOwner(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            owner,
            0,
        )
    } == 0
        || unsafe {
            SetSecurityDescriptorGroup(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                owner,
                0,
            )
        } == 0
    {
        unsafe { LocalFree(dacl.cast()) };
        return Err(3_500 + unsafe { GetLastError() });
    }
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_READ_DATA,
        GenericWrite: 0x2,
        GenericExecute: 0x20,
        GenericAll: FILE_READ_DATA,
    };
    let mut privileges: PRIVILEGE_SET = unsafe { std::mem::zeroed() };
    let mut length = u32::try_from(std::mem::size_of::<PRIVILEGE_SET>()).unwrap_or(0);
    let mut granted = 0u32;
    let mut status = 0i32;
    let ok = unsafe {
        AccessCheck(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            token,
            desired,
            &mapping,
            &mut privileges,
            &mut length,
            &mut granted,
            &mut status,
        )
    };
    unsafe { LocalFree(dacl.cast()) };
    if ok == 0 {
        Err(4_000 + unsafe { GetLastError() })
    } else {
        Ok(u8::from(status != 0))
    }
}

fn member_of(token: HANDLE, authority: &[u8; 6], subs: &[u32]) -> bool {
    let sid = allocate_sid(authority, subs);
    let Ok(sid) = sid else {
        return false;
    };
    let mut member = 0i32;
    let ok = unsafe { CheckTokenMembership(token, sid.as_ptr(), &mut member) };
    ok != 0 && member != 0
}

fn hardlink(link: &Path, existing: &Path) -> u32 {
    let link_w = wide_path(link);
    let existing_w = wide_path(existing);
    let ok = unsafe { CreateHardLinkW(link_w.as_ptr(), existing_w.as_ptr(), ptr::null()) };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn create_pipe(name: &str, owner: &OwnedSid, worker: Option<&OwnedSid>) -> Result<HANDLE, u32> {
    let system = allocate_sid(&[0, 0, 0, 0, 0, 5], &[18])?;
    let mut entries = vec![
        ace(owner.as_ptr(), GENERIC_ALL),
        ace(system.as_ptr(), GENERIC_ALL),
    ];
    if let Some(worker) = worker {
        entries.push(ace(
            worker.as_ptr(),
            FILE_GENERIC_READ | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE,
        ));
    }
    let dacl = build_dacl(&mut entries)?;
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    if unsafe {
        InitializeSecurityDescriptor(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            SECURITY_DESCRIPTOR_REVISION,
        )
    } == 0
    {
        unsafe { LocalFree(dacl.cast()) };
        return Err(unsafe { GetLastError() });
    }
    if unsafe {
        SetSecurityDescriptorDacl(
            (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            1,
            dacl.cast(),
            0,
        )
    } == 0
    {
        unsafe { LocalFree(dacl.cast()) };
        return Err(unsafe { GetLastError() });
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
        bInheritHandle: 0,
    };
    let wide_name = wide(name);
    let handle = unsafe {
        windows_sys::Win32::System::Pipes::CreateNamedPipeW(
            wide_name.as_ptr(),
            windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX,
            windows_sys::Win32::System::Pipes::PIPE_TYPE_MESSAGE
                | windows_sys::Win32::System::Pipes::PIPE_READMODE_MESSAGE
                | windows_sys::Win32::System::Pipes::PIPE_WAIT
                | windows_sys::Win32::System::Pipes::PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            0,
            &security,
        )
    };
    unsafe { LocalFree(dacl.cast()) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(handle)
    }
}

fn apply_dacl(path: &Path, entries: &mut [EXPLICIT_ACCESS_W]) -> Result<(), u32> {
    let dacl = build_dacl(entries)?;
    let name = wide_path(path);
    let applied = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl.cast(),
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(dacl.cast()) };
    if applied == 0 { Ok(()) } else { Err(applied) }
}

fn build_dacl(entries: &mut [EXPLICIT_ACCESS_W]) -> Result<*mut c_void, u32> {
    let mut dacl = ptr::null_mut();
    let built = unsafe {
        SetEntriesInAclW(
            u32::try_from(entries.len()).unwrap_or(0),
            entries.as_mut_ptr(),
            ptr::null(),
            &mut dacl,
        )
    };
    if built != 0 || dacl.is_null() {
        Err(if built == 0 { 1 } else { built })
    } else {
        Ok(dacl.cast())
    }
}

fn ace(sid: *mut c_void, access: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    }
}

struct OwnedSid(Vec<u8>);

impl OwnedSid {
    fn as_ptr(&self) -> *mut c_void {
        self.0.as_ptr().cast_mut().cast()
    }
}

fn current_sid_bytes() -> Result<OwnedSid, u32> {
    let token = open_current_token(TOKEN_QUERY)?;
    let user = token_user(token).ok_or(1u32)?;
    close(token);
    Ok(user)
}

fn lookup_sid_bytes(account: &str) -> Result<OwnedSid, u32> {
    lookup_raw(account)
}

fn lookup_raw(account: &str) -> Result<OwnedSid, u32> {
    let name = wide(account);
    let mut sid = vec![0u8; 256];
    let mut sid_len = u32::try_from(sid.len()).unwrap_or(0);
    let mut domain = vec![0u16; 256];
    let mut domain_len = u32::try_from(domain.len()).unwrap_or(0);
    let mut use_name = 0i32;
    let ok = unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_name,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(if code == 0 { ERROR_NONE_MAPPED } else { code });
    }
    sid.truncate(usize::try_from(sid_len).unwrap_or(sid.len()));
    Ok(OwnedSid(sid))
}

fn password_from(credential: &CREDENTIALW) -> Password {
    let size = usize::try_from(credential.CredentialBlobSize).unwrap_or(0);
    if credential.CredentialBlob.is_null() || size < 2 || size % 2 != 0 {
        return Password::from_units(Vec::new());
    }
    let units =
        unsafe { std::slice::from_raw_parts(credential.CredentialBlob.cast::<u16>(), size / 2) };
    let mut owned = units.to_vec();
    if owned.last() == Some(&0) {
        owned.pop();
    }
    if owned.is_empty() {
        return Password::from_units(Vec::new());
    }
    owned.push(0);
    Password::from_units(owned)
}

fn zero_blob(credential: &CREDENTIALW) {
    let size = usize::try_from(credential.CredentialBlobSize).unwrap_or(0);
    if !credential.CredentialBlob.is_null() && size > 0 {
        unsafe { ptr::write_bytes(credential.CredentialBlob, 0, size) };
    }
}

fn user_matches(stored: &str, account: &str) -> bool {
    let stored = stored.trim();
    stored.eq_ignore_ascii_case(account)
        || stored
            .rsplit(['\\', '/'])
            .next()
            .is_some_and(|rest| rest.eq_ignore_ascii_case(account))
}

fn open_current_token(access: u32) -> Result<HANDLE, u32> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(token)
    }
}

fn duplicate_identification(token: HANDLE) -> Result<HANDLE, u32> {
    let mut duplicated = ptr::null_mut();
    let ok = unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY,
            ptr::null(),
            SecurityIdentification,
            TokenImpersonation,
            &mut duplicated,
        )
    };
    if ok == 0 || duplicated.is_null() {
        Err(unsafe { GetLastError() })
    } else {
        Ok(duplicated)
    }
}

fn token_user(token: HANDLE) -> Option<OwnedSid> {
    let buffer = token_buffer(token, TokenUser);
    if buffer.len() < std::mem::size_of::<TOKEN_USER>() {
        return None;
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    copy_sid(user.User.Sid).ok()
}

fn token_stats(token: HANDLE) -> Option<TOKEN_STATISTICS> {
    let buffer = token_buffer(token, TokenStatistics);
    if buffer.len() < std::mem::size_of::<TOKEN_STATISTICS>() {
        None
    } else {
        Some(unsafe { buffer.as_ptr().cast::<TOKEN_STATISTICS>().read_unaligned() })
    }
}

fn token_source(token: HANDLE) -> TokenSource {
    let mut source: TOKEN_SOURCE = unsafe { std::mem::zeroed() };
    let mut needed = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenSource,
            (&mut source as *mut TOKEN_SOURCE).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_SOURCE>()).unwrap_or(0),
            &mut needed,
        )
    };
    if ok == 0 {
        return TokenSource {
            name: format!("api-{}", unsafe { GetLastError() }),
            low: 0,
            high: 0,
        };
    }
    let bytes = source.SourceName;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let name: String = bytes[..end]
        .iter()
        .filter_map(|byte| u8::try_from(*byte).ok())
        .map(char::from)
        .collect();
    TokenSource {
        name: if name.is_empty() {
            "empty".to_owned()
        } else {
            name
        },
        low: source.SourceIdentifier.LowPart,
        high: source.SourceIdentifier.HighPart,
    }
}

fn logon_sid(token: HANDLE) -> Option<String> {
    let buffer = token_buffer(token, TokenGroups);
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        return None;
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let base = std::ptr::addr_of!(groups.Groups[0]);
    for index in 0..groups.GroupCount {
        let entry = unsafe { &*base.add(usize::try_from(index).unwrap_or(0)) };
        if entry.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID && !entry.Sid.is_null() {
            return sid_text(entry.Sid).ok();
        }
    }
    None
}

fn group_sids(token: HANDLE, class: i32, enabled_only: bool) -> Vec<SecurityId> {
    let buffer = token_buffer(token, class);
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        return Vec::new();
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let base = std::ptr::addr_of!(groups.Groups[0]);
    let mut out = Vec::new();
    for index in 0..groups.GroupCount {
        let entry = unsafe { &*base.add(usize::try_from(index).unwrap_or(0)) };
        if enabled_only && entry.Attributes & SE_GROUP_ENABLED == 0 {
            continue;
        }
        if entry.Sid.is_null() {
            continue;
        }
        if let Ok(text) = sid_text(entry.Sid)
            && let Some(sid) = SecurityId::parse(&text)
        {
            out.push(sid);
        }
    }
    out
}

fn privilege_list(token: HANDLE) -> Vec<TokenPrivilege> {
    let buffer = token_buffer(token, TokenPrivileges);
    if buffer.len() < std::mem::size_of::<TOKEN_PRIVILEGES>() {
        return Vec::new();
    }
    let privileges = unsafe { &*buffer.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let base = std::ptr::addr_of!(privileges.Privileges[0]);
    let mut out = Vec::new();
    for index in 0..privileges.PrivilegeCount {
        let entry = unsafe { &*base.add(usize::try_from(index).unwrap_or(0)) };
        out.push(TokenPrivilege {
            name: privilege_name(&entry.Luid),
            enabled: entry.Attributes & SE_PRIVILEGE_ENABLED != 0,
        });
    }
    out
}

fn privilege_name(luid: &windows_sys::Win32::Foundation::LUID) -> String {
    let mut name = vec![0u16; 80];
    let mut length = u32::try_from(name.len()).unwrap_or(0);
    let ok = unsafe { LookupPrivilegeNameW(ptr::null(), luid, name.as_mut_ptr(), &mut length) };
    if ok == 0 {
        return format!("luid-{}-{}", luid.LowPart, luid.HighPart);
    }
    let end = usize::try_from(length).unwrap_or(0).min(name.len());
    String::from_utf16_lossy(&name[..end])
}

fn integrity_rid(token: HANDLE) -> u32 {
    let buffer = token_buffer(token, TokenIntegrityLevel);
    if buffer.len() < std::mem::size_of::<SID_AND_ATTRIBUTES>() {
        return 0;
    }
    let label = unsafe { &*buffer.as_ptr().cast::<SID_AND_ATTRIBUTES>() };
    let count_ptr = unsafe { GetSidSubAuthorityCount(label.Sid) };
    if count_ptr.is_null() {
        return 0;
    }
    let count = unsafe { *count_ptr };
    if count == 0 {
        return 0;
    }
    let sub = unsafe { GetSidSubAuthority(label.Sid, u32::from(count - 1)) };
    if sub.is_null() { 0 } else { unsafe { *sub } }
}

fn token_buffer(token: HANDLE, class: i32) -> Vec<u8> {
    let mut needed = 0u32;
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Vec::new();
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 { Vec::new() } else { buffer }
}

fn sid_text(sid: *mut c_void) -> Result<String, u32> {
    if sid.is_null() {
        return Err(1);
    }
    let mut raw = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut raw) } == 0 || raw.is_null() {
        return Err(unsafe { GetLastError() });
    }
    let mut length = 0usize;
    while unsafe { *raw.add(length) } != 0 {
        length += 1;
        if length > 256 {
            break;
        }
    }
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, length) });
    unsafe { LocalFree(raw.cast()) };
    if text.is_empty() { Err(1) } else { Ok(text) }
}

fn copy_sid(sid: *mut c_void) -> Result<OwnedSid, u32> {
    if sid.is_null() {
        return Err(1);
    }
    let length = unsafe { GetLengthSid(sid) };
    let mut owned = vec![0u8; length as usize];
    if unsafe { CopySid(length, owned.as_mut_ptr().cast(), sid) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(OwnedSid(owned))
}

fn allocate_sid(authority: &[u8; 6], subs: &[u32]) -> Result<OwnedSid, u32> {
    let mut sid = ptr::null_mut();
    let ident = SID_IDENTIFIER_AUTHORITY { Value: *authority };
    let mut sub = [0u32; 8];
    for (index, value) in subs.iter().enumerate().take(8) {
        sub[index] = *value;
    }
    let ok = unsafe {
        AllocateAndInitializeSid(
            &ident,
            u8::try_from(subs.len()).unwrap_or(0),
            sub[0],
            sub[1],
            sub[2],
            sub[3],
            sub[4],
            sub[5],
            sub[6],
            sub[7],
            &mut sid,
        )
    };
    if ok == 0 || sid.is_null() {
        return Err(unsafe { GetLastError() });
    }
    let owned = copy_sid(sid);
    unsafe { FreeSid(sid) };
    owned
}

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "lca-01n-{label}-{}-{}",
        std::process::id(),
        unix_ms()
    ));
    let _ = fs::create_dir_all(&path);
    path
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn wide_ptr_to_string(value: *mut u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut length = 0usize;
    while unsafe { *value.add(length) } != 0 && length < 256 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) })
}
