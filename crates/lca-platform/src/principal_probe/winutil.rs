//! Windows objects for the LCA-01M harness. Temporary files, a restricted token, a job,
//! and a named pipe. Nothing here is called from the publisher.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CopySid, CreateRestrictedToken, EqualSid, FreeSid, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, ImpersonateLoggedOnUser,
    InitializeSecurityDescriptor, RevertToSelf, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY, SetSecurityDescriptorDacl, TOKEN_ADJUST_DEFAULT,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_IMPERSONATE, TOKEN_QUERY,
    TOKEN_USER, TokenDefaultDacl, TokenGroups, TokenIntegrityLevel, TokenPrivileges,
    TokenRestrictedSids, TokenType, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_LIMIT_PROCESS_TIME,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT, PeekNamedPipe, SetNamedPipeHandleState,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DETACHED_PROCESS, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThread, GetCurrentThreadId,
    GetExitCodeProcess, InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken,
    OpenThread, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    THREAD_TERMINATE, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::broker::{self, Broker, Peer};

const GRANT: i32 = 1;
const TRUSTEE_IS_SID: i32 = 0;
const TRUSTEE_IS_USER: i32 = 1;
const SE_FILE_OBJECT: i32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL: u32 = 0x8000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
const SANDBOX_INERT: u32 = 0x2;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const STILL_ACTIVE: u32 = 259;
const ERROR_PIPE_CONNECTED: u32 = 535;
const ERROR_MORE_DATA: u32 = 234;
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const RX: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const RWX: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE;

pub(super) struct OwnedSid(Vec<u8>);

impl OwnedSid {
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0.as_ptr().cast_mut().cast()
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(super) struct RestrictedToken {
    raw: HANDLE,
    pub facts: String,
}

impl Drop for RestrictedToken {
    fn drop(&mut self) {
        close_handle(self.raw);
        self.raw = ptr::null_mut();
    }
}

impl RestrictedToken {
    pub(super) fn raw(&self) -> HANDLE {
        self.raw
    }
}

pub(super) struct Job {
    raw: HANDLE,
    pub report: String,
}

impl Job {
    pub(super) fn raw(&self) -> HANDLE {
        self.raw
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        close_handle(self.raw);
        self.raw = ptr::null_mut();
    }
}

pub(super) struct Stage {
    pub root: PathBuf,
    pub outside_root: PathBuf,
    pub exe: PathBuf,
    pub work: PathBuf,
    pub allowed: PathBuf,
    pub denied: PathBuf,
    pub store: PathBuf,
    pub evidence: PathBuf,
    pub outside_file: PathBuf,
    pub drop_dir: PathBuf,
    pub link: PathBuf,
    pub preflight: String,
}

impl Drop for Stage {
    fn drop(&mut self) {
        remove_retry(&self.root);
        remove_retry(&self.outside_root);
    }
}

pub(super) struct Prepared {
    pub stage: Stage,
    pub token: RestrictedToken,
    pub job: Job,
    pub evidence_hex: String,
    pub user_sid: Vec<u8>,
}

pub(super) struct Child {
    pub attempt: String,
    pub assign_error: u32,
    pub in_job: i32,
    pub pid: u32,
    process: HANDLE,
    thread: HANDLE,
    report_read: HANDLE,
    request_write: HANDLE,
    foreign: HANDLE,
    station: HANDLE,
    desktop: HANDLE,
}

impl Drop for Child {
    fn drop(&mut self) {
        unsafe {
            if !self.process.is_null() && WaitForSingleObject(self.process, 0) != WAIT_OBJECT_0 {
                TerminateProcess(self.process, 1);
                WaitForSingleObject(self.process, 2_000);
            }
        }
        close_handle(self.process);
        close_handle(self.thread);
        close_handle(self.report_read);
        close_handle(self.request_write);
        close_handle(self.foreign);
        if !self.desktop.is_null() {
            unsafe { CloseDesktop(self.desktop) };
            self.desktop = ptr::null_mut();
        }
        if !self.station.is_null() {
            unsafe { CloseWindowStation(self.station) };
            self.station = ptr::null_mut();
        }
        self.process = ptr::null_mut();
    }
}

impl Child {
    pub(super) fn peek_contains(&self, marker: &str) -> bool {
        let mut buffer = [0u8; 2048];
        let mut read = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                self.report_read,
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).unwrap_or(0),
                &mut read,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return false;
        }
        let end = usize::try_from(read).unwrap_or(0).min(buffer.len());
        String::from_utf8_lossy(&buffer[..end]).contains(marker)
    }

    pub(super) fn wait_exit(&self, millis: u32) -> u32 {
        unsafe { WaitForSingleObject(self.process, millis) };
        self.exit_code()
    }

    pub(super) fn wait_report(&self, millis: u32) -> (u32, String) {
        let waited = unsafe { WaitForSingleObject(self.process, millis) };
        if waited != WAIT_OBJECT_0 {
            unsafe {
                TerminateProcess(self.process, 1);
                WaitForSingleObject(self.process, 2_000);
            }
        }
        (self.exit_code(), self.read_report())
    }

    fn exit_code(&self) -> u32 {
        let mut code = STILL_ACTIVE;
        unsafe { GetExitCodeProcess(self.process, &mut code) };
        code
    }

    pub(super) fn read_report(&self) -> String {
        let mut out = Vec::new();
        let mut buffer = [0u8; 512];
        loop {
            let mut read = 0u32;
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReadFile(
                    self.report_read,
                    buffer.as_mut_ptr(),
                    u32::try_from(buffer.len()).unwrap_or(0),
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                break;
            }
            let end = usize::try_from(read).unwrap_or(0).min(buffer.len());
            out.extend_from_slice(&buffer[..end]);
            if out.len() > 16_384 {
                break;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

struct Attempt {
    name: &'static str,
    flags: u32,
    empty_desktop: bool,
    private_desktop: bool,
}

pub(super) struct Servers {
    threads: Vec<JoinHandle<()>>,
    ids: Vec<Arc<AtomicU32>>,
}

impl Servers {
    pub(super) fn finish(mut self) {
        for id in &self.ids {
            cancel_thread(id.load(Ordering::SeqCst));
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

pub(super) fn prepare(label: &str) -> Result<Prepared, String> {
    let token = RestrictedToken::create()?;
    let user = current_user_sid().map_err(|code| format!("user sid {code}"))?;
    let users = users_sid().map_err(|code| format!("users sid {code}"))?;
    let system = system_sid().map_err(|code| format!("system sid {code}"))?;
    let mut stage = Stage::build(label, token.raw(), &user, &users, &system)?;
    stage.preflight = format!("{} {}", stage.preflight, token.facts);
    let job = Job::create()?;
    let evidence_hex = broker::hex(&fs::read(&stage.evidence).map_err(|error| error.to_string())?);
    Ok(Prepared {
        stage,
        token,
        job,
        evidence_hex,
        user_sid: user.bytes().to_vec(),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_reaching(
    stage: &Stage,
    token: HANDLE,
    job: HANDLE,
    script: &str,
    pipe: &str,
    worker_id: &str,
    evidence_hex: &str,
    bound: Option<&AtomicU32>,
) -> Result<Child, String> {
    let attempts = [
        Attempt {
            name: "detached",
            flags: DETACHED_PROCESS
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            empty_desktop: false,
            private_desktop: false,
        },
        Attempt {
            name: "private-desktop",
            flags: CREATE_NO_WINDOW
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            empty_desktop: false,
            private_desktop: true,
        },
        Attempt {
            name: "no-window",
            flags: CREATE_NO_WINDOW
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            empty_desktop: false,
            private_desktop: false,
        },
        Attempt {
            name: "empty-desktop",
            flags: CREATE_NO_WINDOW
                | CREATE_SUSPENDED
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            empty_desktop: true,
            private_desktop: false,
        },
    ];
    let mut failures = Vec::new();
    for attempt in attempts {
        match create_suspended(
            stage,
            token,
            job,
            script,
            pipe,
            worker_id,
            evidence_hex,
            &attempt,
        ) {
            Ok(child) => {
                if let Some(slot) = bound {
                    slot.store(child.pid, Ordering::SeqCst);
                }
                if let Err(code) = resume(&child) {
                    failures.push(format!("{} resume={code}", attempt.name));
                    drop(child);
                    continue;
                }
                let started = Instant::now();
                let mut failed: Option<String> = None;
                while started.elapsed() < Duration::from_secs(8) {
                    if child.peek_contains("reached=1") {
                        return Ok(child);
                    }
                    if unsafe { WaitForSingleObject(child.process, 0) } == WAIT_OBJECT_0 {
                        if child.peek_contains("reached=1") {
                            return Ok(child);
                        }
                        let code = child.exit_code();
                        let partial = child.read_report();
                        failed = Some(format!(
                            "{} exit={code:#x} report={}",
                            attempt.name,
                            partial.trim()
                        ));
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                if let Some(reason) = failed {
                    failures.push(reason);
                } else {
                    let code = child.exit_code();
                    failures.push(format!("{} timeout exit={code:#x}", attempt.name));
                }
                drop(child);
            }
            Err(code) => failures.push(format!("{} api={code}", attempt.name)),
        }
    }
    Err(failures.join("; "))
}

pub(super) fn open_code(path: &Path, access: u32) -> u32 {
    open_flags(path, access, FILE_ATTRIBUTE_NORMAL)
}

pub(super) fn fields(report: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for token in report.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            map.insert(key.to_owned(), value.to_owned());
        }
    }
    map
}

pub(super) fn current_pid() -> u32 {
    unsafe { GetCurrentProcessId() }
}

pub(super) fn pipe_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(r"\\.\pipe\lca-01m-{}-{nanos}", unsafe {
        GetCurrentProcessId()
    })
}

pub(super) fn start_servers(
    name: &str,
    broker: Arc<Mutex<Broker>>,
    user: Vec<u8>,
    bound: Arc<AtomicU32>,
) -> Result<Servers, u32> {
    let first = create_server_pipe(name, &user)?;
    let second = create_server_pipe(name, &user)?;
    let mut ids = Vec::new();
    let mut threads = Vec::new();
    for pipe in [first, second] {
        let id = Arc::new(AtomicU32::new(0));
        let thread_id = Arc::clone(&id);
        let broker = Arc::clone(&broker);
        let user = user.clone();
        let bound = Arc::clone(&bound);
        ids.push(id);
        let pipe_bits = pipe as usize;
        threads.push(std::thread::spawn(move || {
            thread_id.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);
            serve_pipe(pipe_bits as HANDLE, broker, &user, &bound);
        }));
    }
    Ok(Servers { threads, ids })
}

pub(super) fn client_exchange(name: &str, messages: &[String]) -> Result<Vec<String>, u32> {
    let mut pipe = INVALID_HANDLE_VALUE;
    for _ in 0..100 {
        pipe = open_client_pipe(name);
        if !invalid(pipe) {
            break;
        }
        let err = unsafe { GetLastError() };
        if err != 231 && err != 2 {
            return Err(err);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if invalid(pipe) {
        return Err(unsafe { GetLastError() });
    }
    let mode = PIPE_READMODE_MESSAGE;
    unsafe { SetNamedPipeHandleState(pipe, &mode, ptr::null(), ptr::null()) };
    let mut labels = Vec::new();
    for message in messages {
        if let Err(code) = write_all(pipe, message.as_bytes()) {
            close_handle(pipe);
            return Err(code);
        }
        match read_pipe(pipe) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                labels.push(broker::decision_label(&text));
                if message.contains("\"request_id\":\"req-read\"") {
                    labels.push(format!("payload={}", broker::payload_of(&text)));
                }
            }
            Err(code) => {
                close_handle(pipe);
                return Err(code);
            }
        }
    }
    close_handle(pipe);
    Ok(labels)
}

pub(super) fn secret_bytes(stage: &Stage) -> Vec<u8> {
    let mut data = Vec::new();
    for path in [
        &stage.denied,
        &stage.store,
        &stage.evidence,
        &stage.outside_file,
    ] {
        data.extend(fs::read(path).unwrap_or_default());
        data.push(0xff);
    }
    data
}

impl RestrictedToken {
    fn create() -> Result<Self, String> {
        let mut source = ptr::null_mut();
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE
                    | TOKEN_QUERY
                    | TOKEN_IMPERSONATE
                    | TOKEN_ASSIGN_PRIMARY
                    | TOKEN_ADJUST_DEFAULT,
                &mut source,
            )
        };
        if opened == 0 {
            return Err(format!("open token {}", unsafe { GetLastError() }));
        }
        let before = info_count(source, TokenPrivileges);
        let users = users_sid().map_err(|code| format!("users {code}"))?;
        let world = world_sid().map_err(|code| format!("world {code}"))?;
        let logon = logon_sid(source);
        let mut restrict = [
            SID_AND_ATTRIBUTES {
                Sid: users.as_ptr(),
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: world.as_ptr(),
                Attributes: 0,
            },
            SID_AND_ATTRIBUTES {
                Sid: logon
                    .as_ref()
                    .map(|sid| sid.as_ptr())
                    .unwrap_or(ptr::null_mut()),
                Attributes: 0,
            },
        ];
        let count = if logon.is_some() { 3 } else { 2 };
        let mut raw = ptr::null_mut();
        let created = unsafe {
            CreateRestrictedToken(
                source,
                DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
                0,
                ptr::null(),
                0,
                ptr::null(),
                count,
                restrict.as_mut_ptr(),
                &mut raw,
            )
        };
        if created == 0 {
            let code = unsafe { GetLastError() };
            close_handle(source);
            return Err(format!("restricted {code}"));
        }
        let facts = format!(
            "{} logon={} privileges_before={before}",
            token_fact_line(raw),
            u8::from(logon.is_some())
        );
        close_handle(source);
        Ok(Self { raw, facts })
    }
}

pub(super) fn token_fact_line(token: HANDLE) -> String {
    let (groups, enabled) = group_counts(token);
    format!(
        "token_type={} integrity={} privileges={} groups={groups} enabled={enabled} restricted={} dacl_aces={}",
        token_u32(token, TokenType),
        integrity_rid(token),
        info_count(token, TokenPrivileges),
        info_count(token, TokenRestrictedSids),
        default_ace_count(token)
    )
}

impl Job {
    pub(super) fn create() -> Result<Self, String> {
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(format!("job {}", unsafe { GetLastError() }));
        }
        let report = apply_limits(raw);
        Ok(Self { raw, report })
    }
}

fn apply_limits(job: HANDLE) -> String {
    let with_memory = set_extended(job, true);
    if with_memory == 0 {
        return format!("limits=0 memory=1 time=1 cpu={}", set_cpu(job));
    }
    let basic = set_extended(job, false);
    format!("limits={basic} memory=0 time=1 cpu={}", set_cpu(job))
}

fn set_extended(job: HANDLE, memory: bool) -> u32 {
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | JOB_OBJECT_LIMIT_PROCESS_TIME;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.BasicLimitInformation.PerProcessUserTimeLimit = 30 * 10_000_000;
    if memory {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = 1024 * 1024 * 1024;
    }
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
        )
    };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn set_cpu(job: HANDLE) -> u32 {
    let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
    info.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
    info.Anonymous.CpuRate = 5_000;
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            (&info as *const JOBOBJECT_CPU_RATE_CONTROL_INFORMATION).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>())
                .unwrap_or(0),
        )
    };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

impl Stage {
    fn build(
        label: &str,
        token: HANDLE,
        user: &OwnedSid,
        users: &OwnedSid,
        system: &OwnedSid,
    ) -> Result<Self, String> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let id = format!("lca-01m-{label}-{}-{nanos}", std::process::id());
        let mut last = String::from("no candidate");
        for parent in candidate_parents() {
            let root = parent.join(&id);
            let outside_root = parent.join(format!("{id}-out"));
            if fs::create_dir_all(&root).is_err() {
                continue;
            }
            grant_users(&root, user, users, system, RX)
                .map_err(|code| format!("root acl {code}"))?;
            let probe = root.join("probe.txt");
            fs::write(&probe, b"probe").map_err(|error| error.to_string())?;
            grant_users(&probe, user, users, system, FILE_GENERIC_READ)
                .map_err(|code| format!("probe acl {code}"))?;
            let ntdll = PathBuf::from(system_root())
                .join("System32")
                .join("ntdll.dll");
            let line = format!(
                "root={} probe={} ntdll={}",
                impersonated_open(
                    token,
                    &root,
                    FILE_LIST_DIRECTORY | FILE_TRAVERSE,
                    FILE_FLAG_BACKUP_SEMANTICS
                ),
                impersonated_open(token, &probe, FILE_GENERIC_READ, FILE_ATTRIBUTE_NORMAL),
                impersonated_open(token, &ntdll, FILE_GENERIC_READ, FILE_ATTRIBUTE_NORMAL)
            );
            if line.contains("root=0") && line.contains("probe=0") && line.contains("ntdll=0") {
                let mut stage = Self::populate(root, outside_root, user, users, system)?;
                let check = stage.measure(token);
                if !check.starts_with("ok ") {
                    remove_retry(&stage.root);
                    remove_retry(&stage.outside_root);
                    last = check;
                    continue;
                }
                return Ok(stage);
            }
            last = line;
            remove_retry(&root);
        }
        Err(last)
    }

    fn populate(
        root: PathBuf,
        outside_root: PathBuf,
        user: &OwnedSid,
        users: &OwnedSid,
        system: &OwnedSid,
    ) -> Result<Self, String> {
        let bin = root.join("bin");
        let work = root.join("work");
        let drop_dir = root.join("drop");
        let store_dir = root.join("store");
        fs::create_dir_all(&bin).map_err(|error| error.to_string())?;
        fs::create_dir_all(&work).map_err(|error| error.to_string())?;
        fs::create_dir_all(&drop_dir).map_err(|error| error.to_string())?;
        fs::create_dir_all(&store_dir).map_err(|error| error.to_string())?;
        fs::create_dir_all(&outside_root).map_err(|error| error.to_string())?;
        let exe = bin.join("worker.exe");
        fs::copy(
            std::env::current_exe().map_err(|error| error.to_string())?,
            &exe,
        )
        .map_err(|error| error.to_string())?;
        let allowed = root.join("allowed.txt");
        let denied = root.join("denied.txt");
        let store = store_dir.join("proposals.bin");
        let evidence = root.join("evidence.bin");
        let outside_file = outside_root.join("secret.txt");
        fs::write(&allowed, b"fixture-bytes").map_err(|error| error.to_string())?;
        fs::write(&denied, b"denied-secret").map_err(|error| error.to_string())?;
        fs::write(&store, b"proposal-store").map_err(|error| error.to_string())?;
        let sealed = crate::protect(b"evidence-secret").map_err(|error| error.to_string())?;
        fs::write(&evidence, sealed).map_err(|error| error.to_string())?;
        fs::write(&outside_file, b"outside-secret").map_err(|error| error.to_string())?;
        grant_users(&bin, user, users, system, RX).map_err(acl_error)?;
        grant_users(&exe, user, users, system, RX).map_err(acl_error)?;
        grant_users(&work, user, users, system, RX).map_err(acl_error)?;
        grant_users(&root, user, users, system, RX).map_err(acl_error)?;
        grant_users(&allowed, user, users, system, FILE_GENERIC_READ).map_err(acl_error)?;
        grant_users(&drop_dir, user, users, system, RWX).map_err(acl_error)?;
        lock_user(&denied, user, system).map_err(acl_error)?;
        lock_user(&store_dir, user, system).map_err(acl_error)?;
        lock_user(&store, user, system).map_err(acl_error)?;
        lock_user(&evidence, user, system).map_err(acl_error)?;
        lock_user(&outside_root, user, system).map_err(acl_error)?;
        lock_user(&outside_file, user, system).map_err(acl_error)?;
        let _ = fs::remove_file(root.join("probe.txt"));
        Ok(Self {
            link: drop_dir.join("link"),
            root,
            outside_root,
            exe,
            work,
            allowed,
            denied,
            store,
            evidence,
            outside_file,
            drop_dir,
            preflight: String::new(),
        })
    }

    fn measure(&mut self, token: HANDLE) -> String {
        let ntdll = PathBuf::from(system_root())
            .join("System32")
            .join("ntdll.dll");
        let exe = impersonated_open(token, &self.exe, RX, FILE_ATTRIBUTE_NORMAL);
        let ntdll_code = impersonated_open(token, &ntdll, FILE_GENERIC_READ, FILE_ATTRIBUTE_NORMAL);
        let allowed = impersonated_open(
            token,
            &self.allowed,
            FILE_GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
        );
        let denied = impersonated_open(
            token,
            &self.denied,
            FILE_GENERIC_READ,
            FILE_ATTRIBUTE_NORMAL,
        );
        let work = impersonated_open(
            token,
            &self.work,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE,
            FILE_FLAG_BACKUP_SEMANTICS,
        );
        let line =
            format!("exe={exe} ntdll={ntdll_code} allowed={allowed} denied={denied} work={work}");
        self.preflight = line.clone();
        if exe == 0 && ntdll_code == 0 && allowed == 0 && work == 0 && denied != 0 {
            format!("ok {line}")
        } else {
            line
        }
    }
}

fn candidate_parents() -> Vec<PathBuf> {
    let mut parents = Vec::new();
    if let Ok(public) = std::env::var("PUBLIC") {
        parents.push(PathBuf::from(public));
    }
    parents.push(PathBuf::from(r"C:\Users\Public"));
    parents.push(PathBuf::from(system_root()).join("Temp"));
    parents
}

#[allow(clippy::too_many_arguments)]
fn create_suspended(
    stage: &Stage,
    token: HANDLE,
    job: HANDLE,
    script: &str,
    pipe: &str,
    worker_id: &str,
    evidence_hex: &str,
    attempt: &Attempt,
) -> Result<Child, u32> {
    let (report_read, report_write) = anon_pipe()?;
    let (request_read, request_write) = anon_pipe()?;
    clear_inherit(report_read);
    clear_inherit(request_write);
    let granted = open_inheritable(&stage.allowed, FILE_GENERIC_READ)?;
    let foreign = open_private(&stage.store, FILE_GENERIC_READ)?;
    let nul_in = open_nul(GENERIC_READ)?;
    let nul_out = open_nul(GENERIC_WRITE)?;
    let nul_err = open_nul(GENERIC_WRITE)?;
    let inherited = [
        report_write,
        request_read,
        granted,
        nul_in,
        nul_out,
        nul_err,
    ];
    let root = system_root();
    let environment = env_block(&[
        ("SystemRoot", &root),
        ("WINDIR", &root),
        ("PATH", &format!("{root}\\System32")),
        ("PATHEXT", ".EXE;.COM"),
        ("TEMP", &stage.drop_dir.display().to_string()),
        ("TMP", &stage.drop_dir.display().to_string()),
        ("LCA_01M_ROLE", "worker"),
        ("LCA_01M_SCRIPT", script),
        ("LCA_01M_ALLOWED", &stage.allowed.display().to_string()),
        ("LCA_01M_DENIED", &stage.denied.display().to_string()),
        ("LCA_01M_STORE", &stage.store.display().to_string()),
        ("LCA_01M_EVIDENCE", &stage.evidence.display().to_string()),
        ("LCA_01M_OUTSIDE", &stage.outside_file.display().to_string()),
        ("LCA_01M_DROP", &stage.drop_dir.display().to_string()),
        ("LCA_01M_LINK", &stage.link.display().to_string()),
        ("LCA_01M_REPORT", &handle_text(report_write)),
        ("LCA_01M_REQUEST", &handle_text(request_read)),
        ("LCA_01M_GRANTED", &handle_text(granted)),
        ("LCA_01M_FOREIGN", &handle_text(foreign)),
        ("LCA_01M_PIPE", pipe),
        ("LCA_01M_WORKER_ID", worker_id),
        ("LCA_01M_EVIDENCE_HEX", evidence_hex),
        ("LCA_01M_NONCE", &format!("{}", std::process::id())),
    ]);
    let app = wide_path(&stage.exe);
    let mut command = command_line(&stage.exe);
    let cwd = wide_path(&stage.work);
    let mut desktop = [0u16];
    let mut list = AttributeList::new(&inherited)?;
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(0);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = nul_in;
    startup.StartupInfo.hStdOutput = nul_out;
    startup.StartupInfo.hStdError = nul_err;
    let mut private = if attempt.private_desktop {
        match open_private_ui(token) {
            Ok(ui) => Some(ui),
            Err(code) => {
                list.delete();
                close_handle(report_write);
                close_handle(request_read);
                close_handle(granted);
                close_handle(nul_in);
                close_handle(nul_out);
                close_handle(nul_err);
                close_handle(report_read);
                close_handle(request_write);
                close_handle(foreign);
                return Err(code);
            }
        }
    } else {
        None
    };
    if attempt.empty_desktop {
        startup.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    }
    if let Some(ui) = private.as_mut() {
        startup.StartupInfo.lpDesktop = ui.name.as_mut_ptr();
    }
    startup.lpAttributeList = list.as_ptr();
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            token,
            app.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            attempt.flags,
            environment.as_ptr().cast(),
            cwd.as_ptr(),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut process,
        )
    };
    list.delete();
    close_handle(report_write);
    close_handle(request_read);
    close_handle(granted);
    close_handle(nul_in);
    close_handle(nul_out);
    close_handle(nul_err);
    if ok == 0 {
        let code = unsafe { GetLastError() };
        close_handle(report_read);
        close_handle(request_write);
        close_handle(foreign);
        drop(private);
        return Err(code);
    }
    let assign = unsafe { AssignProcessToJobObject(job, process.hProcess) };
    let assign_error = if assign == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let mut in_job = 0i32;
    unsafe { IsProcessInJob(process.hProcess, job, &mut in_job) };
    let (station, desktop_handle) = private
        .as_mut()
        .map(PrivateUi::take_handles)
        .unwrap_or((ptr::null_mut(), ptr::null_mut()));
    Ok(Child {
        attempt: attempt.name.to_owned(),
        assign_error,
        in_job,
        pid: process.dwProcessId,
        process: process.hProcess,
        thread: process.hThread,
        report_read,
        request_write,
        foreign,
        station,
        desktop: desktop_handle,
    })
}

fn resume(child: &Child) -> Result<(), u32> {
    let previous = unsafe { ResumeThread(child.thread) };
    if previous == u32::MAX {
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

struct PrivateUi {
    station: HANDLE,
    desktop: HANDLE,
    name: Vec<u16>,
}

impl PrivateUi {
    fn take_handles(&mut self) -> (HANDLE, HANDLE) {
        let handles = (self.station, self.desktop);
        self.station = ptr::null_mut();
        self.desktop = ptr::null_mut();
        handles
    }
}

impl Drop for PrivateUi {
    fn drop(&mut self) {
        unsafe {
            if !self.desktop.is_null() {
                CloseDesktop(self.desktop);
            }
            if !self.station.is_null() {
                CloseWindowStation(self.station);
            }
        }
    }
}

struct RestoreStation(HANDLE);

impl Drop for RestoreStation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { SetProcessWindowStation(self.0) };
        }
    }
}

fn station_lock() -> &'static Mutex<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    &LOCK
}

fn open_private_ui(token: HANDLE) -> Result<PrivateUi, u32> {
    let _lock = station_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let user = current_user_sid()?;
    let users = users_sid()?;
    let system = system_sid()?;
    let world = world_sid()?;
    let logon = logon_sid(token);
    let station_name = format!(
        "lca{}{}",
        unsafe { GetCurrentProcessId() },
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.subsec_nanos() % 100_000)
            .unwrap_or(0)
    );
    let mut station_acl = ui_acl(
        &[&user, &users, &system, &world],
        logon.as_ref(),
        0x000F_037F,
    )?;
    let mut desktop_acl = ui_acl(
        &[&user, &users, &system, &world],
        logon.as_ref(),
        0x000F_01FF,
    )?;
    let station_wide = wide(&station_name);
    let station_sa = station_acl.attributes();
    let station =
        unsafe { CreateWindowStationW(station_wide.as_ptr(), 0, 0x000F_037F, &station_sa) };
    if station.is_null() {
        return Err(unsafe { GetLastError() });
    }
    let previous = unsafe { GetProcessWindowStation() };
    if unsafe { SetProcessWindowStation(station) } == 0 {
        let code = unsafe { GetLastError() };
        unsafe { CloseWindowStation(station) };
        return Err(code);
    }
    let restore = RestoreStation(previous);
    let desktop_wide = wide("Default");
    let desktop_sa = desktop_acl.attributes();
    let desktop = unsafe {
        CreateDesktopW(
            desktop_wide.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            0x000F_01FF,
            &desktop_sa,
        )
    };
    drop(restore);
    if desktop.is_null() {
        let code = unsafe { GetLastError() };
        unsafe { CloseWindowStation(station) };
        return Err(code);
    }
    Ok(PrivateUi {
        station,
        desktop,
        name: wide(&format!("{station_name}\\Default")),
    })
}

struct UiAcl {
    descriptor: SECURITY_DESCRIPTOR,
    dacl: *mut std::ffi::c_void,
}

impl Drop for UiAcl {
    fn drop(&mut self) {
        if !self.dacl.is_null() {
            unsafe { LocalFree(self.dacl.cast()) };
            self.dacl = ptr::null_mut();
        }
    }
}

impl UiAcl {
    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        }
    }
}

fn ui_acl(sids: &[&OwnedSid], logon: Option<&OwnedSid>, access: u32) -> Result<UiAcl, u32> {
    let mut entries = Vec::new();
    for sid in sids {
        entries.push(ace(sid.as_ptr(), access));
    }
    if let Some(sid) = logon {
        entries.push(ace(sid.as_ptr(), access));
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
    Ok(UiAcl { descriptor, dacl })
}

#[link(name = "user32")]
unsafe extern "system" {
    fn CreateWindowStationW(
        name: *const u16,
        flags: u32,
        access: u32,
        security: *const SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    fn CreateDesktopW(
        name: *const u16,
        device: *const u16,
        devmode: *const u8,
        flags: u32,
        access: u32,
        security: *const SECURITY_ATTRIBUTES,
    ) -> HANDLE;
    fn CloseWindowStation(station: HANDLE) -> i32;
    fn CloseDesktop(desktop: HANDLE) -> i32;
    fn GetProcessWindowStation() -> HANDLE;
    fn SetProcessWindowStation(station: HANDLE) -> i32;
}

struct AttributeList {
    buffer: Vec<u8>,
}

impl AttributeList {
    fn new(handles: &[HANDLE]) -> Result<Self, u32> {
        let mut bytes = 0usize;
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes) };
        let mut buffer = vec![0u8; bytes];
        let ok = unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut bytes)
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        let updated = unsafe {
            UpdateProcThreadAttribute(
                buffer.as_mut_ptr().cast(),
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_HANDLE_LIST).unwrap_or(0),
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if updated == 0 {
            unsafe { DeleteProcThreadAttributeList(buffer.as_mut_ptr().cast()) };
            return Err(unsafe { GetLastError() });
        }
        Ok(Self { buffer })
    }

    fn as_ptr(&mut self) -> *mut std::ffi::c_void {
        self.buffer.as_mut_ptr().cast()
    }

    fn delete(&mut self) {
        unsafe { DeleteProcThreadAttributeList(self.buffer.as_mut_ptr().cast()) };
    }
}

fn serve_pipe(pipe: HANDLE, broker: Arc<Mutex<Broker>>, user: &[u8], bound: &AtomicU32) {
    if !connect_server(pipe) {
        close_handle(pipe);
        return;
    }
    loop {
        let message = match read_pipe(pipe) {
            Ok(message) => message,
            Err(code) if code == ERROR_MORE_DATA => vec![0u8; 2048],
            Err(_) => break,
        };
        let peer = peer_from_pipe(pipe, user, bound);
        let text = String::from_utf8_lossy(&message);
        let response = broker
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .decide(&text, &peer, broker::now_ms());
        if write_all(pipe, response.as_bytes()).is_err() {
            break;
        }
    }
    unsafe { DisconnectNamedPipe(pipe) };
    close_handle(pipe);
}

fn peer_from_pipe(pipe: HANDLE, user: &[u8], bound: &AtomicU32) -> Peer {
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    let mut peer = Peer {
        pid,
        bound_pid: bound.load(Ordering::SeqCst),
        same_user: false,
        restricted_sids: 0,
        impersonation_rejects: false,
    };
    if let Some((same, restricted)) = process_token(pid, user) {
        peer.same_user = same;
        peer.restricted_sids = restricted;
    }
    if let Ok((same, _)) = impersonated_token(pipe, user)
        && !same
    {
        peer.impersonation_rejects = true;
    }
    peer
}

fn process_token(pid: u32, user: &[u8]) -> Option<(bool, u32)> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    close_handle(process);
    if opened == 0 {
        return None;
    }
    let same = token_matches_user(token, user);
    let restricted = info_count(token, TokenRestrictedSids);
    close_handle(token);
    Some((same, restricted))
}

fn impersonated_token(pipe: HANDLE, user: &[u8]) -> Result<(bool, u32), u32> {
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    let _revert = RevertGuard;
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 0, &mut token) };
    if opened == 0 {
        return Err(unsafe { GetLastError() });
    }
    let same = token_matches_user(token, user);
    let restricted = info_count(token, TokenRestrictedSids);
    close_handle(token);
    Ok((same, restricted))
}

struct RevertGuard;

impl Drop for RevertGuard {
    fn drop(&mut self) {
        unsafe { RevertToSelf() };
    }
}

fn connect_server(pipe: HANDLE) -> bool {
    let ok = unsafe { ConnectNamedPipe(pipe, ptr::null_mut()) };
    ok != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED
}

fn create_server_pipe(name: &str, user: &[u8]) -> Result<HANDLE, u32> {
    let users = users_sid()?;
    let system = system_sid()?;
    let user_sid = sid_from_bytes(user)?;
    let mut entries = [
        ace(user_sid.as_ptr(), GENERIC_ALL),
        ace(system.as_ptr(), GENERIC_ALL),
        ace(users.as_ptr(), FILE_GENERIC_READ | FILE_GENERIC_WRITE),
    ];
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
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            4,
            4096,
            4096,
            0,
            &security,
        )
    };
    unsafe { LocalFree(dacl.cast()) };
    if invalid(handle) {
        Err(unsafe { GetLastError() })
    } else {
        Ok(handle)
    }
}

fn open_client_pipe(name: &str) -> HANDLE {
    let wide_name = wide(name);
    unsafe {
        CreateFileW(
            wide_name.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            ptr::null(),
            3,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    }
}

fn read_pipe(pipe: HANDLE) -> Result<Vec<u8>, u32> {
    let mut buffer = vec![0u8; 2048];
    let mut read = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            pipe,
            buffer.as_mut_ptr(),
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
    let end = usize::try_from(read).unwrap_or(0).min(buffer.len());
    buffer.truncate(end);
    Ok(buffer)
}

fn write_all(pipe: HANDLE, bytes: &[u8]) -> Result<(), u32> {
    let mut written = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            pipe,
            bytes.as_ptr(),
            u32::try_from(bytes.len()).unwrap_or(u32::MAX),
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

fn anon_pipe() -> Result<(HANDLE, HANDLE), u32> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let ok = unsafe {
        windows_sys::Win32::System::Pipes::CreatePipe(&mut read, &mut write, &security, 0)
    };
    if ok == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok((read, write))
    }
}

fn open_inheritable(path: &Path, access: u32) -> Result<HANDLE, u32> {
    let name = wide_path(path);
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            SHARE,
            &security,
            3,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if invalid(handle) {
        Err(unsafe { GetLastError() })
    } else {
        Ok(handle)
    }
}

fn open_private(path: &Path, access: u32) -> Result<HANDLE, u32> {
    let handle = open_raw(path, access, FILE_ATTRIBUTE_NORMAL, false)?;
    clear_inherit(handle);
    Ok(handle)
}

fn open_nul(access: u32) -> Result<HANDLE, u32> {
    let name = wide(r"\\.\NUL");
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            SHARE,
            &security,
            3,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if invalid(handle) {
        Err(unsafe { GetLastError() })
    } else {
        Ok(handle)
    }
}

fn open_raw(path: &Path, access: u32, flags: u32, inherit: bool) -> Result<HANDLE, u32> {
    let name = wide_path(path);
    let mut security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: i32::from(inherit),
    };
    let sa = if inherit {
        &mut security as *mut _
    } else {
        ptr::null_mut()
    };
    let handle =
        unsafe { CreateFileW(name.as_ptr(), access, SHARE, sa, 3, flags, ptr::null_mut()) };
    if invalid(handle) {
        Err(unsafe { GetLastError() })
    } else {
        Ok(handle)
    }
}

fn open_flags(path: &Path, access: u32, flags: u32) -> u32 {
    match open_raw(path, access, flags, false) {
        Ok(handle) => {
            close_handle(handle);
            0
        }
        Err(code) => code,
    }
}

fn impersonated_open(token: HANDLE, path: &Path, access: u32, flags: u32) -> u32 {
    if unsafe { ImpersonateLoggedOnUser(token) } == 0 {
        return unsafe { GetLastError() };
    }
    let _guard = RevertGuard;
    open_flags(path, access, flags)
}

fn clear_inherit(handle: HANDLE) {
    unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
}

fn env_block(pairs: &[(&str, &str)]) -> Vec<u16> {
    let mut block = String::new();
    for (key, value) in pairs {
        if key.contains('\0') || value.contains('\0') {
            continue;
        }
        block.push_str(key);
        block.push('=');
        block.push_str(value);
        block.push('\0');
    }
    block.push('\0');
    block.encode_utf16().collect()
}

fn command_line(exe: &Path) -> Vec<u16> {
    let mut out = Vec::new();
    out.push(u16::from(b'"'));
    out.extend(OsStr::new(exe).encode_wide());
    out.push(u16::from(b'"'));
    out.extend(" principal_probe::principal_probe_child --exact".encode_utf16());
    out.push(0);
    out
}

fn handle_text(handle: HANDLE) -> String {
    (handle as usize).to_string()
}

pub(super) fn handle_from(text: &str) -> HANDLE {
    text.parse::<usize>().unwrap_or(0) as HANDLE
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned())
}

fn grant_users(
    path: &Path,
    user: &OwnedSid,
    users: &OwnedSid,
    system: &OwnedSid,
    users_access: u32,
) -> Result<(), u32> {
    let mut entries = [
        ace(user.as_ptr(), GENERIC_ALL),
        ace(system.as_ptr(), GENERIC_ALL),
        ace(users.as_ptr(), users_access),
    ];
    apply_dacl(path, &mut entries)
}

fn lock_user(path: &Path, user: &OwnedSid, system: &OwnedSid) -> Result<(), u32> {
    let mut entries = [
        ace(user.as_ptr(), GENERIC_ALL),
        ace(system.as_ptr(), GENERIC_ALL),
    ];
    apply_dacl(path, &mut entries)
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

fn build_dacl(entries: &mut [EXPLICIT_ACCESS_W]) -> Result<*mut std::ffi::c_void, u32> {
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

fn ace(sid: *mut std::ffi::c_void, access: u32) -> EXPLICIT_ACCESS_W {
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

fn current_user_sid() -> Result<OwnedSid, u32> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    let buffer = token_buffer(token, TokenUser);
    close_handle(token);
    if buffer.len() < std::mem::size_of::<TOKEN_USER>() {
        return Err(1);
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    copy_sid(user.User.Sid)
}

fn users_sid() -> Result<OwnedSid, u32> {
    allocate_sid(&[0, 0, 0, 0, 0, 5], &[32, 545])
}

fn world_sid() -> Result<OwnedSid, u32> {
    allocate_sid(&[0, 0, 0, 0, 0, 1], &[0])
}

fn system_sid() -> Result<OwnedSid, u32> {
    allocate_sid(&[0, 0, 0, 0, 0, 5], &[18])
}

fn sid_from_bytes(bytes: &[u8]) -> Result<OwnedSid, u32> {
    if bytes.is_empty() {
        return Err(1);
    }
    Ok(OwnedSid(bytes.to_vec()))
}

fn logon_sid(token: HANDLE) -> Option<OwnedSid> {
    if let Some(sid) = logon_from_groups(token) {
        return Some(sid);
    }
    let buffer = token_buffer(token, 28);
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        return None;
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    if groups.GroupCount == 0 || groups.Groups[0].Sid.is_null() {
        return None;
    }
    copy_sid(groups.Groups[0].Sid).ok()
}

fn logon_from_groups(token: HANDLE) -> Option<OwnedSid> {
    let buffer = token_buffer(token, TokenGroups);
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        return None;
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let base = std::ptr::addr_of!(groups.Groups[0]);
    for index in 0..groups.GroupCount {
        let entry = unsafe { &*base.add(usize::try_from(index).unwrap_or(0)) };
        if entry.Attributes & 0xC000_0000 == 0xC000_0000 && !entry.Sid.is_null() {
            return copy_sid(entry.Sid).ok();
        }
    }
    None
}

fn copy_sid(sid: *mut std::ffi::c_void) -> Result<OwnedSid, u32> {
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
    for (index, value) in subs.iter().enumerate() {
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

fn token_matches_user(token: HANDLE, user: &[u8]) -> bool {
    let buffer = token_buffer(token, TokenUser);
    if buffer.len() < std::mem::size_of::<TOKEN_USER>() || user.is_empty() {
        return false;
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    unsafe { EqualSid(token_user.User.Sid, user.as_ptr().cast_mut().cast()) != 0 }
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

fn group_counts(token: HANDLE) -> (u32, u32) {
    let buffer = token_buffer(token, TokenGroups);
    if buffer.len() < std::mem::size_of::<TOKEN_GROUPS>() {
        return (0, 0);
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    let mut enabled = 0u32;
    let base = std::ptr::addr_of!(groups.Groups[0]);
    for index in 0..groups.GroupCount {
        let entry = unsafe { &*base.add(usize::try_from(index).unwrap_or(0)) };
        if entry.Attributes & 0x4 != 0 {
            enabled += 1;
        }
    }
    (groups.GroupCount, enabled)
}

fn default_ace_count(token: HANDLE) -> u32 {
    let buffer = token_buffer(token, TokenDefaultDacl);
    if buffer.len() < std::mem::size_of::<windows_sys::Win32::Security::TOKEN_DEFAULT_DACL>() {
        return 0;
    }
    let dacl = unsafe {
        &*buffer
            .as_ptr()
            .cast::<windows_sys::Win32::Security::TOKEN_DEFAULT_DACL>()
    };
    if dacl.DefaultDacl.is_null() {
        0
    } else {
        u32::from(unsafe { (*dacl.DefaultDacl).AceCount })
    }
}

fn info_count(token: HANDLE, class: i32) -> u32 {
    let buffer = token_buffer(token, class);
    if buffer.len() < 4 {
        0
    } else {
        u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
    }
}

fn token_u32(token: HANDLE, class: i32) -> u32 {
    info_count(token, class)
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

fn invalid(handle: HANDLE) -> bool {
    handle.is_null() || handle == INVALID_HANDLE_VALUE
}

fn close_handle(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
}

fn cancel_thread(id: u32) {
    if id == 0 {
        return;
    }
    let thread = unsafe { OpenThread(THREAD_TERMINATE, 0, id) };
    if thread.is_null() {
        return;
    }
    unsafe {
        CancelSynchronousIo(thread);
        CloseHandle(thread);
    }
}

fn acl_error(code: u32) -> String {
    format!("acl {code}")
}

fn remove_retry(path: &Path) {
    for _ in 0..20 {
        if fs::remove_dir_all(path).is_ok() || !path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
