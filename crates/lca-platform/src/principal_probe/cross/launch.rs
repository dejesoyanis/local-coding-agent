//! Separate-principal launch. Credentials stay in a zeroed buffer and are passed
//! only as a `CreateProcessWithLogonW` argument. They are not placed on the command
//! line, in the environment, or in the report.

#![allow(unsafe_code)]
#![allow(clippy::too_many_lines)]

use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_LIST_DIRECTORY, FILE_SHARE_READ, FILE_TRAVERSE, MoveFileW,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithLogonW, GetCurrentThreadId,
    GetExitCodeProcess, LOGON_WITH_PROFILE, OpenThread, PROCESS_INFORMATION, STARTUPINFOW,
    THREAD_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use super::broker::{self, Broker};
use super::contract::{self, Gate, Password};
use super::host::{self, Secret};

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const CREATE_ALWAYS: u32 = 2;
const STILL_ACTIVE: u32 = 259;
const RX: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | FILE_LIST_DIRECTORY | FILE_TRAVERSE;

pub(super) struct Outcome {
    pub report: String,
    pub gate: Gate,
    pub worker_started: bool,
}

pub(super) fn run_mode_b() -> Outcome {
    let Some(account) = account_name() else {
        return stopped("account_not_configured", 0, false);
    };
    if !contract::valid_account(&account) {
        return stopped("account_invalid", 0, false);
    }
    let broker_sid = match host::current_principal() {
        Ok(snapshot) => snapshot.user_sid.as_str().to_owned(),
        Err(code) => return stopped("broker_token", code, false),
    };
    let worker_sid = match host::lookup_account(&account) {
        Ok(sid) => sid,
        Err(code) => {
            let reason = if code == 1332 {
                "account_not_found"
            } else {
                "account_lookup"
            };
            return stopped(reason, code, false);
        }
    };
    if worker_sid == broker_sid {
        return stopped("same_principal", 0, false);
    }
    let password = match host::read_secret(&account) {
        Secret::Present(password) => password,
        Secret::Absent(code) => return stopped("credential_missing", code, false),
        Secret::Empty => return stopped("credential_empty", 0, false),
        Secret::Mismatch => return stopped("credential_user_mismatch", 0, false),
    };
    let outcome = match launch(&account, &password, &broker_sid, &worker_sid) {
        Ok(outcome) => outcome,
        Err(failure) => stopped(failure.step, failure.code, true),
    };
    drop(password);
    outcome
}

pub(super) fn worker_main() -> i32 {
    let report_path = std::env::var("LCA_01N_REPORT").unwrap_or_default();
    if report_path.is_empty() {
        return 2;
    }
    let mut lines = Vec::new();
    lines.push("reached=1".to_owned());
    let snapshot = host::current_principal();
    match &snapshot {
        Ok(snapshot) => lines.push(format!("user_sid={}", snapshot.user_sid.as_str())),
        Err(code) => lines.push(format!("user_sid_error={code}")),
    }
    for (key, label) in [
        ("LCA_01N_STORE", "store"),
        ("LCA_01N_EVIDENCE", "evidence"),
        ("LCA_01N_RESTORATION", "restoration"),
        ("LCA_01N_FORBIDDEN", "forbidden"),
        ("LCA_01N_HOST", "host"),
        ("LCA_01N_ALLOWED", "allowed_direct"),
    ] {
        let path = std::env::var(key).unwrap_or_default();
        if path.is_empty() {
            lines.push("missing_env=1".to_owned());
            break;
        }
        let file = PathBuf::from(&path);
        lines.push(format!(
            "{label}_read={}",
            open_code(&file, GENERIC_READ, OPEN_EXISTING)
        ));
        lines.push(format!(
            "{label}_write={}",
            open_code(&file, GENERIC_WRITE, OPEN_EXISTING)
        ));
    }
    let link = std::env::var("LCA_01N_LINK").unwrap_or_default();
    let store = std::env::var("LCA_01N_STORE").unwrap_or_default();
    lines.push(format!(
        "hardlink={}",
        hardlink_code(Path::new(&link), Path::new(&store))
    ));
    let drop_dir = std::env::var("LCA_01N_DROP").unwrap_or_default();
    let renamed = PathBuf::from(&drop_dir).join("stolen.bin");
    lines.push(format!(
        "rename={}",
        rename_code(Path::new(&store), &renamed)
    ));
    let note = PathBuf::from(&drop_dir).join("note.txt");
    lines.push(format!(
        "drop_write={}",
        open_code(&note, GENERIC_WRITE, CREATE_ALWAYS)
    ));
    let (ipc, pipe) = ipc_exchange();
    lines.push(ipc);
    lines.push("holding=1".to_owned());
    let body = lines.join("\n");
    let _ = fs::write(&report_path, &body);
    if let Some(handle) = pipe {
        let _ = host::read_frame(handle);
        host::close(handle);
        let _ = fs::write(&report_path, format!("{body}\nwait_returned=1\n"));
    }
    0
}

fn launch(
    account: &str,
    password: &Password,
    broker_sid: &str,
    worker_sid: &str,
) -> Result<Outcome, contract::OsFailure> {
    let logon = host::logon(account, password).map_err(|code| contract::OsFailure {
        step: "logon",
        code,
    })?;
    let logged = host::snapshot_token(logon).map_err(|code| {
        host::close(logon);
        contract::OsFailure {
            step: "logon_token",
            code,
        }
    })?;
    host::close(logon);
    if logged.user_sid.as_str() != worker_sid || logged.user_sid.as_str() == broker_sid {
        return Ok(stopped("logon_sid", 0, true));
    }
    if host::privileged_snapshot(&logged) {
        return Ok(stopped("privileged_principal", 0, true));
    }
    let root = std::env::temp_dir().join(format!(
        "lca-01n-run-{}-{}",
        std::process::id(),
        host::unix_ms()
    ));
    let stage = prepare_tree(&root, account).map_err(|code| contract::OsFailure {
        step: "stage",
        code,
    })?;
    let session = format!("s-{}-{}", std::process::id(), host::unix_ms());
    let endpoint = host::pipe_name("worker");
    let spec = contract::LaunchSpec {
        account: account.to_owned(),
        executable: stage.executable.clone(),
        working_directory: stage.drop_dir.clone(),
        handles: Vec::new(),
        inherit_unlisted: false,
        endpoint: endpoint.clone(),
        timeout_ms: 20_000,
    };
    if contract::validate_launch(&spec, &stage.executable).is_err() {
        let _ = fs::remove_dir_all(&root);
        return Ok(stopped("launch_contract", 0, false));
    }
    let issued = host::unix_ms();
    let expires = issued.saturating_add(25_000);
    let command = contract::worker_command_line(&stage.executable);
    if String::from_utf16_lossy(&command)
        .to_ascii_lowercase()
        .contains("password")
    {
        let _ = fs::remove_dir_all(&root);
        return Ok(stopped("command_line", 0, false));
    }
    let environment = contract::worker_environment(&[
        ("LCA_01N_ROLE", "worker"),
        ("LCA_01N_REPORT", &stage.report.to_string_lossy()),
        ("LCA_01N_STORE", &stage.store.to_string_lossy()),
        ("LCA_01N_EVIDENCE", &stage.evidence.to_string_lossy()),
        ("LCA_01N_RESTORATION", &stage.restoration.to_string_lossy()),
        ("LCA_01N_FORBIDDEN", &stage.forbidden.to_string_lossy()),
        ("LCA_01N_HOST", &stage.host_file.to_string_lossy()),
        ("LCA_01N_ALLOWED", &stage.allowed.to_string_lossy()),
        ("LCA_01N_LINK", &stage.link.to_string_lossy()),
        ("LCA_01N_DROP", &stage.drop_dir.to_string_lossy()),
        ("LCA_01N_PIPE", &endpoint),
        ("LCA_01N_SESSION", &session),
        ("LCA_01N_ISSUED", &issued.to_string()),
        ("LCA_01N_EXPIRES", &expires.to_string()),
        ("SystemRoot", &system_root()),
        ("PATH", &format!("{}\\System32", system_root())),
        ("TEMP", &stage.drop_dir.to_string_lossy()),
        ("TMP", &stage.drop_dir.to_string_lossy()),
    ])
    .map_err(|_| contract::OsFailure {
        step: "environment",
        code: 1,
    })?;
    let pipe = host::create_worker_pipe(&endpoint, worker_sid)
        .map_err(|code| contract::OsFailure { step: "pipe", code })?;
    let shared = Arc::new(Shared {
        ready: AtomicBool::new(false),
        failed: AtomicBool::new(false),
        broker: Mutex::new(Broker::new(broker_sid, b"fixture-bytes".to_vec())),
        pipe_instance: 1,
    });
    let thread_id = Arc::new(AtomicU32::new(0));
    let server_shared = Arc::clone(&shared);
    let server_thread = Arc::clone(&thread_id);
    let pipe_bits = pipe as usize;
    let server = std::thread::spawn(move || {
        let pipe = pipe_bits as HANDLE;
        serve(pipe, server_shared, server_thread);
    });
    let created = create_worker(account, password, &stage, &command, &environment);
    let child = match created {
        Ok(child) => child,
        Err(failure) => {
            shared.failed.store(true, Ordering::Relaxed);
            cancel_server(&thread_id);
            let _ = server.join();
            let _ = fs::remove_dir_all(&root);
            return Err(failure);
        }
    };
    let process_token = match host::open_process_token(child.process) {
        Ok(token) => token,
        Err(code) => {
            shared.failed.store(true, Ordering::Relaxed);
            drop(child);
            let _ = server.join();
            let _ = fs::remove_dir_all(&root);
            return Ok(started_failure("process_token", code));
        }
    };
    let process_snapshot = match host::snapshot_token(process_token) {
        Ok(snapshot) => snapshot,
        Err(code) => {
            host::close(process_token);
            shared.failed.store(true, Ordering::Relaxed);
            drop(child);
            let _ = server.join();
            let _ = fs::remove_dir_all(&root);
            return Ok(started_failure("process_token", code));
        }
    };
    host::close(process_token);
    if process_snapshot.user_sid.as_str() == broker_sid
        || process_snapshot.user_sid.as_str() != worker_sid
        || host::privileged_snapshot(&process_snapshot)
    {
        shared.failed.store(true, Ordering::Relaxed);
        drop(child);
        let _ = server.join();
        let _ = fs::remove_dir_all(&root);
        return Ok(started_failure("process_sid", 0));
    }
    let bound = broker::ObservedPeer {
        pid: child.pid,
        user_sid: process_snapshot.user_sid.as_str().to_owned(),
        logon_low: process_snapshot.authentication_id.low,
        logon_high: process_snapshot.authentication_id.high,
        pipe_instance: 1,
        impersonation_sid: process_snapshot.user_sid.as_str().to_owned(),
        impersonation_ok: true,
    };
    if shared
        .broker
        .lock()
        .expect("broker")
        .open_session(bound, &session)
        .is_err()
    {
        shared.failed.store(true, Ordering::Relaxed);
        drop(child);
        let _ = server.join();
        let _ = fs::remove_dir_all(&root);
        return Ok(started_failure("session", 0));
    }
    let job_assigned = child.assign_job();
    shared.ready.store(true, Ordering::Relaxed);
    let report = wait_report(&stage.report, Duration::from_secs(20));
    let pid = child.pid;
    let (exit_code, killed_running) = child.finish();
    let _ = server.join();
    let text = report.unwrap_or_default();
    let outcome = judge(
        &text,
        &process_snapshot,
        broker_sid,
        pid,
        exit_code,
        killed_running,
        job_assigned,
        &shared,
    );
    let _ = fs::remove_dir_all(&root);
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn judge(
    report: &str,
    snapshot: &contract::PrincipalSnapshot,
    broker_sid: &str,
    pid: u32,
    exit_code: u32,
    killed_running: bool,
    job_assigned: bool,
    shared: &Shared,
) -> Outcome {
    if report.is_empty() || report.contains("missing_env=1") || !report.contains("holding=1") {
        return started_failure("no_report", exit_code);
    }
    if report.contains("wait_returned=1") || exit_code == STILL_ACTIVE {
        return started_failure("containment", exit_code);
    }
    let mut worker = snapshot.clone();
    worker.verification = contract::Verification::AccessChecked;
    let mut evidence = contract::unknown_evidence();
    evidence.store_readable = opened(report, "store_read");
    evidence.store_writable = opened(report, "store_write");
    evidence.evidence_readable = opened(report, "evidence_read");
    evidence.evidence_writable = opened(report, "evidence_write");
    evidence.restoration_readable = opened(report, "restoration_read");
    evidence.restoration_writable = opened(report, "restoration_write");
    evidence.host_readable = any_opened(
        report,
        &["host_read", "forbidden_read", "allowed_direct_read"],
    );
    evidence.host_writable = any_opened(
        report,
        &["host_write", "forbidden_write", "allowed_direct_write"],
    );
    evidence.registered_only = Some(report.contains("decisions=allow,allow,allow,deny:capability"));
    evidence.path_authorized = if report.contains("deny:resource") {
        Some(false)
    } else {
        None
    };
    evidence.implicit_handles = Some(false);
    evidence.abort_contained = if killed_running {
        Some(exit_code != STILL_ACTIVE)
    } else {
        None
    };
    evidence.worker_minted = Some(false);
    evidence.boundary_claimed = false;
    let broker = contract::sample_principal(broker_sid, contract::Verification::TokenObserved);
    let findings = contract::evaluate(&broker, &worker, &evidence);
    let hardlink_created = field(report, "hardlink") == Some("0");
    let rename_created = field(report, "rename") == Some("0");
    let audit = shared.broker.lock().expect("broker").audit().to_vec();
    let authenticated = audit
        .iter()
        .any(|line| line.starts_with(&format!("pid={pid} ")) && line.contains("decision=allow"));
    let mut gate = contract::decide_gate(true, &findings);
    if hardlink_created
        || rename_created
        || !authenticated
        || !report.contains("deny:resource")
        || !report.contains("deny:replay")
        || !report.contains("deny:schema")
    {
        gate = Gate::Partial;
    }
    let label = match gate {
        Gate::Validated => "A",
        Gate::Partial => "B",
        Gate::NotEstablished => "C",
    };
    let store_open = evidence.store_readable == Some(true) || evidence.store_writable == Some(true);
    let evidence_open =
        evidence.evidence_readable == Some(true) || evidence.evidence_writable == Some(true);
    let restoration_open =
        evidence.restoration_readable == Some(true) || evidence.restoration_writable == Some(true);
    let host_open = evidence.host_readable == Some(true) || evidence.host_writable == Some(true);
    Outcome {
        worker_started: true,
        gate,
        report: format!(
            "gate={label} worker_started=1 account_created=0 logon_attempted=1 job_assigned={} killed_running={} exit={exit_code:#x} store_read_denied={} evidence_denied={} restoration_denied={} host_denied={} hardlink_created={} broker_authenticated={} inherit_unlisted=0\n{report}\naudit:\n{}",
            u8::from(job_assigned),
            u8::from(killed_running),
            u8::from(!store_open && evidence.store_readable == Some(false)),
            u8::from(!evidence_open),
            u8::from(!restoration_open),
            u8::from(!host_open),
            u8::from(hardlink_created),
            u8::from(authenticated),
            audit.join("\n")
        ),
    }
}

fn opened(report: &str, key: &str) -> Option<bool> {
    let value = field(report, key)?;
    let code: u32 = value.parse().ok()?;
    Some(code == 0)
}

fn any_opened(report: &str, keys: &[&str]) -> Option<bool> {
    let mut opened_any = false;
    for key in keys {
        match opened(report, key) {
            Some(true) => opened_any = true,
            Some(false) => {}
            None => return None,
        }
    }
    Some(opened_any)
}

fn field<'a>(report: &'a str, key: &str) -> Option<&'a str> {
    report
        .lines()
        .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))
}

struct Shared {
    ready: AtomicBool,
    failed: AtomicBool,
    broker: Mutex<Broker>,
    pipe_instance: u64,
}

fn serve(pipe: HANDLE, shared: Arc<Shared>, thread_id: Arc<AtomicU32>) {
    thread_id.store(unsafe { GetCurrentThreadId() }, Ordering::Relaxed);
    if !host::connect_pipe(pipe) || shared.failed.load(Ordering::Relaxed) {
        host::close(pipe);
        return;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while !shared.ready.load(Ordering::Relaxed)
        && !shared.failed.load(Ordering::Relaxed)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !shared.ready.load(Ordering::Relaxed) {
        host::close(pipe);
        return;
    }
    loop {
        if shared.failed.load(Ordering::Relaxed) {
            break;
        }
        let frame = match host::read_frame(pipe) {
            Ok(frame) => frame,
            Err(_) => break,
        };
        let text = String::from_utf8_lossy(&frame);
        let Some(peer) = host::observe_client(pipe, shared.pipe_instance) else {
            break;
        };
        let response = shared
            .broker
            .lock()
            .expect("broker")
            .decide(&text, &peer, host::unix_ms());
        if host::write_frame(pipe, response.as_bytes()).is_err() {
            break;
        }
    }
    host::close(pipe);
}

struct Stage {
    executable: PathBuf,
    drop_dir: PathBuf,
    report: PathBuf,
    store: PathBuf,
    evidence: PathBuf,
    restoration: PathBuf,
    forbidden: PathBuf,
    host_file: PathBuf,
    allowed: PathBuf,
    link: PathBuf,
}

fn prepare_tree(root: &Path, account: &str) -> Result<Stage, u32> {
    let protected = root.join("protected");
    let host_dir = root.join("host");
    let drop_dir = root.join("drop");
    let stage_dir = root.join("stage");
    for directory in [&protected, &host_dir, &drop_dir, &stage_dir] {
        fs::create_dir_all(directory).map_err(|_| 1u32)?;
    }
    let stage = Stage {
        executable: stage_dir.join("worker.exe"),
        drop_dir: drop_dir.clone(),
        report: drop_dir.join("report.txt"),
        store: protected.join("store.bin"),
        evidence: protected.join("evidence.bin"),
        restoration: protected.join("restoration.bin"),
        forbidden: protected.join("workspace.bin"),
        host_file: host_dir.join("secret.bin"),
        allowed: protected.join("fixture.bin"),
        link: drop_dir.join("link.bin"),
    };
    for file in [
        &stage.store,
        &stage.evidence,
        &stage.restoration,
        &stage.forbidden,
        &stage.host_file,
        &stage.allowed,
    ] {
        fs::write(file, b"protected-bytes").map_err(|_| 1u32)?;
        host::protect_user(file)?;
    }
    host::protect_user(&protected)?;
    host::protect_user(&host_dir)?;
    let current = std::env::current_exe().map_err(|_| 1u32)?;
    fs::copy(&current, &stage.executable).map_err(|_| 1u32)?;
    host::grant_account(&stage_dir, account, RX)?;
    host::grant_account(
        &stage.executable,
        account,
        FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
    )?;
    host::grant_account(&drop_dir, account, GENERIC_ALL)?;
    Ok(stage)
}

struct Child {
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
    job: HANDLE,
}

impl Child {
    fn assign_job(&self) -> bool {
        if self.job.is_null() {
            return false;
        }
        unsafe { AssignProcessToJobObject(self.job, self.process) != 0 }
    }

    fn finish(mut self) -> (u32, bool) {
        let mut code = STILL_ACTIVE;
        unsafe { GetExitCodeProcess(self.process, &mut code) };
        let running = code == STILL_ACTIVE;
        let job = self.job;
        self.job = ptr::null_mut();
        if !job.is_null() {
            host::close(job);
        }
        if running {
            let _ = unsafe { TerminateProcess(self.process, 1) };
            unsafe { WaitForSingleObject(self.process, 8_000) };
            unsafe { GetExitCodeProcess(self.process, &mut code) };
        }
        host::close(self.process);
        host::close(self.thread);
        self.process = ptr::null_mut();
        self.thread = ptr::null_mut();
        (code, running)
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if !self.job.is_null() {
            host::close(self.job);
            self.job = ptr::null_mut();
        }
        if !self.process.is_null() {
            let _ = unsafe { TerminateProcess(self.process, 1) };
            host::close(self.process);
            self.process = ptr::null_mut();
        }
        host::close(self.thread);
        self.thread = ptr::null_mut();
    }
}

fn create_worker(
    account: &str,
    password: &Password,
    stage: &Stage,
    command: &[u16],
    environment: &[u16],
) -> Result<Child, contract::OsFailure> {
    let mut user = wide(account);
    let mut domain = wide(".");
    let mut pass = password.as_wide().to_vec();
    let application = wide_path(&stage.executable);
    let directory = wide_path(&stage.drop_dir);
    let mut command = command.to_vec();
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessWithLogonW(
            user.as_ptr(),
            domain.as_ptr(),
            pass.as_ptr(),
            LOGON_WITH_PROFILE,
            application.as_ptr(),
            command.as_mut_ptr(),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &startup,
            &mut info,
        )
    };
    user.fill(0);
    domain.fill(0);
    pass.fill(0);
    command.fill(0);
    if ok == 0 {
        return Err(contract::OsFailure {
            step: "create",
            code: unsafe { GetLastError() },
        });
    }
    Ok(Child {
        process: info.hProcess,
        thread: info.hThread,
        pid: info.dwProcessId,
        job: make_job(),
    })
}

fn make_job() -> HANDLE {
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        return ptr::null_mut();
    }
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    let set = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
        )
    };
    if set == 0 {
        host::close(job);
        ptr::null_mut()
    } else {
        job
    }
}

fn cancel_server(thread_id: &AtomicU32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while thread_id.load(Ordering::Relaxed) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let id = thread_id.load(Ordering::Relaxed);
    if id == 0 {
        return;
    }
    let thread = unsafe { OpenThread(THREAD_TERMINATE, 0, id) };
    if thread.is_null() {
        return;
    }
    unsafe { windows_sys::Win32::System::IO::CancelSynchronousIo(thread) };
    unsafe { CloseHandle(thread) };
}

fn wait_report(path: &Path, budget: Duration) -> Option<String> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path)
            && text.contains("holding=1")
        {
            return Some(text);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    fs::read_to_string(path).ok()
}

fn stopped(reason: &str, code: u32, attempted: bool) -> Outcome {
    Outcome {
        gate: Gate::NotEstablished,
        worker_started: false,
        report: format!(
            "INCONCLUSIVE reason={reason} code={code} gate=C worker_started=0 account_created=0 logon_attempted={}",
            u8::from(attempted)
        ),
    }
}

fn started_failure(reason: &str, code: u32) -> Outcome {
    Outcome {
        gate: Gate::Partial,
        worker_started: true,
        report: format!(
            "gate=B worker_started=1 account_created=0 logon_attempted=1 reason={reason} code={code}"
        ),
    }
}

fn ipc_exchange() -> (String, Option<HANDLE>) {
    let pipe = std::env::var("LCA_01N_PIPE").unwrap_or_default();
    let session = std::env::var("LCA_01N_SESSION").unwrap_or_default();
    let issued: u64 = std::env::var("LCA_01N_ISSUED")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    let expires: u64 = std::env::var("LCA_01N_EXPIRES")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    let Some(handle) = open_pipe(&pipe) else {
        return ("decisions=pipe".to_owned(), None);
    };
    let mut labels = Vec::new();
    let mut payload = String::new();
    let messages = [
        broker::request(&session, "req-ping", "ping", "", issued, expires),
        broker::request(&session, "req-info", "worker_info", "", issued, expires),
        broker::request(
            &session,
            "req-read",
            "read_fixture",
            "fixture-001",
            issued,
            expires,
        ),
        broker::request(&session, "req-exec", "execute", "", issued, expires),
        broker::request(
            &session,
            "req-path",
            "read_fixture",
            "C:/secret",
            issued,
            expires,
        ),
        broker::request(&session, "req-ping", "ping", "", issued, expires),
        broker::request("session-other", "req-other", "ping", "", issued, expires),
    ];
    for message in messages {
        if host::write_frame(handle, message.as_bytes()).is_err() {
            labels.push("deny:pipe".to_owned());
            break;
        }
        let Ok(frame) = host::read_frame(handle) else {
            labels.push("deny:pipe".to_owned());
            break;
        };
        let text = String::from_utf8_lossy(&frame).to_string();
        if payload.is_empty() && message.contains("read_fixture") {
            payload = broker::payload_of(&text);
        }
        labels.push(broker::label(&text));
    }
    let smuggled = broker::request(&session, "req-claim", "ping", "", issued, expires).replacen(
        '}',
        ",\"user_sid\":\"S-1-5-21-9-8-7-1001\"}",
        1,
    );
    if host::write_frame(handle, smuggled.as_bytes()).is_ok()
        && let Ok(frame) = host::read_frame(handle)
    {
        labels.push(broker::label(&String::from_utf8_lossy(&frame)));
    }
    (
        format!("decisions={}\nread_payload={payload}", labels.join(",")),
        Some(handle),
    )
}

fn open_pipe(name: &str) -> Option<HANDLE> {
    if name.is_empty() {
        return None;
    }
    let wide_name = wide(name);
    for _ in 0..50 {
        let handle = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                FILE_GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            return Some(handle);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

fn open_code(path: &Path, access: u32, disposition: u32) -> u32 {
    if path.as_os_str().is_empty() {
        return 2;
    }
    let name = wide_path(path);
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ,
            ptr::null(),
            disposition,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        unsafe { GetLastError() }
    } else {
        host::close(handle);
        0
    }
}

fn hardlink_code(link: &Path, existing: &Path) -> u32 {
    if link.as_os_str().is_empty() || existing.as_os_str().is_empty() {
        return 2;
    }
    let link_w = wide_path(link);
    let existing_w = wide_path(existing);
    let ok = unsafe { CreateHardLinkW(link_w.as_ptr(), existing_w.as_ptr(), ptr::null()) };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn rename_code(from: &Path, to: &Path) -> u32 {
    if from.as_os_str().is_empty() {
        return 2;
    }
    let from_w = wide_path(from);
    let to_w = wide_path(to);
    let ok = unsafe { MoveFileW(from_w.as_ptr(), to_w.as_ptr()) };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn account_name() -> Option<String> {
    let value = std::env::var("LCA_01N_ACCOUNT").ok()?;
    if contract::valid_account(&value) {
        Some(value)
    } else {
        Some(String::new())
    }
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned())
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
