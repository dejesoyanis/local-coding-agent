//! LCA-01L isolation experiments.
//!
//! This module is compiled only as a Windows unit test. The agent binary does not
//! contain it, and `apply_ntfs` does not call it. Nothing here changes a user account,
//! a production ACL, or the publisher.
//!
//! A same-user child is not a security boundary. Results are observations on this
//! machine. A privilege failure is not a pass.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    EXPLICIT_ACCESS_W, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CopySid, CreateRestrictedToken, FreeSid, GetLengthSid,
    GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, SID_IDENTIFIER_AUTHORITY, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY,
    TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenIntegrityLevel,
    TokenPrivileges, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, MOVEFILE_REPLACE_EXISTING, MoveFileExW, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken, PROCESS_INFORMATION,
    PROCESS_SET_QUOTA, PROCESS_TERMINATE, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

const DENY_ACCESS: i32 = 3;
const GRANT_ACCESS: i32 = 1;
const TRUSTEE_IS_SID: i32 = 0;
const TRUSTEE_IS_USER: i32 = 1;
const SE_FILE_OBJECT: i32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const DISABLE_MAX_PRIVILEGE: u32 = 0x1;
const SYNCHRONIZE: u32 = 0x0010_0000;
const SE_GROUP_INTEGRITY: u32 = 0x20;
const TOKEN_MANDATORY_LOW_RID: u32 = 0x1000;
const CREATE_FLAGS: u32 = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("lca-01l-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("temp");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn parent_test() -> bool {
    std::env::var_os("LCA_01L_ROLE").is_none()
}

fn nonce() -> String {
    let mut raw = [0u8; 32];
    let ticks = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    raw[..16].copy_from_slice(&ticks.to_le_bytes());
    raw[16..20].copy_from_slice(&std::process::id().to_le_bytes());
    let anchor = 0u8;
    let address = std::ptr::from_ref(&anchor) as usize;
    raw[20..28].copy_from_slice(&address.to_le_bytes());
    hex(&Sha256::digest(raw))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn wide(path: &Path) -> Vec<u16> {
    OsStr::new(path).encode_wide().chain(Some(0)).collect()
}

fn spawn_filtered(role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test exe"));
    command
        .arg("isolation_probe::isolation_probe_child")
        .arg("--exact")
        .env("LCA_01L_ROLE", role)
        .env_remove("LCA_01K_ATTACK")
        .env_remove("LCA_01K_KILL")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn wait_deadline(child: &mut Child, limit: Duration) -> bool {
    let start = Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            return true;
        }
        if start.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_reply(reader: &mut impl BufRead) -> String {
    let mut line = String::new();
    let read = reader.read_line(&mut line).expect("reply");
    assert!(read > 0, "worker closed stdout");
    line.trim_end().to_owned()
}

#[test]
fn isolation_probe_child() {
    let code = match std::env::var("LCA_01L_ROLE").as_deref() {
        Ok("worker") => run_worker(),
        Ok("restricted") => run_restricted(),
        Ok("watcher") => run_watcher(),
        Ok("attacker") => run_attacker(),
        Ok("inherit") => run_inherit(),
        Ok("touch") => run_touch(),
        Ok("controller") => run_controller(),
        _ => return,
    };
    std::process::exit(code);
}

fn run_worker() -> i32 {
    let expected = std::env::var("LCA_01L_TOKEN").unwrap_or_default();
    let request = inherited_file("LCA_01L_REQUEST");
    let reply = inherited_file("LCA_01L_REPLY");
    let mut input = BufReader::new(request);
    let mut output = reply;
    let mut token = String::new();
    if input.read_line(&mut token).is_err() {
        return 2;
    }
    let token = token.trim_end();
    if token != expected || expected.len() != 64 {
        let _ = writeln!(output, "DENY auth");
        let _ = output.flush();
        return 2;
    }
    let _ = writeln!(output, "OK auth");
    let _ = output.flush();
    loop {
        let mut line = String::new();
        let read = input.read_line(&mut line).unwrap_or(0);
        if read == 0 {
            return 0;
        }
        if line.len() > 1024 {
            let _ = writeln!(output, "DENY size");
            let _ = output.flush();
            continue;
        }
        let line = line.trim_end();
        if line == "mutate" {
            let _ = writeln!(output, "DENY mutate");
        } else if let Some(text) = line.strip_prefix("echo ") {
            if text.len() > 64 {
                let _ = writeln!(output, "DENY size");
            } else {
                let _ = writeln!(output, "OK {text}");
            }
        } else if line == "identity" {
            let parent = std::env::var("LCA_01L_PARENT").unwrap_or_default();
            let _ = writeln!(output, "OK pid={} parent={parent}", std::process::id());
        } else {
            let _ = writeln!(output, "DENY unknown");
        }
        let _ = output.flush();
    }
}

fn inherited_file(name: &str) -> File {
    let value = std::env::var(name)
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .unwrap_or(0);
    unsafe { File::from_raw_handle(value as _) }
}

fn run_restricted() -> i32 {
    let report = std::env::var("LCA_01L_REPORT").unwrap_or_default();
    let allowed = open_read(Path::new(
        &std::env::var("LCA_01L_ALLOWED").unwrap_or_default(),
    ));
    let denied = open_read(Path::new(
        &std::env::var("LCA_01L_DENIED").unwrap_or_default(),
    ));
    let _ = fs::write(&report, format!("allowed={allowed}\ndenied={denied}\n"));
    0
}

fn run_watcher() -> i32 {
    let report = std::env::var("LCA_01L_REPORT").unwrap_or_default();
    let parent: u32 = std::env::var("LCA_01L_PARENT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, parent) };
    if handle.is_null() {
        let _ = fs::write(&report, format!("open={}", unsafe { GetLastError() }));
        return 0;
    }
    let _ = fs::write(&report, "opened");
    let waited = unsafe { WaitForSingleObject(handle, 8_000) };
    unsafe { CloseHandle(handle) };
    let text = if waited == WAIT_OBJECT_0 {
        "parent_exit"
    } else {
        return {
            let _ = fs::write(&report, format!("wait={waited}"));
            0
        };
    };
    let _ = fs::write(&report, text);
    0
}

#[allow(clippy::zombie_processes)]
fn run_controller() -> i32 {
    let report = std::env::var("LCA_01L_REPORT").unwrap_or_default();
    let _ = fs::write(&report, "");
    let mut watcher = spawn_filtered("watcher");
    watcher
        .env("LCA_01L_REPORT", &report)
        .env("LCA_01L_PARENT", std::process::id().to_string());
    let watcher = watcher.spawn().expect("watcher");
    let start = Instant::now();
    loop {
        if fs::read_to_string(&report).ok().as_deref() == Some("opened") {
            break;
        }
        if start.elapsed() > Duration::from_secs(5) {
            let _ = fs::write(&report, "watcher_not_ready");
            return 3;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // `process::exit` in the caller skips this destructor, so the watcher stays alive
    // until it observes this process exit.
    std::mem::forget(watcher);
    0
}

fn run_inherit() -> i32 {
    let report = std::env::var("LCA_01L_REPORT").unwrap_or_default();
    let inherit = std::env::var("LCA_01L_INHERIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let private = std::env::var("LCA_01L_PRIVATE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let text = format!(
        "inherit={} private={}",
        read_prefix(inherit),
        read_prefix(private)
    );
    let _ = fs::write(&report, text);
    0
}

fn read_prefix(value: usize) -> String {
    if value == 0 {
        return "missing".to_owned();
    }
    let mut buffer = [0u8; 4];
    let mut read = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            value as HANDLE,
            buffer.as_mut_ptr().cast(),
            4,
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        format!("err={}", unsafe { GetLastError() })
    } else {
        format!("bytes={}", hex(&buffer[..read as usize]))
    }
}

fn run_touch() -> i32 {
    let report = std::env::var("LCA_01L_REPORT").unwrap_or_default();
    let path = std::env::var("LCA_01L_PATH").unwrap_or_default();
    let code = match OpenOptions::new().append(true).open(&path) {
        Ok(_) => 0,
        Err(error) => error.raw_os_error().unwrap_or(1) as u32,
    };
    let _ = fs::write(&report, code.to_string());
    0
}

fn run_attacker() -> i32 {
    let root = PathBuf::from(std::env::var("LCA_01L_ROOT").unwrap_or_default());
    let report = PathBuf::from(std::env::var("LCA_01L_REPORT").unwrap_or_default());
    let notes = root.join("ws").join("dir").join("notes.txt");
    let moved = root.join("ws").join("dir").join("moved.txt");
    let outside = root.join("out").join("alias.txt");
    let parent = root.join("ws").join("dir");
    let renamed = root.join("ws").join("dir-renamed");
    let blob = root.join("evidence").join("blob.bin");
    let mut lines = String::new();
    let link = call_wide2(&outside, &notes, |from, to| unsafe {
        CreateHardLinkW(from, to, ptr::null())
    });
    lines.push_str(&format!(
        "hardlink code={link} exists={}\n",
        u8::from(outside.exists())
    ));
    let target = call_wide2(&notes, &moved, |from, to| unsafe {
        MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING)
    });
    lines.push_str(&format!(
        "target_rename code={target} renamed={}\n",
        u8::from(moved.exists())
    ));
    let directory = call_wide2(&parent, &renamed, |from, to| unsafe {
        MoveFileExW(from, to, 0)
    });
    lines.push_str(&format!(
        "parent_rename code={directory} renamed={}\n",
        u8::from(renamed.exists())
    ));
    let dpapi = match fs::read(&blob) {
        Ok(bytes) => match crate::unprotect(&bytes) {
            Ok(plain) if plain == b"sealed-evidence" => 0,
            Ok(_) => 2,
            Err(_) => 3,
        },
        Err(error) => error.raw_os_error().unwrap_or(1),
    };
    lines.push_str(&format!("dpapi code={dpapi}\n"));
    let write_code = match fs::write(&blob, b"tampered") {
        Ok(()) => 0,
        Err(error) => error.raw_os_error().unwrap_or(1),
    };
    lines.push_str(&format!("evidence_write code={write_code}\n"));
    let _ = fs::write(&report, lines);
    0
}

fn call_wide2(from: &Path, to: &Path, call: fn(*const u16, *const u16) -> i32) -> u32 {
    let left = wide(from);
    let right = wide(to);
    let result = call(left.as_ptr(), right.as_ptr());
    if result == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

#[test]
fn experiment_ipc_rejects_a_bad_peer_and_a_forbidden_request() {
    if !parent_test() {
        return;
    }
    let token = nonce();
    let mut child = PipeWorker::spawn(&token);
    let job_code = assign_job(child.pid);
    observe("job.txt", &format!("assign={job_code}"));
    writeln!(child.request, "{token}").expect("token");
    child.request.flush().expect("flush");
    assert_eq!(read_reply(&mut child.reply), "OK auth");
    writeln!(child.request, "echo ping").expect("echo");
    child.request.flush().expect("flush");
    assert_eq!(read_reply(&mut child.reply), "OK ping", "job={job_code}");
    writeln!(child.request, "mutate").expect("mutate");
    child.request.flush().expect("flush");
    assert_eq!(read_reply(&mut child.reply), "DENY mutate");
    writeln!(child.request, "{}", "x".repeat(1100)).expect("size");
    child.request.flush().expect("flush");
    assert_eq!(read_reply(&mut child.reply), "DENY size");
    writeln!(child.request, "identity").expect("identity");
    child.request.flush().expect("flush");
    let identity = read_reply(&mut child.reply);
    assert!(
        identity.contains(&format!("pid={}", child.pid)),
        "{identity}"
    );
    assert!(
        identity.contains(&format!("parent={}", std::process::id())),
        "{identity}"
    );
    drop(child.request_handle());
    assert!(child.wait(Duration::from_secs(5)), "worker did not exit");
}

#[test]
fn experiment_ipc_rejects_the_wrong_token_and_a_killed_worker() {
    if !parent_test() {
        return;
    }
    let token = nonce();
    let mut rejected = PipeWorker::spawn(&token);
    writeln!(rejected.request, "{}", "ab".repeat(32)).expect("wrong");
    rejected.request.flush().expect("flush");
    assert_eq!(read_reply(&mut rejected.reply), "DENY auth");
    assert!(
        rejected.wait(Duration::from_secs(5)),
        "rejected worker hung"
    );
    assert_eq!(rejected.exit_code(), 2, "auth failure must be visible");

    let token = nonce();
    let mut worker = PipeWorker::spawn(&token);
    writeln!(worker.request, "{token}").expect("token");
    worker.request.flush().expect("flush");
    unsafe { TerminateProcess(worker.process, 1) };
    assert!(worker.wait(Duration::from_secs(5)), "killed worker hung");
}

#[test]
fn experiment_controller_exit_is_visible_to_the_worker() {
    if !parent_test() {
        return;
    }
    let scratch = Scratch::new("watch");
    let report = scratch.path().join("report.txt");
    let mut controller = spawn_filtered("controller");
    controller.env("LCA_01L_REPORT", &report);
    let mut controller = controller.spawn().expect("controller");
    assert!(
        wait_deadline(&mut controller, Duration::from_secs(8)),
        "controller hung"
    );
    let start = Instant::now();
    let text = loop {
        if let Ok(text) = fs::read_to_string(&report)
            && (text == "parent_exit"
                || text.starts_with("open=")
                || text.starts_with("wait=")
                || text == "watcher_not_ready")
        {
            break text;
        }
        if start.elapsed() > Duration::from_secs(8) {
            panic!("watcher did not report");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(text, "parent_exit", "{text}");
}

struct PipeWorker {
    request: File,
    reply: BufReader<File>,
    process: HANDLE,
    thread: HANDLE,
    pid: u32,
}

impl PipeWorker {
    fn spawn(token: &str) -> Self {
        let (request_read, request_write) = anon_pipe();
        let (reply_read, reply_write) = anon_pipe();
        clear_inherit(request_write);
        clear_inherit(reply_read);
        let process = launch_worker(token, request_read as usize, reply_write as usize);
        unsafe {
            CloseHandle(request_read);
            CloseHandle(reply_write);
        }
        let request = unsafe { File::from_raw_handle(request_write) };
        let reply = BufReader::new(unsafe { File::from_raw_handle(reply_read) });
        Self {
            request,
            reply,
            process: process.hProcess,
            thread: process.hThread,
            pid: process.dwProcessId,
        }
    }

    fn request_handle(&mut self) -> File {
        // The caller drops the write end. Replace it with a closed placeholder.
        let spare = OpenOptions::new()
            .read(true)
            .write(true)
            .open("NUL")
            .expect("nul");
        std::mem::replace(&mut self.request, spare)
    }

    fn wait(&mut self, limit: Duration) -> bool {
        let start = Instant::now();
        loop {
            let state = unsafe { WaitForSingleObject(self.process, 0) };
            if state == WAIT_OBJECT_0 {
                return true;
            }
            if start.elapsed() > limit {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn exit_code(&self) -> u32 {
        let mut code = 0u32;
        let _ = unsafe { GetExitCodeProcess(self.process, &mut code) };
        code
    }
}

impl Drop for PipeWorker {
    fn drop(&mut self) {
        unsafe {
            TerminateProcess(self.process, 1);
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

fn anon_pipe() -> (HANDLE, HANDLE) {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let ok = unsafe { CreatePipe(&mut read, &mut write, &security, 0) };
    assert_ne!(ok, 0, "pipe {}", unsafe { GetLastError() });
    (read, write)
}

fn clear_inherit(handle: HANDLE) {
    let cleared = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) };
    assert_ne!(cleared, 0, "inherit {}", unsafe { GetLastError() });
}

fn launch_worker(token: &str, request: usize, reply: usize) -> PROCESS_INFORMATION {
    let exe = std::env::current_exe().expect("exe");
    let mut command = format!(
        "\"{}\" isolation_probe::isolation_probe_child --exact",
        exe.display()
    );
    let mut command_wide: Vec<u16> = OsStr::new(&command).encode_wide().chain(Some(0)).collect();
    let _ = &mut command;
    let parent = std::process::id().to_string();
    let request = request.to_string();
    let reply = reply.to_string();
    let mut environment = environment_block(&[
        ("LCA_01L_ROLE", "worker"),
        ("LCA_01L_TOKEN", token),
        ("LCA_01L_PARENT", &parent),
        ("LCA_01L_REQUEST", &request),
        ("LCA_01L_REPLY", &reply),
    ]);
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            command_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_FLAGS,
            environment.as_mut_ptr().cast(),
            ptr::null(),
            &startup,
            &mut process,
        )
    };
    assert_ne!(ok, 0, "worker {}", unsafe { GetLastError() });
    process
}

#[test]
fn experiment_handle_inheritance_is_explicit() {
    if !parent_test() {
        return;
    }
    let scratch = Scratch::new("inherit");
    let inherited_path = scratch.path().join("inherited.txt");
    let private_path = scratch.path().join("private.txt");
    fs::write(&inherited_path, b"in").expect("in");
    fs::write(&private_path, b"out").expect("out");
    let inherited = File::open(&inherited_path).expect("open in");
    let private = File::open(&private_path).expect("open out");
    let inherited_handle = inherited.as_raw_handle() as usize;
    let private_handle = private.as_raw_handle() as usize;
    let marked = unsafe {
        SetHandleInformation(
            inherited.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    assert_ne!(marked, 0, "inherit flag {}", unsafe { GetLastError() });
    let cleared = unsafe { SetHandleInformation(private.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) };
    assert_ne!(cleared, 0, "private flag {}", unsafe { GetLastError() });
    let report = scratch.path().join("report.txt");
    let status = create_inherited_child(&report, inherited_handle, private_handle);
    assert_eq!(status, 0, "child status {status}");
    let text = fs::read_to_string(&report).expect("report");
    observe("inherit.txt", &text);
    assert!(
        text.starts_with("inherit=bytes=696e "),
        "inherited handle did not read its file: {text}"
    );
    assert!(
        !text.contains("private=bytes=6f7574"),
        "non-inherited handle was usable: {text}"
    );
    drop(inherited);
    drop(private);
}

fn create_inherited_child(report: &Path, inherited: usize, private: usize) -> u32 {
    let exe = std::env::current_exe().expect("exe");
    let mut command = format!(
        "\"{}\" isolation_probe::isolation_probe_child --exact",
        exe.display()
    );
    let mut command_wide: Vec<u16> = OsStr::new(&command).encode_wide().chain(Some(0)).collect();
    let _ = &mut command;
    let mut environment = environment_block(&[
        ("LCA_01L_ROLE", "inherit"),
        ("LCA_01L_REPORT", &report.display().to_string()),
        ("LCA_01L_INHERIT", &inherited.to_string()),
        ("LCA_01L_PRIVATE", &private.to_string()),
    ]);
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            command_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_FLAGS,
            environment.as_mut_ptr().cast(),
            ptr::null(),
            &startup,
            &mut process,
        )
    };
    if ok == 0 {
        return unsafe { GetLastError() };
    }
    let waited = unsafe { WaitForSingleObject(process.hProcess, 8_000) };
    let mut code = 0u32;
    if waited == WAIT_OBJECT_0 {
        let _ = unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(process.hProcess, &mut code)
        };
    } else {
        code = waited;
        let _ =
            unsafe { windows_sys::Win32::System::Threading::TerminateProcess(process.hProcess, 1) };
    }
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    code
}

fn environment_block(extra: &[(&str, &str)]) -> Vec<u16> {
    let mut block = String::new();
    for (key, value) in std::env::vars() {
        if key.starts_with("LCA_01L_") || key == "LCA_01K_ATTACK" || key == "LCA_01K_KILL" {
            continue;
        }
        if key.contains('=') || value.contains('\0') || key.contains('\0') {
            continue;
        }
        block.push_str(&key);
        block.push('=');
        block.push_str(&value);
        block.push('\0');
    }
    for (key, value) in extra {
        block.push_str(key);
        block.push('=');
        block.push_str(value);
        block.push('\0');
    }
    block.push('\0');
    block.encode_utf16().collect()
}

#[test]
fn experiment_restricted_token_and_low_integrity() {
    if !parent_test() {
        return;
    }
    let scratch = Scratch::new("token");
    let allowed = scratch.path().join("allowed.txt");
    let denied = scratch.path().join("denied.txt");
    fs::write(&allowed, b"allowed").expect("allowed");
    fs::write(&denied, b"denied").expect("denied");
    let user = current_user_sid().expect("user sid");
    let users = users_sid().expect("users sid");
    set_dacl(
        &allowed,
        &[
            ace(users.as_ptr(), FILE_GENERIC_READ, GRANT_ACCESS),
            ace(user.as_ptr(), GENERIC_ALL, GRANT_ACCESS),
        ],
    )
    .expect("allowed dacl");
    set_dacl(&denied, &[ace(user.as_ptr(), GENERIC_ALL, GRANT_ACCESS)]).expect("denied dacl");

    let mut token = ptr::null_mut();
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_IMPERSONATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT,
            &mut token,
        )
    };
    assert_ne!(opened, 0, "token {}", unsafe { GetLastError() });
    let before_privileges = info_count(token, TokenPrivileges);
    let before_groups = info_count(token, TokenGroups);
    let mut restricted = ptr::null_mut();
    let restrict = SID_AND_ATTRIBUTES {
        Sid: users.as_ptr().cast(),
        Attributes: 0,
    };
    let created = unsafe {
        CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,
            0,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            1,
            &restrict,
            &mut restricted,
        )
    };
    assert_ne!(created, 0, "restricted {}", unsafe { GetLastError() });
    let after_privileges = info_count(restricted, TokenPrivileges);
    let after_groups = info_count(restricted, TokenGroups);
    let impersonated = unsafe { ImpersonateLoggedOnUser(restricted) };
    assert_ne!(impersonated, 0, "impersonate {}", unsafe { GetLastError() });
    let allowed_read = open_read(&allowed);
    let denied_read = open_read(&denied);
    unsafe { RevertToSelf() };
    assert_eq!(allowed_read, 0, "allowed read {allowed_read}");
    assert_eq!(denied_read, 5, "denied read {denied_read}");
    assert!(
        after_privileges < before_privileges || after_privileges == 0,
        "privileges before={before_privileges} after={after_privileges} groups {before_groups}->{after_groups}"
    );

    let probe = scratch.path().join("restricted.txt");
    fs::write(&probe, b"").expect("probe");
    set_dacl(
        &probe,
        &[
            ace(users.as_ptr(), GENERIC_ALL, GRANT_ACCESS),
            ace(user.as_ptr(), GENERIC_ALL, GRANT_ACCESS),
        ],
    )
    .expect("probe dacl");
    let spawn = spawn_restricted_probe(restricted, &allowed, &denied, &probe);
    let probe_text = fs::read_to_string(&probe).unwrap_or_default();
    if probe_text.contains("allowed=") {
        assert!(
            probe_text.contains("allowed=0") && probe_text.contains("denied=5"),
            "restricted process report: {probe_text}"
        );
    }

    let low = measure_low_integrity(token, &allowed, &denied);
    unsafe {
        CloseHandle(restricted);
        CloseHandle(token);
    }
    observe(
        "token.txt",
        &format!(
            "privileges {before_privileges}->{after_privileges}\ngroups {before_groups}->{after_groups}\nallowed_read={allowed_read}\ndenied_read={denied_read}\nspawn={spawn}\nprocess={probe_text}\n{low}"
        ),
    );
    if low.contains("medium_write=") {
        assert!(
            low.contains("medium_write=1")
                && low.contains("low_read=0")
                && low.contains("low_write=5"),
            "{low}"
        );
    }
}

fn spawn_restricted_probe(token: HANDLE, allowed: &Path, denied: &Path, report: &Path) -> u32 {
    let exe = std::env::current_exe().expect("exe");
    let mut command = format!(
        "\"{}\" isolation_probe::isolation_probe_child --exact",
        exe.display()
    );
    let mut command_wide: Vec<u16> = OsStr::new(&command).encode_wide().chain(Some(0)).collect();
    let _ = &mut command;
    let allowed = allowed.display().to_string();
    let denied = denied.display().to_string();
    let report_path = report.display().to_string();
    let mut environment = environment_block(&[
        ("LCA_01L_ROLE", "restricted"),
        ("LCA_01L_ALLOWED", &allowed),
        ("LCA_01L_DENIED", &denied),
        ("LCA_01L_REPORT", &report_path),
    ]);
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            token,
            ptr::null(),
            command_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_FLAGS,
            environment.as_mut_ptr().cast(),
            ptr::null(),
            &startup,
            &mut process,
        )
    };
    if ok == 0 {
        return unsafe { GetLastError() };
    }
    let _ = unsafe { WaitForSingleObject(process.hProcess, 8_000) };
    let mut code = 0u32;
    let _ = unsafe { GetExitCodeProcess(process.hProcess, &mut code) };
    unsafe {
        TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if fs::read_to_string(report).ok().as_deref() == Some("") || fs::metadata(report).is_err() {
        let _ = fs::write(report, format!("exit={code} exit_hex={code:#x}\n"));
    }
    0
}

fn measure_low_integrity(primary: HANDLE, allowed: &Path, denied: &Path) -> String {
    let mut duplicated = ptr::null_mut();
    let duplicated_ok = unsafe {
        windows_sys::Win32::Security::DuplicateTokenEx(
            primary,
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
            ptr::null(),
            windows_sys::Win32::Security::SecurityImpersonation,
            windows_sys::Win32::Security::TokenImpersonation,
            &mut duplicated,
        )
    };
    if duplicated_ok == 0 {
        return format!("duplicate={}", unsafe { GetLastError() });
    }
    let sid = integrity_sid(TOKEN_MANDATORY_LOW_RID);
    let mut label = TOKEN_MANDATORY_LABEL {
        label: SID_AND_ATTRIBUTES {
            Sid: sid.as_ptr().cast(),
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    let lowered = unsafe {
        windows_sys::Win32::Security::SetTokenInformation(
            duplicated,
            TokenIntegrityLevel,
            (&mut label as *mut TOKEN_MANDATORY_LABEL).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_MANDATORY_LABEL>()).unwrap_or(0),
        )
    };
    if lowered == 0 {
        let code = unsafe { GetLastError() };
        unsafe { CloseHandle(duplicated) };
        return format!("integrity={code}");
    }
    let impersonated = unsafe { ImpersonateLoggedOnUser(duplicated) };
    if impersonated == 0 {
        let code = unsafe { GetLastError() };
        unsafe { CloseHandle(duplicated) };
        return format!("low_impersonate={code}");
    }
    let low_read = open_read(allowed);
    let low_write = open_write(denied);
    unsafe { RevertToSelf() };
    unsafe { CloseHandle(duplicated) };
    let medium = OpenOptions::new().write(true).truncate(true).open(denied);
    format!(
        "low_read={low_read} low_write={low_write} medium_write={}",
        u8::from(medium.is_ok())
    )
}

fn observe(name: &str, text: &str) {
    let dir = env_target().join("lca-01l");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::write(dir.join(name), text);
}

fn env_target() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("target"))
}

#[repr(C)]
struct TOKEN_MANDATORY_LABEL {
    label: SID_AND_ATTRIBUTES,
}

fn open_read(path: &Path) -> u32 {
    open_access(path, FILE_GENERIC_READ)
}

fn open_write(path: &Path) -> u32 {
    open_access(path, GENERIC_WRITE | FILE_WRITE_DATA)
}

fn open_access(path: &Path, access: u32) -> u32 {
    let name = wide(path);
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        unsafe { GetLastError() }
    } else {
        unsafe { CloseHandle(handle) };
        0
    }
}

fn info_count(token: HANDLE, class: i32) -> u32 {
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, class, ptr::null_mut(), 0, &mut needed);
    }
    if needed < 4 {
        return 0;
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
    if ok == 0 {
        return u32::MAX;
    }
    u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])
}

struct OwnedSid(Vec<u8>);

impl OwnedSid {
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0.as_ptr().cast_mut().cast()
    }
}

fn current_user_sid() -> Result<OwnedSid, u32> {
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(unsafe { GetLastError() });
    }
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        unsafe { CloseHandle(token) };
        return Err(unsafe { GetLastError() });
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let length = unsafe { GetLengthSid(user.User.Sid) };
    let mut owned = vec![0u8; length as usize];
    let copied = unsafe { CopySid(length, owned.as_mut_ptr().cast(), user.User.Sid) };
    unsafe { CloseHandle(token) };
    if copied == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(OwnedSid(owned))
}

fn users_sid() -> Result<OwnedSid, u32> {
    allocate_sid(&[0, 0, 0, 0, 0, 5], &[32, 545])
}

fn integrity_sid(rid: u32) -> OwnedSid {
    allocate_sid(&[0, 0, 0, 0, 0, 16], &[rid]).expect("integrity sid")
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
    let length = unsafe { GetLengthSid(sid) };
    let mut owned = vec![0u8; length as usize];
    let copied = unsafe { CopySid(length, owned.as_mut_ptr().cast(), sid) };
    unsafe { FreeSid(sid) };
    if copied == 0 {
        return Err(unsafe { GetLastError() });
    }
    Ok(OwnedSid(owned))
}

fn ace(sid: *mut std::ffi::c_void, access: u32, mode: i32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: mode,
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

fn set_dacl(path: &Path, entries: &[EXPLICIT_ACCESS_W]) -> Result<(), u32> {
    let mut entries = entries.to_vec();
    let mut dacl = ptr::null_mut();
    let built = unsafe {
        SetEntriesInAclW(
            u32::try_from(entries.len()).unwrap_or(0),
            entries.as_mut_ptr(),
            ptr::null(),
            &mut dacl,
        )
    };
    if built != 0 {
        return Err(built);
    }
    let name = wide(path);
    let applied = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    unsafe { LocalFree(dacl.cast()) };
    if applied == 0 { Ok(()) } else { Err(applied) }
}

#[test]
fn experiment_acl_does_not_separate_same_user_processes() {
    if !parent_test() {
        return;
    }
    let scratch = Scratch::new("acl");
    let file = scratch.path().join("notes.txt");
    fs::write(&file, b"alpha\n").expect("seed");
    let user = current_user_sid().expect("sid");
    set_dacl(
        &file,
        &[
            ace(
                user.as_ptr(),
                FILE_WRITE_DATA | FILE_APPEND_DATA,
                DENY_ACCESS,
            ),
            ace(user.as_ptr(), FILE_GENERIC_READ, GRANT_ACCESS),
        ],
    )
    .expect("dacl");
    assert_eq!(open_read(&file), 0, "read was denied");
    assert_eq!(open_write(&file), 5, "write was allowed");
    let report = scratch.path().join("touch.txt");
    let mut child = spawn_filtered("touch");
    child
        .env("LCA_01L_REPORT", &report)
        .env("LCA_01L_PATH", &file);
    let mut child = child.spawn().expect("touch");
    assert!(
        wait_deadline(&mut child, Duration::from_secs(8)),
        "touch hung"
    );
    let child_code: u32 = fs::read_to_string(&report)
        .expect("touch report")
        .trim()
        .parse()
        .expect("code");
    observe("acl.txt", &format!("child_write={child_code}"));
    assert_ne!(child_code, 0, "same-user child wrote");
    set_dacl(&file, &[ace(user.as_ptr(), GENERIC_ALL, GRANT_ACCESS)]).expect("owner rewrite");
    fs::write(&file, b"rewritten\n").expect("owner write");
    assert_eq!(fs::read(&file).expect("after"), b"rewritten\n");
}

#[test]
fn experiment_same_user_attacks_cross_a_process_boundary() {
    if !parent_test() {
        return;
    }
    let scratch = Scratch::new("attack");
    let dir = scratch.path().join("ws").join("dir");
    let outside = scratch.path().join("out");
    let evidence = scratch.path().join("evidence");
    fs::create_dir_all(&dir).expect("dir");
    fs::create_dir_all(&outside).expect("out");
    fs::create_dir_all(&evidence).expect("evidence");
    let notes = dir.join("notes.txt");
    fs::write(&notes, b"alpha\n").expect("notes");
    crate::restrict_directory(&evidence).expect("restrict");
    let sealed = crate::protect(b"sealed-evidence").expect("protect");
    fs::write(evidence.join("blob.bin"), &sealed).expect("blob");
    let mut held = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .open(&notes)
        .expect("pin");
    let report = scratch.path().join("report.txt");
    let mut child = spawn_filtered("attacker");
    child
        .env("LCA_01L_ROOT", scratch.path())
        .env("LCA_01L_REPORT", &report);
    let mut child = child.spawn().expect("attacker");
    assert!(
        wait_deadline(&mut child, Duration::from_secs(8)),
        "attacker hung"
    );
    let text = fs::read_to_string(&report).expect("report");
    assert!(
        text.contains("hardlink code=0 exists=1"),
        "hardlink was not created:\n{text}"
    );
    assert!(
        text.contains("target_rename code=32 renamed=0"),
        "rename was not denied:\n{text}"
    );
    assert!(
        text.contains("parent_rename code=5 renamed=0"),
        "parent rename was not denied:\n{text}"
    );
    assert!(text.contains("dpapi code=0"), "dpapi:\n{text}");
    assert!(
        text.contains("evidence_write code=0"),
        "evidence write:\n{text}"
    );
    held.write_all(b"beta\n").expect("write");
    held.set_len(5).expect("truncate");
    held.flush().expect("flush");
    let alias = outside.join("alias.txt");
    assert_eq!(fs::read(&alias).expect("alias"), b"beta\n");
    assert_eq!(
        fs::read(evidence.join("blob.bin")).expect("blob"),
        b"tampered"
    );
    drop(held);
}

fn assign_job(pid: u32) -> u32 {
    let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
    if job.is_null() {
        return unsafe { GetLastError() };
    }
    let process = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
    if process.is_null() {
        unsafe { CloseHandle(job) };
        return unsafe { GetLastError() };
    }
    let assigned = unsafe { AssignProcessToJobObject(job, process) };
    let code = if assigned == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    unsafe {
        CloseHandle(process);
        CloseHandle(job);
    }
    code
}
