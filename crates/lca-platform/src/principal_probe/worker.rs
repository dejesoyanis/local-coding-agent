//! Code that runs inside the restricted worker. The parent decides what this process may do.

#![allow(unsafe_code)]

use std::path::PathBuf;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessW, GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION,
    STARTUPINFOW,
};

use super::broker;
use super::winutil::{self, handle_from, open_code, token_fact_line};

const GENERIC_WRITE: u32 = 0x4000_0000;
const CREATE_ALWAYS: u32 = 2;

pub(super) fn run() -> i32 {
    emit("reached=1");
    emit(&access_line());
    match std::env::var("LCA_01M_SCRIPT").as_deref() {
        Ok("ipc") => ipc(),
        Ok("spawn") => emit(&format!("spawn={}", spawn_cmd())),
        Ok("wait") => block_until_request(),
        _ => {}
    }
    0
}

fn access_line() -> String {
    let allowed = env_path("LCA_01M_ALLOWED");
    let denied = env_path("LCA_01M_DENIED");
    let store = env_path("LCA_01M_STORE");
    let evidence = env_path("LCA_01M_EVIDENCE");
    let outside = env_path("LCA_01M_OUTSIDE");
    let drop_dir = env_path("LCA_01M_DROP");
    let link = env_path("LCA_01M_LINK");
    let granted = handle_from(&std::env::var("LCA_01M_GRANTED").unwrap_or_default());
    let foreign = handle_from(&std::env::var("LCA_01M_FOREIGN").unwrap_or_default());
    let (foreign_read, _) = read_handle(foreign);
    let (granted_read, granted_hex) = read_handle(granted);
    let granted_write = write_handle(granted);
    let token = process_token();
    let facts = if token.is_null() {
        "token_type=0 integrity=0 privileges=0 groups=0 enabled=0 restricted=0 dacl_aces=0"
            .to_owned()
    } else {
        let line = token_fact_line(token);
        close(token);
        line
    };
    format!(
        "{facts} allowed_read={} denied_read={} denied_write={} store_read={} evidence_read={} outside_read={} outside_write={} hardlink={} drop_write={} granted_read={granted_read} granted_write={granted_write} granted_hex={granted_hex} foreign_read={foreign_read} dpapi={} own_pipe={}",
        open_code(&allowed, FILE_GENERIC_READ),
        open_code(&denied, FILE_GENERIC_READ),
        open_code(&denied, FILE_GENERIC_WRITE | GENERIC_WRITE),
        open_code(&store, FILE_GENERIC_READ),
        open_code(&evidence, FILE_GENERIC_READ),
        open_code(&outside, FILE_GENERIC_READ),
        open_code(&outside, FILE_GENERIC_WRITE | GENERIC_WRITE),
        hardlink(&link, &denied),
        create_note(&drop_dir),
        dpapi_result(),
        own_pipe()
    )
}

fn ipc() {
    let pipe = std::env::var("LCA_01M_PIPE").unwrap_or_default();
    let worker_id = std::env::var("LCA_01M_WORKER_ID").unwrap_or_default();
    let messages = broker::scripted_requests(&worker_id, broker::now_ms());
    match winutil::client_exchange(&pipe, &messages) {
        Ok(labels) => {
            let mut decisions = Vec::new();
            let mut payload = String::new();
            for label in labels {
                if let Some(value) = label.strip_prefix("payload=") {
                    payload = value.to_owned();
                } else {
                    decisions.push(label);
                }
            }
            emit(&format!(
                "decisions={} read_payload={payload}",
                decisions.join(",")
            ));
        }
        Err(code) => emit(&format!("ipc_error={code}")),
    }
}

fn block_until_request() {
    let handle = handle_from(&std::env::var("LCA_01M_REQUEST").unwrap_or_default());
    let mut buffer = [0u8; 1];
    let mut read = 0u32;
    unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            handle,
            buffer.as_mut_ptr(),
            1,
            &mut read,
            ptr::null_mut(),
        )
    };
    emit("wait_returned=1");
}

fn spawn_cmd() -> u32 {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let exe = PathBuf::from(root).join("System32").join("cmd.exe");
    let app = wide(&exe);
    let mut command = wide_text(&format!("\"{}\" /c exit", exe.display()));
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap_or(0);
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            app.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut process,
        )
    };
    if ok == 0 {
        return unsafe { GetLastError() };
    }
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(process.hProcess, 1_000);
        windows_sys::Win32::System::Threading::TerminateProcess(process.hProcess, 1);
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    0
}

fn hardlink(link: &std::path::Path, existing: &std::path::Path) -> u32 {
    let new_name = wide(link);
    let old_name = wide(existing);
    let ok = unsafe { CreateHardLinkW(new_name.as_ptr(), old_name.as_ptr(), ptr::null()) };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn create_note(dir: &std::path::Path) -> u32 {
    let path = dir.join("note.txt");
    let name = wide(&path);
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return unsafe { GetLastError() };
    }
    let bytes = b"note";
    let mut written = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            handle,
            bytes.as_ptr(),
            u32::try_from(bytes.len()).unwrap_or(0),
            &mut written,
            ptr::null_mut(),
        )
    };
    close(handle);
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn read_handle(handle: HANDLE) -> (u32, String) {
    let mut buffer = [0u8; 64];
    let mut read = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::ReadFile(
            handle,
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).unwrap_or(0),
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return (unsafe { GetLastError() }, "-".to_owned());
    }
    let end = usize::try_from(read).unwrap_or(0).min(buffer.len());
    (0, broker::hex(&buffer[..end]))
}

fn write_handle(handle: HANDLE) -> u32 {
    let bytes = b"x";
    let mut written = 0u32;
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            handle,
            bytes.as_ptr(),
            1,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn dpapi_result() -> &'static str {
    let hex_text = std::env::var("LCA_01M_EVIDENCE_HEX").unwrap_or_default();
    let Some(bytes) = unhex(&hex_text) else {
        return "badhex";
    };
    match crate::unprotect(&bytes) {
        Ok(plain) if plain == b"evidence-secret" => "ok",
        _ => "fail",
    }
}

fn own_pipe() -> u32 {
    let nonce = std::env::var("LCA_01M_NONCE").unwrap_or_else(|_| "0".to_owned());
    let name = wide_text(&format!(r"\\.\pipe\lca-01m-own-{nonce}"));
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE,
            1,
            128,
            128,
            0,
            ptr::null(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        unsafe { GetLastError() }
    } else {
        close(handle);
        0
    }
}

fn process_token() -> HANDLE {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        ptr::null_mut()
    } else {
        token
    }
}

fn emit(text: &str) {
    let handle = handle_from(&std::env::var("LCA_01M_REPORT").unwrap_or_default());
    let mut line = text.to_owned();
    if !line.ends_with('\n') {
        line.push('\n');
    }
    let mut written = 0u32;
    unsafe {
        windows_sys::Win32::Storage::FileSystem::WriteFile(
            handle,
            line.as_ptr(),
            u32::try_from(line.len()).unwrap_or(0),
            &mut written,
            ptr::null_mut(),
        )
    };
}

fn env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_default())
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_val(bytes[index])?;
        let lo = hex_val(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn wide(path: &std::path::Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn wide_text(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn close(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
}
