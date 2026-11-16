//! Runs one process on a pseudoconsole and feeds it one input line.
//!
//! The child sees a console, so `IsTerminal` is true. This is not an approval bypass:
//! the child still has to read and check the line.

#![allow(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::{ConsoleCapture, PlatformError};

/// Starts `program` attached to a pseudoconsole and writes `input` before waiting.
pub fn spawn_console(
    program: &Path,
    args: &[OsString],
    input: &str,
) -> Result<ConsoleCapture, PlatformError> {
    let mut input_read = Owned(ptr::null_mut());
    let mut input_write = Owned(ptr::null_mut());
    let mut output_read = Owned(ptr::null_mut());
    let mut output_write = Owned(ptr::null_mut());
    let mut security: SECURITY_ATTRIBUTES = unsafe { std::mem::zeroed() };
    security.nLength = u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX);
    security.bInheritHandle = 1;
    if unsafe {
        CreatePipe(&mut input_read.0, &mut input_write.0, &security, 65_536) == 0
            || CreatePipe(&mut output_read.0, &mut output_write.0, &security, 65_536) == 0
    } {
        return Err(last_error("CreatePipe"));
    }
    let mut console: HPCON = 0;
    let created = unsafe {
        CreatePseudoConsole(
            COORD { X: 120, Y: 40 },
            input_read.0,
            output_write.0,
            0,
            &mut console,
        )
    };
    if created < 0 {
        return Err(PlatformError::Io(format!(
            "CreatePseudoConsole failed: {created}"
        )));
    }
    let pseudo = Pseudo(console);
    let attributes = attribute_list()?;
    bind_console(&attributes, pseudo.0)?;
    let command = command_line(program, args);
    let mut wide_command = wide(&command);
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = u32::try_from(size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = ptr::null_mut();
    startup.StartupInfo.hStdOutput = ptr::null_mut();
    startup.StartupInfo.hStdError = ptr::null_mut();
    startup.lpAttributeList = attributes.ptr.cast();
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            ptr::null(),
            wide_command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &startup.StartupInfo,
            &mut process,
        )
    };
    if ok == 0 {
        return Err(last_error("CreateProcessW"));
    }
    let process_handle = Owned(process.hProcess);
    let thread_handle = Owned(process.hThread);
    let output_handle = SendHandle(output_read.into_raw());
    let reader = std::thread::spawn(move || output_handle.read());
    std::thread::sleep(std::time::Duration::from_millis(150));
    let payload = input.as_bytes();
    let mut written = 0u32;
    if !payload.is_empty()
        && unsafe {
            WriteFile(
                input_write.0,
                payload.as_ptr(),
                u32::try_from(payload.len()).unwrap_or(u32::MAX),
                &mut written,
                ptr::null_mut(),
            )
        } == 0
    {
        unsafe { TerminateProcess(process_handle.0, 1) };
        return Err(last_error("WriteFile"));
    }
    let waited = unsafe { WaitForSingleObject(process_handle.0, 30_000) };
    if waited != WAIT_OBJECT_0 {
        unsafe { TerminateProcess(process_handle.0, 1) };
        drop(output_write);
        drop(pseudo);
        let _ = reader.join();
        return Err(PlatformError::Io(
            "console process did not exit within 30 seconds".to_owned(),
        ));
    }
    drop(input_write);
    drop(input_read);
    drop(output_write);
    drop(pseudo);
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(process_handle.0, &mut exit_code) } == 0 {
        let _ = reader.join();
        return Err(last_error("GetExitCodeProcess"));
    }
    drop(thread_handle);
    drop(process_handle);
    let output = reader.join().unwrap_or(Ok(Vec::new()))?;
    Ok(ConsoleCapture { exit_code, output })
}

struct SendHandle(HANDLE);

unsafe impl Send for SendHandle {}

impl SendHandle {
    fn read(self) -> Result<Vec<u8>, PlatformError> {
        let bytes = read_all(self.0);
        unsafe { CloseHandle(self.0) };
        bytes
    }
}

struct Owned(HANDLE);

impl Owned {
    fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct Pseudo(HPCON);

impl Drop for Pseudo {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { ClosePseudoConsole(self.0) };
        }
    }
}

struct AttributeList {
    ptr: *mut u8,
    layout: std::alloc::Layout,
    ready: bool,
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            if self.ready {
                DeleteProcThreadAttributeList(self.ptr.cast());
            }
            std::alloc::dealloc(self.ptr, self.layout);
        }
    }
}

fn bind_console(list: &AttributeList, console: HPCON) -> Result<(), PlatformError> {
    // The process attribute stores the HPCON value itself. The handle must stay open
    // until CreateProcess returns; the caller owns that handle.
    if unsafe {
        UpdateProcThreadAttribute(
            list.ptr.cast(),
            0,
            usize::try_from(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE).unwrap_or(0),
            console as *const std::ffi::c_void,
            size_of::<HPCON>(),
            ptr::null_mut(),
            ptr::null(),
        )
    } == 0
    {
        return Err(last_error("UpdateProcThreadAttribute"));
    }
    Ok(())
}

fn attribute_list() -> Result<AttributeList, PlatformError> {
    let mut bytes = 0usize;
    unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes) };
    if bytes == 0 {
        return Err(last_error("InitializeProcThreadAttributeList"));
    }
    let layout = std::alloc::Layout::from_size_align(bytes, 16)
        .map_err(|_| PlatformError::Io("attribute list alignment was rejected".to_owned()))?;
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(PlatformError::Io(
            "attribute list allocation failed".to_owned(),
        ));
    }
    let mut list = AttributeList {
        ptr,
        layout,
        ready: false,
    };
    if unsafe { InitializeProcThreadAttributeList(list.ptr.cast(), 1, 0, &mut bytes) } == 0 {
        return Err(last_error("InitializeProcThreadAttributeList"));
    }
    list.ready = true;
    Ok(list)
}

fn read_all(handle: HANDLE) -> Result<Vec<u8>, PlatformError> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let mut got = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(u32::MAX),
                &mut got,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            if code == 0 || code == 38 || code == 109 {
                break;
            }
            return Err(PlatformError::Io(format!("ReadFile failed: {code}")));
        }
        if got == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..usize::try_from(got).unwrap_or(0)]);
    }
    Ok(output)
}

fn command_line(program: &Path, args: &[OsString]) -> String {
    let mut line = String::new();
    push_quoted(&mut line, &program.to_string_lossy());
    for arg in args {
        push_quoted(&mut line, &arg.to_string_lossy());
    }
    line
}

fn push_quoted(out: &mut String, arg: &str) {
    if !out.is_empty() {
        out.push(' ');
    }
    out.push('"');
    let mut slashes = 0u32;
    for ch in arg.chars() {
        if ch == '\\' {
            slashes = slashes.saturating_add(1);
            continue;
        }
        if ch == '"' {
            for _ in 0..slashes.saturating_mul(2).saturating_add(1) {
                out.push('\\');
            }
            out.push('"');
            slashes = 0;
            continue;
        }
        for _ in 0..slashes {
            out.push('\\');
        }
        slashes = 0;
        out.push(ch);
    }
    for _ in 0..slashes.saturating_mul(2) {
        out.push('\\');
    }
    out.push('"');
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

fn last_error(what: &str) -> PlatformError {
    let code = unsafe { GetLastError() };
    PlatformError::Io(format!("{what} failed: {code}"))
}
