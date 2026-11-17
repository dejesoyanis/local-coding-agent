//! LCA-01K publication experiments.
//!
//! This module is compiled only as a Windows unit test. `apply_ntfs` cannot call it:
//! the module is absent from the library that the agent links. Nothing here is a
//! second production publisher.
//!
//! Strategies:
//! - A: in-place `WriteFile` on a handle. The production case calls [`crate::OpenedTarget::replace_with`].
//! - B: staged file plus `MoveFileExW`.
//! - C: `ReplaceFileW`.
//! - D: `FileRenameInfoEx` with replace and POSIX flags.
//! - E: a file-id check followed by a later rename. No API takes the file id in the rename.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileRenameInformationEx, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD, ERROR_SHARING_VIOLATION,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, CreateHardLinkW, CreateSymbolicLinkW, DeleteFileW, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO, FILE_RENAME_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo,
    FileIdInfo, FileRenameInfoEx, FileStandardInfo, FlushFileBuffers, GetFileInformationByHandleEx,
    GetVolumeInformationW, MoveFileExW, OPEN_EXISTING, ReadFile, ReplaceFileW, SetEndOfFile,
    SetFileInformationByHandle, SetFilePointerEx, WriteFile,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use crate::{PlatformError, PublishPhase};

const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_ADD_FILE: u32 = 0x0002;
const FILE_DELETE_CHILD: u32 = 0x0040;
const FILE_TRAVERSE: u32 = 0x0020;
const FILE_WRITE_DATA: u32 = 0x0002;
const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT_NT: u32 = 0x0020_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x2;
const RENAME_EX_FLAGS: u32 = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
const SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE: u32 = 0x2;
const ORIGINAL: &[u8] = b"alpha\n";
const PROPOSED: &[u8] = b"beta\n";
const DECOY: &[u8] = b"decoy!\n";
const TORN: &[u8] = b"beta\n\n";

/// Conclusion of the experiments in this module. It is not itself the evidence.
const ARCHITECTURE_DECISION: &str = "not_established";

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(info: *mut OsVersion) -> i32;
}

#[repr(C)]
struct OsVersion {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform_id: u32,
    csd: [u16; 128],
    service_pack_major: u16,
    service_pack_minor: u16,
    suite_mask: u16,
    product_type: u8,
    reserved: u8,
}

struct Host {
    version: String,
    filesystem: String,
    flags: u32,
}

struct Owned(HANDLE);

impl Owned {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct Info {
    file_id: [u8; 16],
    links: u32,
    reparse: bool,
    delete_pending: u8,
}

struct Scratch {
    path: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("lca-01k-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("temp workspace");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn(spec: &Path, role: &str) -> Self {
        let child = Command::new(std::env::current_exe().expect("test exe"))
            .arg("publication_probe::publication_probe_child")
            .arg("--exact")
            .env(role, spec)
            .env_remove("LCA_01K_ATTACK")
            .env_remove("LCA_01K_KILL")
            .env(role, spec)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn probe child");
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("child").id()
    }

    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.0
            .as_mut()
            .expect("child")
            .try_wait()
            .expect("poll child")
    }

    fn wait(mut self) -> ExitStatus {
        self.0.take().expect("child").wait().expect("wait child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = Command::new("taskkill")
                .args(["/F", "/PID", &child.id().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = child.wait();
        }
    }
}

fn begin(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/lca-01k");
    fs::create_dir_all(&dir).expect("evidence dir");
    let path = dir.join(format!("{test}.log"));
    fs::write(&path, b"").expect("truncate evidence");
    path
}

fn note(log: &Path, line: &str) {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().expect("evidence lock");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .expect("evidence");
    writeln!(file, "{line}").expect("evidence write");
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

fn host_of(path: &Path) -> Host {
    let mut info = OsVersion {
        size: u32::try_from(std::mem::size_of::<OsVersion>()).unwrap_or(0),
        major: 0,
        minor: 0,
        build: 0,
        platform_id: 0,
        csd: [0; 128],
        service_pack_major: 0,
        service_pack_minor: 0,
        suite_mask: 0,
        product_type: 0,
        reserved: 0,
    };
    let status = unsafe { RtlGetVersion(&mut info) };
    let version = if status == 0 {
        format!("{}.{}.{}", info.major, info.minor, info.build)
    } else {
        format!("rtl_status_{status:#x}")
    };
    let (filesystem, flags) = volume_of(path);
    Host {
        version,
        filesystem,
        flags,
    }
}

fn volume_of(path: &Path) -> (String, u32) {
    let display = path.to_string_lossy().replace('/', "\\");
    let root = if let Some(rest) = display.strip_prefix(r"\\?\") {
        rest.get(..2).map(|drive| format!("{drive}\\"))
    } else {
        display.get(..2).map(|drive| format!("{drive}\\"))
    };
    let Some(root) = root else {
        return ("unknown".to_owned(), 0);
    };
    let mut wide: Vec<u16> = OsStr::new(&root).encode_wide().collect();
    wide.push(0);
    let mut name = [0u16; 64];
    let mut flags = 0u32;
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if ok == 0 {
        return (format!("volume_error_{}", unsafe { GetLastError() }), 0);
    }
    let len = name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(name.len());
    (String::from_utf16_lossy(&name[..len]), flags)
}

fn host_line(log: &Path, path: &Path) {
    let host = host_of(path);
    note(
        log,
        &format!(
            "host windows={} filesystem={} volume_flags={:#x} decision={ARCHITECTURE_DECISION} power_loss=unproven",
            host.version, host.filesystem, host.flags
        ),
    );
}

fn single_component(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name.contains(['/', '\\', ':', '\0'])
        || name.chars().any(|character| character.is_control())
    {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name);
    let upper = stem.to_ascii_uppercase();
    if matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL") {
        return false;
    }
    let bytes = upper.as_bytes();
    if bytes.len() == 4
        && (bytes.starts_with(b"COM") || bytes.starts_with(b"LPT"))
        && bytes[3].is_ascii_digit()
        && bytes[3] != b'0'
    {
        return false;
    }
    true
}

fn wide(path: &Path) -> Vec<u16> {
    let mut units: Vec<u16> = OsStr::new(path).encode_wide().collect();
    units.push(0);
    units
}

fn sync_path(path: &Path) {
    if let Ok(file) = OpenOptions::new().read(true).open(path) {
        let _ = file.sync_all();
    }
}

fn class_small(bytes: Option<&[u8]>) -> &'static str {
    match bytes {
        None => "missing",
        Some(ORIGINAL) => "original",
        Some(PROPOSED) => "proposed",
        Some(DECOY) => "decoy",
        Some(TORN) => "torn",
        Some(_) => "other",
    }
}

fn describe_small(path: &Path) -> String {
    match fs::read(path) {
        Ok(bytes) => format!(
            "{} len={} sha256={}",
            class_small(Some(&bytes)),
            bytes.len(),
            sha256_hex(&bytes)
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "missing".to_owned(),
        Err(error) => format!("read_error_{}", error.raw_os_error().unwrap_or(0)),
    }
}

fn pattern(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fn write_spec(path: &Path, pairs: &[(&str, &str)]) {
    let mut body = String::new();
    for (key, value) in pairs {
        body.push_str(key);
        body.push('=');
        body.push_str(value);
        body.push('\n');
    }
    fs::write(path, body).expect("spec");
}

fn read_spec(path: &Path) -> HashMap<String, String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut map = HashMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_owned(), value.to_owned());
        }
    }
    map
}

fn report(path: &Path, ok: bool, code: u32, detail: &str) {
    fs::write(
        path,
        format!("ok={}\ncode={code}\ndetail={detail}\n", u8::from(ok)),
    )
    .expect("report");
}

#[derive(Debug)]
struct Attack {
    ok: bool,
    code: u32,
    detail: String,
}

fn read_attack(path: &Path) -> Attack {
    let map = read_spec(path);
    Attack {
        ok: map.get("ok").map(String::as_str) == Some("1"),
        code: map
            .get("code")
            .and_then(|value| value.parse().ok())
            .unwrap_or(u32::MAX),
        detail: map
            .get("detail")
            .cloned()
            .unwrap_or_else(|| "absent".to_owned()),
    }
}

fn wait_file(path: &Path, child: &mut ChildGuard) -> bool {
    let started = Instant::now();
    while !path.exists() {
        if child.try_wait().is_some() {
            return false;
        }
        if started.elapsed() > Duration::from_secs(30) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    true
}

fn open_dir(path: &Path) -> Result<Owned, String> {
    let wide = wide(path);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_DELETE_CHILD
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("dir_open_{}", unsafe { GetLastError() }));
    }
    Ok(Owned(handle))
}

fn nt_open(
    parent: HANDLE,
    name: &str,
    access: u32,
    share: u32,
    disposition: u32,
) -> Result<Owned, String> {
    if !single_component(name) {
        return Err("rejected_component".to_owned());
    }
    let mut name_buf: Vec<u16> = name.encode_utf16().collect();
    let byte_len = u16::try_from(name_buf.len().saturating_mul(2)).unwrap_or(u16::MAX);
    let unicode = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: name_buf.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(0),
        RootDirectory: parent,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut io = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::zeroed();
    let mut handle: HANDLE = ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            io.as_mut_ptr(),
            ptr::null_mut(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            FILE_NON_DIRECTORY_FILE
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT_NT
                | FILE_OPEN_FOR_BACKUP_INTENT,
            ptr::null_mut(),
            0,
        )
    };
    if status < 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("nt={status:#x}"));
    }
    Ok(Owned(handle))
}

fn query(handle: HANDLE) -> Result<Info, String> {
    let mut identity = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: windows_sys::Win32::Storage::FileSystem::FILE_ID_128 {
            Identifier: [0; 16],
        },
    };
    let mut standard = FILE_STANDARD_INFO {
        AllocationSize: 0,
        EndOfFile: 0,
        NumberOfLinks: 0,
        DeletePending: 0,
        Directory: 0,
    };
    let mut tag = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    let id_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(0),
        )
    };
    let standard_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).unwrap_or(0),
        )
    };
    let tag_ok = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(0),
        )
    };
    if id_ok == 0 || standard_ok == 0 || tag_ok == 0 {
        return Err(format!("query_{}", unsafe { GetLastError() }));
    }
    Ok(Info {
        file_id: identity.FileId.Identifier,
        links: standard.NumberOfLinks,
        reparse: tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        delete_pending: standard.DeletePending,
    })
}

fn rewind(handle: HANDLE) -> Result<(), u32> {
    let ok = unsafe { SetFilePointerEx(handle, 0, ptr::null_mut(), 0) };
    if ok == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

fn write_handle(handle: HANDLE, bytes: &[u8]) -> Result<(), u32> {
    rewind(handle)?;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let chunk = (bytes.len() - offset).min(64 * 1024);
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                bytes[offset..].as_ptr().cast(),
                chunk as u32,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok == 0 || written == 0 {
            return Err(unsafe { GetLastError() });
        }
        offset += written as usize;
    }
    Ok(())
}

fn set_len(handle: HANDLE, len: u64) -> Result<(), u32> {
    let end = i64::try_from(len).map_err(|_| 87u32)?;
    let moved = unsafe { SetFilePointerEx(handle, end, ptr::null_mut(), 0) };
    if moved == 0 {
        return Err(unsafe { GetLastError() });
    }
    let truncated = unsafe { SetEndOfFile(handle) };
    if truncated == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

fn flush_handle(handle: HANDLE) -> Result<(), u32> {
    let ok = unsafe { FlushFileBuffers(handle) };
    if ok == 0 {
        Err(unsafe { GetLastError() })
    } else {
        Ok(())
    }
}

fn read_handle(handle: HANDLE) -> Result<Vec<u8>, u32> {
    rewind(handle)?;
    let mut collected = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(unsafe { GetLastError() });
        }
        if read == 0 {
            break;
        }
        collected.extend_from_slice(&buffer[..read as usize]);
    }
    Ok(collected)
}

fn publish_inplace(handle: HANDLE, bytes: &[u8]) -> Result<(), u32> {
    write_handle(handle, bytes)?;
    set_len(handle, bytes.len() as u64)?;
    flush_handle(handle)
}

fn move_file(from: &Path, to: &Path, flags: u32) -> u32 {
    let from = wide(from);
    let to = wide(to);
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), flags) };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn replace_file(replaced: &Path, replacement: &Path, backup: Option<&Path>, flags: u32) -> u32 {
    let replaced = wide(replaced);
    let replacement = wide(replacement);
    let backup_buf = backup.map(wide);
    let backup_ptr = backup_buf
        .as_ref()
        .map(|buf| buf.as_ptr())
        .unwrap_or(ptr::null());
    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            backup_ptr,
            flags,
            ptr::null(),
            ptr::null(),
        )
    };
    if ok == 0 {
        unsafe { GetLastError() }
    } else {
        0
    }
}

fn posix_replace(
    staged: HANDLE,
    parent: HANDLE,
    directory: &Path,
    name: &str,
) -> Result<(), String> {
    let full = directory.join(name).to_string_lossy().to_string();
    let forms = [
        (parent, name.to_owned()),
        (ptr::null_mut(), full.clone()),
        (ptr::null_mut(), format!(r"\\?\{full}")),
    ];
    let mut notes = Vec::new();
    for (root, form) in forms {
        for null_terminated in [false, true] {
            let mut wide: Vec<u16> = form.encode_utf16().collect();
            let chars = wide.len();
            if null_terminated {
                wide.push(0);
            }
            let name_at = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
            let root_at = std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory);
            let len_at = std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength);
            let mut buffer = vec![0u8; name_at + wide.len() * 2 + 8];
            buffer[..4].copy_from_slice(&RENAME_EX_FLAGS.to_le_bytes());
            let root_bytes = (root as usize).to_le_bytes();
            let root_len = std::mem::size_of::<HANDLE>();
            buffer[root_at..root_at + root_len].copy_from_slice(&root_bytes[..root_len]);
            let nbytes = u32::try_from(chars * 2).unwrap_or(0);
            buffer[len_at..len_at + 4].copy_from_slice(&nbytes.to_le_bytes());
            for (index, unit) in wide.iter().enumerate() {
                let at = name_at + index * 2;
                buffer[at..at + 2].copy_from_slice(&unit.to_le_bytes());
            }
            let win32 = unsafe {
                SetFileInformationByHandle(
                    staged,
                    FileRenameInfoEx,
                    buffer.as_ptr().cast(),
                    u32::try_from(name_at + wide.len() * 2).unwrap_or(0),
                )
            };
            if win32 != 0 {
                return Ok(());
            }
            let win32_error = unsafe { GetLastError() };
            let mut io = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::zeroed();
            let status = unsafe {
                NtSetInformationFile(
                    staged,
                    io.as_mut_ptr(),
                    buffer.as_ptr().cast(),
                    u32::try_from(name_at + wide.len() * 2).unwrap_or(0),
                    FileRenameInformationEx,
                )
            };
            notes.push(format!(
                "null={null_terminated} win32={win32_error} nt={status:#x}"
            ));
            if status >= 0 {
                return Ok(());
            }
        }
    }
    Err(notes.join(" | "))
}

fn stage_file(parent: HANDLE, name: &str, bytes: &[u8]) -> Result<(Owned, Info), String> {
    let handle = nt_open(
        parent,
        name,
        DELETE | FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_CREATE,
    )?;
    write_handle(handle.raw(), bytes).map_err(|code| format!("stage_write_{code}"))?;
    flush_handle(handle.raw()).map_err(|code| format!("stage_flush_{code}"))?;
    let info = query(handle.raw())?;
    Ok((handle, info))
}

fn denial(code: u32) -> bool {
    code == ERROR_SHARING_VIOLATION || code == ERROR_ACCESS_DENIED
}

fn shares() -> &'static [(u32, &'static str)] {
    &[
        (0, "none"),
        (FILE_SHARE_READ, "read"),
        (FILE_SHARE_READ | FILE_SHARE_WRITE, "read_write"),
        (FILE_SHARE_READ | FILE_SHARE_DELETE, "read_delete"),
        (
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            "read_write_delete",
        ),
    ]
}

fn run_attack(spec_path: &Path) -> ! {
    let spec = read_spec(spec_path);
    let ready = PathBuf::from(spec["ready"].clone());
    let started = Instant::now();
    while !ready.exists() {
        if started.elapsed() > Duration::from_secs(30) {
            report(&PathBuf::from(&spec["report"]), false, 0, "timeout");
            let _ = fs::write(&spec["done"], b"done");
            std::process::exit(4);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let workspace = PathBuf::from(spec["workspace"].clone());
    let target = workspace.join(&spec["target"]);
    let report_path = PathBuf::from(spec["report"].clone());
    let (ok, code, detail) = match spec["op"].as_str() {
        "rename" => {
            let code = move_file(&target, &workspace.join("moved-away.txt"), 0);
            (
                code == 0,
                code,
                if code == 0 { "renamed" } else { "denied" },
            )
        }
        "swap" => {
            let code = move_file(&target, &workspace.join("moved-away.txt"), 0);
            if code == 0 {
                match fs::write(&target, DECOY) {
                    Ok(()) => (true, 0, "swapped"),
                    Err(error) => (
                        false,
                        error.raw_os_error().unwrap_or(0) as u32,
                        "recreate_failed",
                    ),
                }
            } else {
                (false, code, "denied")
            }
        }
        "delete_recreate" => {
            let wide = wide(&target);
            let deleted = unsafe { DeleteFileW(wide.as_ptr()) };
            let code = if deleted == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            if code == 0 {
                match fs::write(&target, DECOY) {
                    Ok(()) => (true, 0, "recreated"),
                    Err(error) => (
                        false,
                        error.raw_os_error().unwrap_or(0) as u32,
                        "recreate_failed",
                    ),
                }
            } else {
                (false, code, "denied")
            }
        }
        "replace" => {
            let code = move_file(
                &workspace.join("other.txt"),
                &target,
                MOVEFILE_REPLACE_EXISTING,
            );
            (
                code == 0,
                code,
                if code == 0 { "replaced" } else { "denied" },
            )
        }
        "hardlink" => {
            let link = wide(&PathBuf::from(&spec["link"]));
            let existing = wide(&target);
            let created = unsafe { CreateHardLinkW(link.as_ptr(), existing.as_ptr(), ptr::null()) };
            let code = if created == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            (code == 0, code, if code == 0 { "linked" } else { "denied" })
        }
        "parent_rename" => {
            let code = move_file(
                &PathBuf::from(&spec["from"]),
                &PathBuf::from(&spec["to"]),
                0,
            );
            (
                code == 0,
                code,
                if code == 0 { "renamed" } else { "denied" },
            )
        }
        "symlink" => {
            let link = wide(&PathBuf::from(&spec["link"]));
            let dest = wide(&PathBuf::from(&spec["dest"]));
            let created = unsafe {
                CreateSymbolicLinkW(
                    link.as_ptr(),
                    dest.as_ptr(),
                    SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
                )
            };
            let code = if created == 0 {
                unsafe { GetLastError() }
            } else {
                0
            };
            (
                code == 0,
                code,
                if code == 0 { "created" } else { "denied" },
            )
        }
        "junction" => {
            let output = Command::new("cmd")
                .args(["/c", "mklink", "/J", &spec["link"], &spec["dest"]])
                .output();
            match output {
                Ok(output) if output.status.success() => (true, 0, "created"),
                Ok(output) => (
                    false,
                    output.status.code().unwrap_or(1) as u32,
                    "cmd_failed",
                ),
                Err(error) => (
                    false,
                    error.raw_os_error().unwrap_or(0) as u32,
                    "cmd_spawn_failed",
                ),
            }
        }
        other => (false, 0, other),
    };
    let detail = if detail.len() > 40 { "detail" } else { detail };
    report(&report_path, ok, code, detail);
    let _ = fs::write(&spec["done"], b"done");
    std::process::exit(0);
}

fn attack_sync(scratch: &Path, pairs: &[(&str, &str)]) -> Attack {
    let spec = scratch.join("attack-spec.txt");
    let ready = scratch.join("attack-ready");
    let done = scratch.join("attack-done");
    let report_path = scratch.join("attack-report.txt");
    let _ = fs::remove_file(&ready);
    let _ = fs::remove_file(&done);
    let _ = fs::remove_file(&report_path);
    let mut fields = vec![
        ("workspace", scratch.to_str().unwrap_or("")),
        ("ready", ready.to_str().unwrap_or("")),
        ("done", done.to_str().unwrap_or("")),
        ("report", report_path.to_str().unwrap_or("")),
    ];
    fields.extend_from_slice(pairs);
    write_spec(&spec, &fields);
    let mut child = ChildGuard::spawn(&spec, "LCA_01K_ATTACK");
    fs::write(&ready, b"go").expect("ready");
    sync_path(&ready);
    let arrived = wait_file(&done, &mut child);
    let status = child.wait();
    assert!(arrived, "attacker did not finish");
    assert!(status.success(), "attacker process failed");
    read_attack(&report_path)
}

fn park(ready: &Path) -> ! {
    fs::write(ready, b"ready").expect("ready");
    sync_path(ready);
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(120) {
        std::thread::park_timeout(Duration::from_millis(200));
    }
    std::process::exit(3);
}

fn run_kill(spec_path: &Path) -> ! {
    let spec = read_spec(spec_path);
    let root = PathBuf::from(spec["workspace"].clone());
    let point = spec["point"].clone();
    let strategy = spec["strategy"].clone();
    let ready = PathBuf::from(spec["ready"].clone());
    let notes = root.join("notes.txt");
    let info = crate::inspect(&notes).unwrap_or_else(|error| {
        let _ = fs::write(&spec["error"], error.to_string());
        std::process::exit(4);
    });
    let evidence = format!(
        "strategy={strategy}\npoint={point}\noriginal_id={}\noriginal_hash={}\nproposed_hash={}\n",
        hex_encode(&info.file_id()),
        sha256_hex(ORIGINAL),
        sha256_hex(PROPOSED)
    );
    let evidence_path = root.join("evidence.txt");
    fs::write(&evidence_path, &evidence).expect("evidence");
    sync_path(&evidence_path);
    fs::write(root.join("token.txt"), b"single-use").expect("token");
    sync_path(&root.join("token.txt"));
    let result = match strategy.as_str() {
        "A" => kill_a(&root, &point, &ready),
        "B" => kill_b(&root, &point, &ready),
        "C" => kill_c(&root, &point, &ready),
        "D" => kill_d(&root, &point, &ready),
        other => Err(format!("unknown_{other}")),
    };
    if let Err(error) = result {
        let _ = fs::write(&spec["error"], error);
        std::process::exit(4);
    }
    std::process::exit(0);
}

fn kill_a(root: &Path, point: &str, ready: &Path) -> Result<(), String> {
    if point == "before_staging" {
        park(ready);
    }
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(root, &components).map_err(|error| error.to_string())?;
    let point_owned = point.to_owned();
    let ready_owned = ready.to_owned();
    let replaced = opened.replace_with(PROPOSED, root, &components, &mut |phase| {
        let hit = matches!(
            (phase, point_owned.as_str()),
            (PublishPhase::AfterWrite, "after_staging")
                | (PublishPhase::AfterStageFlush, "after_flush")
                | (PublishPhase::BeforeRename, "before_publication")
                | (PublishPhase::DuringPublish, "during_publication")
                | (PublishPhase::BeforeFlush, "before_flush")
                | (PublishPhase::AfterRename, "after_publication")
                | (PublishPhase::BeforeReadback, "before_verification")
        );
        if hit {
            park(&ready_owned);
        }
        Ok(())
    });
    if point == "before_audit" {
        replaced.map_err(|failure| failure.error().to_string())?;
        park(ready);
    }
    Err(format!("point_not_hit_{point}:{replaced:?}"))
}

fn kill_b(root: &Path, point: &str, ready: &Path) -> Result<(), String> {
    if point == "before_staging" {
        park(ready);
    }
    let staged = root.join("staged.tmp");
    fs::write(&staged, PROPOSED).map_err(|error| error.to_string())?;
    if point == "after_staging" {
        park(ready);
    }
    sync_path(&staged);
    if point == "after_flush" || point == "before_publication" {
        park(ready);
    }
    let code = move_file(
        &staged,
        &root.join("notes.txt"),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    );
    if code != 0 {
        return Err(format!("movefile_{code}"));
    }
    if point == "after_publication" || point == "before_verification" || point == "before_audit" {
        park(ready);
    }
    Err(format!("point_not_hit_{point}"))
}

fn kill_c(root: &Path, point: &str, ready: &Path) -> Result<(), String> {
    if point == "before_staging" {
        park(ready);
    }
    let staged = root.join("staged.tmp");
    fs::write(&staged, PROPOSED).map_err(|error| error.to_string())?;
    if point == "after_staging" {
        park(ready);
    }
    sync_path(&staged);
    if point == "after_flush" || point == "before_publication" {
        park(ready);
    }
    let code = replace_file(
        &root.join("notes.txt"),
        &staged,
        Some(&root.join("notes.bak")),
        0,
    );
    if code != 0 {
        return Err(format!("replacefile_{code}"));
    }
    if point == "after_publication" || point == "before_verification" || point == "before_audit" {
        park(ready);
    }
    Err(format!("point_not_hit_{point}"))
}

fn kill_d(root: &Path, point: &str, ready: &Path) -> Result<(), String> {
    if point == "before_staging" {
        park(ready);
    }
    let parent = open_dir(root)?;
    let (staged, _) = stage_file(parent.raw(), "staged.tmp", PROPOSED)?;
    if point == "after_staging" || point == "after_flush" || point == "before_publication" {
        park(ready);
    }
    posix_replace(staged.raw(), parent.raw(), root, "notes.txt")?;
    if point == "after_publication" || point == "before_verification" || point == "before_audit" {
        park(ready);
    }
    Err(format!("point_not_hit_{point}"))
}

#[test]
fn publication_probe_child() {
    if let Ok(path) = std::env::var("LCA_01K_ATTACK") {
        run_attack(Path::new(&path));
    }
    if let Ok(path) = std::env::var("LCA_01K_KILL") {
        run_kill(Path::new(&path));
    }
}

#[test]
fn architecture_gate_does_not_select_a_new_publisher() {
    if std::env::var_os("LCA_01K_ATTACK").is_some() || std::env::var_os("LCA_01K_KILL").is_some() {
        return;
    }
    assert_eq!(ARCHITECTURE_DECISION, "not_established");
    let scratch = Scratch::new("gate");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let before = crate::inspect(&scratch.path().join("notes.txt")).unwrap();
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    let readback = opened
        .replace_with(PROPOSED, scratch.path(), &components, &mut |_| Ok(()))
        .expect("production publish");
    assert_eq!(readback, PROPOSED);
    let after = crate::inspect(&scratch.path().join("notes.txt")).unwrap();
    assert_eq!(after.file_id(), before.file_id());
    assert_ne!(before.file_id(), [0; 16]);
}

#[test]
fn experiment_a_target_identity() {
    if std::env::var_os("LCA_01K_ATTACK").is_some() || std::env::var_os("LCA_01K_KILL").is_some() {
        return;
    }
    let log = begin("experiment_a");
    let scratch = Scratch::new("host");
    host_line(&log, scratch.path());
    uncontended(&log);
    for (share, name) in shares() {
        for attack in ["rename", "swap"] {
            identity_case(&log, "A", *share, name, attack);
            identity_case(&log, "D", *share, name, attack);
        }
    }
    held_api(&log, "B");
    held_api(&log, "C");
}

fn uncontended(log: &Path) {
    let scratch = Scratch::new("base-a");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let before = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    opened
        .replace_with(PROPOSED, scratch.path(), &components, &mut |_| Ok(()))
        .unwrap();
    let after = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    assert_eq!(before, after);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        PROPOSED
    );
    note(
        log,
        &format!(
            "strategy=A mode=uncontended api=OpenedTarget::replace_with share=0x1 flags=WriteFile+SetEndOfFile+FlushFileBuffers original_id={} result_id={} path=proposed result=binding_held atomic_proven=false power_loss=unproven",
            hex_encode(&before),
            hex_encode(&after)
        ),
    );

    let scratch = Scratch::new("base-b");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    fs::write(scratch.path().join("staged.tmp"), PROPOSED).unwrap();
    sync_path(&scratch.path().join("staged.tmp"));
    let before = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let staged = crate::inspect(&scratch.path().join("staged.tmp"))
        .unwrap()
        .file_id();
    let code = move_file(
        &scratch.path().join("staged.tmp"),
        &scratch.path().join("notes.txt"),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    );
    assert_eq!(code, 0, "MoveFileEx {code}");
    let after = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    assert_eq!(after, staged);
    assert_ne!(after, before);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        PROPOSED
    );
    note(
        log,
        &format!(
            "strategy=B mode=uncontended api=MoveFileExW flags=0x9 share=none original_id={} staged_id={} result_id={} path=proposed result=file_id_changed atomic_proven=false power_loss=unproven",
            hex_encode(&before),
            hex_encode(&staged),
            hex_encode(&after)
        ),
    );

    let scratch = Scratch::new("base-c");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    fs::write(scratch.path().join("staged.tmp"), PROPOSED).unwrap();
    let before = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let staged = crate::inspect(&scratch.path().join("staged.tmp"))
        .unwrap()
        .file_id();
    let code = replace_file(
        &scratch.path().join("notes.txt"),
        &scratch.path().join("staged.tmp"),
        Some(&scratch.path().join("notes.bak")),
        0,
    );
    assert_eq!(code, 0, "ReplaceFile {code}");
    let after = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let backup = crate::inspect(&scratch.path().join("notes.bak"))
        .unwrap()
        .file_id();
    assert_eq!(after, staged);
    assert_eq!(backup, before);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        PROPOSED
    );
    assert_eq!(
        fs::read(scratch.path().join("notes.bak")).unwrap(),
        ORIGINAL
    );
    note(
        log,
        &format!(
            "strategy=C mode=uncontended api=ReplaceFileW flags=0x0 share=none original_id={} staged_id={} result_id={} backup_id={} path=proposed backup=original result=file_id_changed atomic_proven=false power_loss=unproven",
            hex_encode(&before),
            hex_encode(&staged),
            hex_encode(&after),
            hex_encode(&backup)
        ),
    );

    let scratch = Scratch::new("base-c-wt");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    fs::write(scratch.path().join("staged.tmp"), PROPOSED).unwrap();
    let code = replace_file(
        &scratch.path().join("notes.txt"),
        &scratch.path().join("staged.tmp"),
        Some(&scratch.path().join("notes.bak")),
        1,
    );
    note(
        log,
        &format!(
            "strategy=C mode=write_through api=ReplaceFileW flags=0x1 code={code} result=flag_observed power_loss=unproven documented_support=not_supported"
        ),
    );

    let scratch = Scratch::new("base-d");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let parent = open_dir(scratch.path()).unwrap();
    let pinned = nt_open(
        parent.raw(),
        "notes.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .unwrap();
    let before = query(pinned.raw()).unwrap();
    let (staged, staged_info) = stage_file(parent.raw(), "staged.tmp", PROPOSED).unwrap();
    posix_replace(staged.raw(), parent.raw(), scratch.path(), "notes.txt").expect("posix");
    let pending = query(pinned.raw()).unwrap();
    assert_eq!(pending.file_id, before.file_id);
    assert_eq!(read_handle(pinned.raw()).unwrap(), ORIGINAL);
    assert_eq!(
        pending.delete_pending, 1,
        "old handle should be delete-pending"
    );
    drop(pinned);
    drop(staged);
    let now = crate::inspect(&scratch.path().join("notes.txt")).unwrap();
    assert_eq!(now.file_id(), staged_info.file_id);
    assert_ne!(now.file_id(), before.file_id);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        PROPOSED
    );
    note(
        log,
        &format!(
            "strategy=D mode=uncontended api=FileRenameInfoEx flags=0x{RENAME_EX_FLAGS:x} share=0x7 original_id={} staged_id={} result_id={} old_handle=original delete_pending=1 path=proposed result=handle_split atomic_proven=false power_loss=unproven file_id_compare_field=absent",
            hex_encode(&before.file_id),
            hex_encode(&staged_info.file_id),
            hex_encode(&now.file_id())
        ),
    );
}

fn identity_case(log: &Path, strategy: &str, share: u32, share_name: &str, attack: &str) {
    let scratch = Scratch::new("id");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let parent = open_dir(scratch.path()).unwrap();
    let held = nt_open(
        parent.raw(),
        "notes.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        share,
        FILE_OPEN,
    )
    .unwrap();
    let before = query(held.raw()).unwrap();
    assert!(!before.reparse);
    assert_eq!(before.links, 1);
    let staged = if strategy == "D" {
        Some(stage_file(parent.raw(), "staged.tmp", PROPOSED).unwrap())
    } else {
        None
    };
    let outcome = attack_sync(scratch.path(), &[("op", attack), ("target", "notes.txt")]);
    let allows_delete = share & FILE_SHARE_DELETE != 0;
    if allows_delete {
        assert!(
            outcome.ok,
            "{strategy} {share_name} {attack} did not land: {outcome:?}"
        );
    } else {
        assert!(
            denial(outcome.code),
            "{strategy} {share_name} {attack} code {}",
            outcome.code
        );
        assert!(!outcome.ok);
    }
    let publish = if strategy == "A" {
        publish_inplace(held.raw(), PROPOSED)
            .map(|_| "published".to_owned())
            .map_err(|code| code.to_string())
    } else {
        let (handle, _) = staged.expect("staged");
        match posix_replace(handle.raw(), parent.raw(), scratch.path(), "notes.txt") {
            Ok(()) => {
                drop(handle);
                Ok("published".to_owned())
            }
            Err(error) => Err(error),
        }
    };
    let handle_bytes = read_handle(held.raw()).ok();
    let handle_id = query(held.raw()).map(|info| info.file_id).ok();
    drop(held);
    drop(parent);
    let path_class = describe_small(&scratch.path().join("notes.txt"));
    let moved_class = describe_small(&scratch.path().join("moved-away.txt"));
    let security = if !allows_delete {
        assert_eq!(handle_id, Some(before.file_id));
        if strategy == "A" {
            assert!(
                publish.is_ok(),
                "{strategy} publish while pinned: {publish:?}"
            );
            assert_eq!(
                fs::read(scratch.path().join("notes.txt")).unwrap(),
                PROPOSED
            );
            assert_eq!(
                crate::inspect(&scratch.path().join("notes.txt"))
                    .unwrap()
                    .file_id(),
                before.file_id
            );
            "binding_held"
        } else {
            assert!(
                publish.is_err(),
                "posix replace should fail without share-delete"
            );
            assert_eq!(
                fs::read(scratch.path().join("notes.txt")).unwrap(),
                ORIGINAL
            );
            "publication_blocked"
        }
    } else if strategy == "A" {
        assert!(publish.is_ok());
        assert_eq!(handle_id, Some(before.file_id));
        assert_eq!(handle_bytes.as_deref(), Some(PROPOSED));
        let path_bytes = fs::read(scratch.path().join("notes.txt")).ok();
        assert_ne!(path_bytes.as_deref(), Some(PROPOSED));
        "violation"
    } else {
        assert!(publish.is_ok(), "{publish:?}");
        let now = crate::inspect(&scratch.path().join("notes.txt")).unwrap();
        assert_ne!(now.file_id(), before.file_id);
        assert_eq!(
            fs::read(scratch.path().join("notes.txt")).unwrap(),
            PROPOSED
        );
        assert_eq!(
            fs::read(scratch.path().join("moved-away.txt")).unwrap(),
            ORIGINAL
        );
        "violation"
    };
    note(
        log,
        &format!(
            "strategy={strategy} attack={attack} share={share_name} share_mask={share:#x} attack_ok={} attack_code={} publish={} path={path_class} moved={moved_class} original_id={} result={security} power_loss=unproven",
            u8::from(outcome.ok),
            outcome.code,
            match &publish {
                Ok(_) => "ok".to_owned(),
                Err(error) => {
                    let text = error.replace(' ', "_");
                    if text.len() > 180 {
                        text[..180].to_owned()
                    } else {
                        text
                    }
                }
            },
            hex_encode(&before.file_id)
        ),
    );
}

fn held_api(log: &Path, strategy: &str) {
    let scratch = Scratch::new("held-api");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    fs::write(scratch.path().join("staged.tmp"), PROPOSED).unwrap();
    sync_path(&scratch.path().join("staged.tmp"));
    let before = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let parent = open_dir(scratch.path()).unwrap();
    let held = nt_open(
        parent.raw(),
        "notes.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ,
        FILE_OPEN,
    )
    .unwrap();
    let code = if strategy == "B" {
        move_file(
            &scratch.path().join("staged.tmp"),
            &scratch.path().join("notes.txt"),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } else {
        replace_file(
            &scratch.path().join("notes.txt"),
            &scratch.path().join("staged.tmp"),
            Some(&scratch.path().join("notes.bak")),
            0,
        )
    };
    assert!(
        denial(code),
        "{strategy} against exclusive handle returned {code}"
    );
    drop(held);
    let after = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    assert_eq!(before, after);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        ORIGINAL
    );
    note(
        log,
        &format!(
            "strategy={strategy} mode=exclusive_handle api_code={code} original_id={} result_id={} path=original result=publication_blocked power_loss=unproven",
            hex_encode(&before),
            hex_encode(&after)
        ),
    );
}

#[test]
fn experiment_b_concurrent_namespace() {
    if std::env::var_os("LCA_01K_ATTACK").is_some() || std::env::var_os("LCA_01K_KILL").is_some() {
        return;
    }
    let log = begin("experiment_b");
    let scratch = Scratch::new("hostb");
    host_line(&log, scratch.path());
    for op in ["rename", "swap", "delete_recreate", "replace"] {
        production_pause(&log, op);
    }
    parent_pause(&log);
    byte_lock_does_not_pin(&log);
    stress(&log, FILE_SHARE_READ, false);
    stress(&log, FILE_SHARE_READ | FILE_SHARE_DELETE, true);
}

fn production_pause(log: &Path, op: &str) {
    let scratch = Scratch::new("pause");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    if op == "replace" {
        fs::write(scratch.path().join("other.txt"), DECOY).unwrap();
    }
    let before = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let ready = scratch.path().join("attack-ready");
    let done = scratch.path().join("attack-done");
    let report_path = scratch.path().join("attack-report.txt");
    let spec = scratch.path().join("attack-spec.txt");
    write_spec(
        &spec,
        &[
            ("op", op),
            ("target", "notes.txt"),
            ("workspace", scratch.path().to_str().unwrap_or("")),
            ("ready", ready.to_str().unwrap_or("")),
            ("done", done.to_str().unwrap_or("")),
            ("report", report_path.to_str().unwrap_or("")),
        ],
    );
    let mut child = ChildGuard::spawn(&spec, "LCA_01K_ATTACK");
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    let mut child_died = false;
    let published = opened.replace_with(PROPOSED, scratch.path(), &components, &mut |phase| {
        if phase == PublishPhase::BeforeRename {
            fs::write(&ready, b"go").expect("ready");
            sync_path(&ready);
            let started = Instant::now();
            while !done.exists() {
                if child.try_wait().is_some() && !done.exists() {
                    child_died = true;
                    break;
                }
                if started.elapsed() > Duration::from_secs(30) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    });
    let status = child.wait();
    assert!(!child_died && done.exists(), "{op} attacker missing");
    assert!(status.success(), "{op}");
    let outcome = read_attack(&report_path);
    assert!(
        denial(outcome.code),
        "{op} broke the production pin: {outcome:?}"
    );
    assert!(!outcome.ok);
    let readback = published.expect("publish after denied attack");
    assert_eq!(readback, PROPOSED);
    let after = crate::inspect(&scratch.path().join("notes.txt")).unwrap();
    assert_eq!(after.file_id(), before);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        PROPOSED
    );
    note(
        log,
        &format!(
            "strategy=A-production op={op} attack_code={} attack_detail={} original_id={} result_id={} path=proposed result=binding_held formal_proof=false power_loss=unproven",
            outcome.code,
            outcome.detail,
            hex_encode(&before),
            hex_encode(&after.file_id())
        ),
    );
}

fn parent_pause(log: &Path) {
    let scratch = Scratch::new("parent");
    fs::create_dir(scratch.path().join("sub")).unwrap();
    fs::write(scratch.path().join("sub").join("notes.txt"), ORIGINAL).unwrap();
    let before = crate::inspect(&scratch.path().join("sub").join("notes.txt"))
        .unwrap()
        .file_id();
    let ready = scratch.path().join("attack-ready");
    let done = scratch.path().join("attack-done");
    let report_path = scratch.path().join("attack-report.txt");
    let spec = scratch.path().join("attack-spec.txt");
    write_spec(
        &spec,
        &[
            ("op", "parent_rename"),
            ("target", "notes.txt"),
            ("from", scratch.path().join("sub").to_str().unwrap_or("")),
            ("to", scratch.path().join("sub-old").to_str().unwrap_or("")),
            ("workspace", scratch.path().to_str().unwrap_or("")),
            ("ready", ready.to_str().unwrap_or("")),
            ("done", done.to_str().unwrap_or("")),
            ("report", report_path.to_str().unwrap_or("")),
        ],
    );
    let child = ChildGuard::spawn(&spec, "LCA_01K_ATTACK");
    let components = vec!["sub".to_owned(), "notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    let published = opened.replace_with(PROPOSED, scratch.path(), &components, &mut |phase| {
        if phase == PublishPhase::BeforeRename {
            fs::write(&ready, b"go").unwrap();
            sync_path(&ready);
            let started = Instant::now();
            while !done.exists() && started.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    });
    let _ = child.wait();
    let outcome = read_attack(&report_path);
    assert!(
        denial(outcome.code) && !outcome.ok,
        "parent move: {outcome:?}"
    );
    assert!(published.is_ok(), "{published:?}");
    assert_eq!(
        fs::read(scratch.path().join("sub").join("notes.txt")).unwrap(),
        PROPOSED
    );
    assert_eq!(
        crate::inspect(&scratch.path().join("sub").join("notes.txt"))
            .unwrap()
            .file_id(),
        before
    );
    note(
        log,
        &format!(
            "strategy=A-production op=parent_rename attack_code={} result=binding_held power_loss=unproven",
            outcome.code
        ),
    );
}

fn byte_lock_does_not_pin(log: &Path) {
    let scratch = Scratch::new("lock");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let parent = open_dir(scratch.path()).unwrap();
    let held = nt_open(
        parent.raw(),
        "notes.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .unwrap();
    let mut overlapped = windows_sys::Win32::System::IO::OVERLAPPED {
        Internal: 0,
        InternalHigh: 0,
        Anonymous: windows_sys::Win32::System::IO::OVERLAPPED_0 {
            Anonymous: windows_sys::Win32::System::IO::OVERLAPPED_0_0 {
                Offset: 0,
                OffsetHigh: 0,
            },
        },
        hEvent: ptr::null_mut(),
    };
    let locked = unsafe {
        windows_sys::Win32::Storage::FileSystem::LockFileEx(
            held.raw(),
            windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK
                | windows_sys::Win32::Storage::FileSystem::LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    assert_ne!(locked, 0, "lock {}", unsafe { GetLastError() });
    let outcome = attack_sync(scratch.path(), &[("op", "rename"), ("target", "notes.txt")]);
    assert!(
        outcome.ok,
        "byte lock unexpectedly pinned the name: {outcome:?}"
    );
    assert_eq!(read_handle(held.raw()).unwrap(), ORIGINAL);
    let locked_read = fs::read(scratch.path().join("moved-away.txt"));
    let locked_code = locked_read
        .as_ref()
        .err()
        .and_then(|error| error.raw_os_error())
        .unwrap_or(0);
    assert_eq!(locked_code, 33, "fresh read while the byte lock was held");
    drop(held);
    assert_eq!(
        fs::read(scratch.path().join("moved-away.txt")).unwrap(),
        ORIGINAL
    );
    assert!(!scratch.path().join("notes.txt").exists());
    note(
        log,
        &format!(
            "strategy=lock api=LockFileEx flags=LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY share=0x5 attack=rename attack_ok=1 fresh_read_code={locked_code} result=violation formal_proof=false power_loss=unproven"
        ),
    );
}

fn stress(log: &Path, share: u32, expect_win: bool) {
    let mut wins = 0u32;
    let mut denials = 0u32;
    for _ in 0..8 {
        let scratch = Scratch::new("stress");
        fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
        let parent = open_dir(scratch.path()).unwrap();
        let held = nt_open(
            parent.raw(),
            "notes.txt",
            FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
            share,
            FILE_OPEN,
        )
        .unwrap();
        let outcome = attack_sync(scratch.path(), &[("op", "rename"), ("target", "notes.txt")]);
        if outcome.ok {
            wins += 1;
        } else if denial(outcome.code) {
            denials += 1;
        }
        drop(held);
    }
    if expect_win {
        assert_eq!(wins, 8, "share-delete stress denials={denials}");
    } else {
        assert_eq!(wins, 0, "exclusive stress wins={wins}");
        assert_eq!(denials, 8);
    }
    note(
        log,
        &format!(
            "strategy=stress share={share:#x} rounds=8 wins={wins} denials={denials} formal_proof=false result={}",
            if expect_win {
                "violation"
            } else {
                "binding_held"
            }
        ),
    );
}

#[test]
fn experiment_c_atomic_visibility() {
    if std::env::var_os("LCA_01K_ATTACK").is_some() || std::env::var_os("LCA_01K_KILL").is_some() {
        return;
    }
    let log = begin("experiment_c");
    let scratch = Scratch::new("hostc");
    host_line(&log, scratch.path());
    for (label, size, equal) in [
        ("4KiB", 4 * 1024, false),
        ("4KiB-equal", 4 * 1024, true),
        ("64KiB", 64 * 1024, false),
        ("1MiB", 1024 * 1024, false),
        ("1MiB-equal", 1024 * 1024, true),
        ("8MiB", 8 * 1024 * 1024, false),
    ] {
        visibility_a(&log, label, size, equal);
    }
    for (label, size) in [
        ("4KiB", 4 * 1024),
        ("64KiB", 64 * 1024),
        ("1MiB", 1024 * 1024),
        ("8MiB", 8 * 1024 * 1024),
    ] {
        visibility_d(&log, label, size);
        visibility_b(&log, label, size);
        visibility_c(&log, label, size);
    }
}

fn classify_pattern(bytes: &[u8], original: &[u8], proposed: &[u8]) -> &'static str {
    if bytes == original {
        "original"
    } else if bytes == proposed {
        "proposed"
    } else {
        "mixed"
    }
}

fn visibility_a(log: &Path, label: &str, size: usize, equal: bool) {
    let scratch = Scratch::new("vis-a");
    let notes = scratch.path().join("notes.txt");
    let original = pattern(0x11, size);
    let proposed = pattern(0x22, if equal { size } else { size / 2 });
    fs::write(&notes, &original).unwrap();
    let before = crate::inspect(&notes).unwrap().file_id();
    let reader = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&notes)
        .unwrap();
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    let mut hook_mixed = 0u32;
    let mut hook_other = 0u32;
    let published = opened.replace_with(&proposed, scratch.path(), &components, &mut |phase| {
        if phase == PublishPhase::DuringPublish {
            for _ in 0..8 {
                let fresh = fs::read(&notes).expect("fresh read");
                let mut existing = reader.try_clone().expect("clone");
                existing.seek(SeekFrom::Start(0)).unwrap();
                let mut via = Vec::new();
                existing.read_to_end(&mut via).unwrap();
                let kind = classify_pattern(&fresh, &original, &proposed);
                if kind == "mixed" {
                    hook_mixed += 1;
                    assert_eq!(fresh.len(), original.len());
                    assert_eq!(fresh[0], 0x22);
                    assert_eq!(*fresh.last().unwrap(), 0x11);
                    assert_eq!(via, fresh);
                } else {
                    hook_other += 1;
                }
            }
        }
        Ok(())
    });
    assert!(published.is_ok(), "{label} {published:?}");
    assert_eq!(fs::read(&notes).unwrap(), proposed);
    assert_eq!(crate::inspect(&notes).unwrap().file_id(), before);
    let verdict = if hook_mixed > 0 {
        "mixed_observed"
    } else {
        "no_mixed_sample_not_a_proof"
    };
    if !equal || size > 64 * 1024 {
        assert_eq!(verdict, "mixed_observed", "{label} hook_other={hook_other}");
    }
    assert_ne!(verdict, "proven");
    note(
        log,
        &format!(
            "strategy=A size={label} equal={equal} api=OpenedTarget::replace_with share=0x1 hook_mixed={hook_mixed} hook_other={hook_other} original_id={} result_id={} final=proposed verdict={verdict} atomic_proven=false power_loss=unproven",
            hex_encode(&before),
            hex_encode(&before)
        ),
    );
}

fn visibility_d(log: &Path, label: &str, size: usize) {
    let scratch = Scratch::new("vis-d");
    let notes = scratch.path().join("notes.txt");
    let original = pattern(0x11, size);
    let proposed = pattern(0x22, size);
    fs::write(&notes, &original).unwrap();
    let parent = open_dir(scratch.path()).unwrap();
    let pinned = nt_open(
        parent.raw(),
        "notes.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .unwrap();
    let before = query(pinned.raw()).unwrap().file_id;
    let (staged, staged_info) = stage_file(parent.raw(), "staged.tmp", &proposed).unwrap();
    let samples = Arc::new(Mutex::new([0u32; 4]));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let path = notes.clone();
    let original_sample = original.clone();
    let proposed_sample = proposed.clone();
    let samples_thread = samples.clone();
    let stop_thread = stop.clone();
    let spinner = std::thread::spawn(move || {
        while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(bytes) = fs::read(&path) {
                let index = match classify_pattern(&bytes, &original_sample, &proposed_sample) {
                    "original" => 0,
                    "proposed" => 1,
                    _ => 2,
                };
                samples_thread.lock().expect("samples")[index] += 1;
            } else {
                samples_thread.lock().expect("samples")[3] += 1;
            }
        }
    });
    posix_replace(staged.raw(), parent.raw(), scratch.path(), "notes.txt").expect("posix");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    spinner.join().unwrap();
    let old = read_handle(pinned.raw()).unwrap();
    assert_eq!(old, original);
    drop(pinned);
    drop(staged);
    let fresh = fs::read(&notes).unwrap();
    assert_eq!(fresh, proposed);
    let now = crate::inspect(&notes).unwrap().file_id();
    assert_eq!(now, staged_info.file_id);
    assert_ne!(now, before);
    let counts = samples.lock().unwrap();
    let verdict = if counts[2] > 0 {
        "mixed_observed"
    } else {
        "no_mixed_sample_not_a_proof"
    };
    assert_ne!(verdict, "proven");
    note(
        log,
        &format!(
            "strategy=D size={label} api=FileRenameInfoEx flags=0x{RENAME_EX_FLAGS:x} share=0x7 existing_handle=original fresh_open=proposed spinner_original={} spinner_proposed={} spinner_mixed={} spinner_other={} original_id={} result_id={} verdict={verdict} atomic_proven=false power_loss=unproven",
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            hex_encode(&before),
            hex_encode(&now)
        ),
    );
}

fn sample_during(
    path: PathBuf,
    original: &[u8],
    proposed: &[u8],
    publish: impl FnOnce(),
) -> [u32; 4] {
    let samples = Arc::new(Mutex::new([0u32; 4]));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let original = original.to_vec();
    let proposed = proposed.to_vec();
    let samples_thread = samples.clone();
    let stop_thread = stop.clone();
    let spinner = std::thread::spawn(move || {
        let mut seen = 0u32;
        while !stop_thread.load(std::sync::atomic::Ordering::Relaxed) && seen < 32 {
            seen += 1;
            match fs::read(&path) {
                Ok(bytes) => {
                    let index = match classify_pattern(&bytes, &original, &proposed) {
                        "original" => 0,
                        "proposed" => 1,
                        _ => 2,
                    };
                    samples_thread.lock().expect("samples")[index] += 1;
                }
                Err(_) => samples_thread.lock().expect("samples")[3] += 1,
            }
        }
    });
    publish();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    spinner.join().expect("spinner");
    *samples.lock().expect("samples")
}

fn visibility_b(log: &Path, label: &str, size: usize) {
    let scratch = Scratch::new("vis-b");
    let notes = scratch.path().join("notes.txt");
    let original = pattern(0x11, size);
    let proposed = pattern(0x22, size);
    fs::write(&notes, &original).unwrap();
    let staged = scratch.path().join("staged.tmp");
    fs::write(&staged, &proposed).unwrap();
    sync_path(&staged);
    let before = crate::inspect(&notes).unwrap().file_id();
    let staged_id = crate::inspect(&staged).unwrap().file_id();
    let code = std::cell::Cell::new(1u32);
    let counts = sample_during(notes.clone(), &original, &proposed, || {
        code.set(move_file(
            &staged,
            &notes,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        ));
    });
    let first = code.get();
    if first != 0 {
        assert!(denial(first), "{label} MoveFileEx {first}");
        let retry = move_file(
            &staged,
            &notes,
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        );
        assert_eq!(retry, 0, "{label} MoveFileEx retry {retry}");
    }
    let now = crate::inspect(&notes).unwrap().file_id();
    assert_eq!(now, staged_id);
    assert_ne!(now, before);
    assert_eq!(fs::read(&notes).unwrap(), proposed);
    let verdict = if counts[2] > 0 {
        "mixed_observed"
    } else {
        "no_mixed_sample_not_a_proof"
    };
    assert_ne!(verdict, "proven");
    note(
        log,
        &format!(
            "strategy=B size={label} api=MoveFileExW flags=0x9 code={first} spinner_original={} spinner_proposed={} spinner_mixed={} spinner_other={} original_id={} result_id={} fresh_open=proposed verdict={verdict} atomic_proven=false power_loss=unproven",
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            hex_encode(&before),
            hex_encode(&now)
        ),
    );
}

fn visibility_c(log: &Path, label: &str, size: usize) {
    let scratch = Scratch::new("vis-c");
    let notes = scratch.path().join("notes.txt");
    let original = pattern(0x11, size);
    let proposed = pattern(0x22, size);
    fs::write(&notes, &original).unwrap();
    let staged = scratch.path().join("staged.tmp");
    fs::write(&staged, &proposed).unwrap();
    let before = crate::inspect(&notes).unwrap().file_id();
    let staged_id = crate::inspect(&staged).unwrap().file_id();
    let backup = scratch.path().join("notes.bak");
    let code = std::cell::Cell::new(1u32);
    let counts = sample_during(notes.clone(), &original, &proposed, || {
        code.set(replace_file(&notes, &staged, Some(&backup), 0));
    });
    let first = code.get();
    if first != 0 {
        assert!(denial(first), "{label} ReplaceFile {first}");
        let retry = replace_file(&notes, &staged, Some(&backup), 0);
        assert_eq!(retry, 0, "{label} ReplaceFile retry {retry}");
    }
    let now = crate::inspect(&notes).unwrap().file_id();
    assert_eq!(now, staged_id);
    assert_ne!(now, before);
    assert_eq!(fs::read(&notes).unwrap(), proposed);
    assert_eq!(fs::read(&backup).unwrap(), original);
    let verdict = if counts[2] > 0 {
        "mixed_observed"
    } else {
        "no_mixed_sample_not_a_proof"
    };
    assert_ne!(verdict, "proven");
    note(
        log,
        &format!(
            "strategy=C size={label} api=ReplaceFileW flags=0x0 code={first} spinner_original={} spinner_proposed={} spinner_mixed={} spinner_other={} original_id={} result_id={} fresh_open=proposed backup=original verdict={verdict} atomic_proven=false power_loss=unproven",
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            hex_encode(&before),
            hex_encode(&now)
        ),
    );
}

#[test]
fn experiment_d_process_kill() {
    if std::env::var_os("LCA_01K_ATTACK").is_some() || std::env::var_os("LCA_01K_KILL").is_some() {
        return;
    }
    let log = begin("experiment_d");
    let scratch = Scratch::new("hostd");
    host_line(&log, scratch.path());
    let points = [
        "before_staging",
        "after_staging",
        "after_flush",
        "before_publication",
        "during_publication",
        "before_flush",
        "after_publication",
        "before_verification",
        "before_audit",
    ];
    for strategy in ["A", "B", "C", "D"] {
        for point in points {
            if strategy != "A" && (point == "during_publication" || point == "before_flush") {
                note(
                    &log,
                    &format!(
                        "strategy={strategy} point={point} result=not_instrumentable power_loss=unproven retry=false"
                    ),
                );
                continue;
            }
            kill_case(&log, strategy, point);
        }
    }
}

fn kill_case(log: &Path, strategy: &str, point: &str) {
    let scratch = Scratch::new("kill");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let before = crate::inspect(&scratch.path().join("notes.txt"))
        .unwrap()
        .file_id();
    let spec = scratch.path().join("kill-spec.txt");
    let ready = scratch.path().join("kill-ready");
    let error_path = scratch.path().join("kill-error.txt");
    write_spec(
        &spec,
        &[
            ("strategy", strategy),
            ("point", point),
            ("workspace", scratch.path().to_str().unwrap_or("")),
            ("ready", ready.to_str().unwrap_or("")),
            ("error", error_path.to_str().unwrap_or("")),
        ],
    );
    let mut child = ChildGuard::spawn(&spec, "LCA_01K_KILL");
    let alive = wait_file(&ready, &mut child);
    if !alive {
        let detail = fs::read_to_string(&error_path).unwrap_or_default();
        panic!("{strategy} {point} exited before the hold: {detail}");
    }
    assert!(
        child.try_wait().is_none(),
        "{strategy} {point} exited early"
    );
    let killed = Command::new("taskkill")
        .args(["/F", "/PID", &child.id().to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("taskkill");
    assert!(killed.success(), "{strategy} {point} taskkill");
    let status = child.wait();
    assert!(!status.success(), "{strategy} {point} survived");
    let bytes = fs::read(scratch.path().join("notes.txt")).ok();
    let after = crate::inspect(&scratch.path().join("notes.txt")).ok();
    let same = after.as_ref().map(|info| info.file_id()) == Some(before);
    let class = match (bytes.as_deref(), same) {
        (Some(ORIGINAL), true) => "original_same_id",
        (Some(PROPOSED), true) => "proposed_same_id",
        (Some(PROPOSED), false) => "proposed_new_id",
        (Some(TORN), true) => "torn_same_id",
        (None, _) => "missing",
        _ => "other",
    };
    let expected = match (strategy, point) {
        ("A", "during_publication") => "torn_same_id",
        ("A", "before_flush" | "after_publication" | "before_verification" | "before_audit") => {
            "proposed_same_id"
        }
        ("A", _) => "original_same_id",
        (_, "after_publication" | "before_verification" | "before_audit") => "proposed_new_id",
        _ => "original_same_id",
    };
    assert_eq!(class, expected, "{strategy} {point}");
    let again = fs::read(scratch.path().join("notes.txt")).ok();
    assert_eq!(again, bytes, "{strategy} {point} changed after the kill");
    assert_eq!(
        fs::read(scratch.path().join("token.txt")).unwrap(),
        b"single-use"
    );
    let evidence = fs::read_to_string(scratch.path().join("evidence.txt")).unwrap();
    assert!(evidence.contains(&hex_encode(&before)), "{evidence}");
    assert!(!scratch.path().join("audit.marker").exists());
    assert!(!scratch.path().join("retried").exists());
    let result_id = after.map(|info| info.file_id()).unwrap_or([0; 16]);
    note(
        log,
        &format!(
            "strategy={strategy} point={point} class={class} original_id={} result_id={} token=single-use retry=false repair=false audit=absent power_loss=unproven",
            hex_encode(&before),
            hex_encode(&result_id)
        ),
    );
}

#[test]
fn experiment_e_reparse_hardlink_and_conditional_bind() {
    if std::env::var_os("LCA_01K_ATTACK").is_some() || std::env::var_os("LCA_01K_KILL").is_some() {
        return;
    }
    let log = begin("experiment_e");
    let scratch = Scratch::new("hoste");
    host_line(&log, scratch.path());
    protected_names(&log);
    hardlink_before_publish(&log);
    hardlink_during_publish(&log);
    junction_refused(&log);
    symlink_attempt(&log);
    conditional_bind(&log);
}

fn protected_names(log: &Path) {
    let scratch = Scratch::new("names");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    for name in ["CON", "NUL", "COM1", "notes.txt:stream", "..", "notes.txt "] {
        assert!(!single_component(name), "{name}");
        let opened = crate::open_tree(scratch.path(), &[name.to_owned()]);
        assert!(opened.is_err(), "{name} opened");
        note(
            log,
            &format!(
                "strategy=A-production op=protected_name name={name} result=rejected atomic_proven=false"
            ),
        );
    }
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        ORIGINAL
    );
}

fn hardlink_before_publish(log: &Path) {
    let scratch = Scratch::new("link-before");
    let notes = scratch.path().join("notes.txt");
    let alias = scratch.path().join("alias.txt");
    fs::write(&notes, ORIGINAL).unwrap();
    fs::hard_link(&notes, &alias).unwrap();
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    let error = opened
        .replace_with(PROPOSED, scratch.path(), &components, &mut |_| Ok(()))
        .expect_err("hardlink");
    assert!(!error.published());
    assert!(matches!(error.error(), PlatformError::Hardlink));
    assert_eq!(fs::read(&notes).unwrap(), ORIGINAL);
    assert_eq!(fs::read(&alias).unwrap(), ORIGINAL);
    note(
        log,
        "strategy=A-production op=hardlink_before result=publication_blocked published=false",
    );
}

fn hardlink_during_publish(log: &Path) {
    let scratch = Scratch::new("link-during");
    let outside = Scratch::new("link-outside");
    let notes = scratch.path().join("notes.txt");
    fs::write(&notes, ORIGINAL).unwrap();
    let before = crate::inspect(&notes).unwrap().file_id();
    let link = outside.path().join("alias.txt");
    let ready = scratch.path().join("attack-ready");
    let done = scratch.path().join("attack-done");
    let report_path = scratch.path().join("attack-report.txt");
    let spec = scratch.path().join("attack-spec.txt");
    write_spec(
        &spec,
        &[
            ("op", "hardlink"),
            ("target", "notes.txt"),
            ("link", link.to_str().unwrap_or("")),
            ("workspace", scratch.path().to_str().unwrap_or("")),
            ("ready", ready.to_str().unwrap_or("")),
            ("done", done.to_str().unwrap_or("")),
            ("report", report_path.to_str().unwrap_or("")),
        ],
    );
    let child = ChildGuard::spawn(&spec, "LCA_01K_ATTACK");
    let components = vec!["notes.txt".to_owned()];
    let mut opened = crate::open_tree(scratch.path(), &components).unwrap();
    let published = opened.replace_with(PROPOSED, scratch.path(), &components, &mut |phase| {
        if phase == PublishPhase::BeforeRename {
            fs::write(&ready, b"go").unwrap();
            sync_path(&ready);
            let started = Instant::now();
            while !done.exists() && started.elapsed() < Duration::from_secs(30) {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    });
    let _ = child.wait();
    let outcome = read_attack(&report_path);
    if outcome.ok {
        let alias = fs::read(&link).unwrap();
        assert_eq!(alias, PROPOSED);
        assert_eq!(crate::inspect(&link).unwrap().file_id(), before);
        let wrote = match &published {
            Ok(_) => true,
            Err(failure) => failure.published(),
        };
        assert!(wrote, "hardlink landed but the target was not published");
        note(
            log,
            &format!(
                "strategy=A-production op=hardlink_during attack_code=0 original_id={} outside=proposed result=violation power_loss=unproven",
                hex_encode(&before)
            ),
        );
    } else {
        assert!(denial(outcome.code), "{outcome:?}");
        assert!(published.is_ok(), "{published:?}");
        assert!(!link.exists());
        assert_eq!(fs::read(&notes).unwrap(), PROPOSED);
        note(
            log,
            &format!(
                "strategy=A-production op=hardlink_during attack_code={} result=binding_held power_loss=unproven",
                outcome.code
            ),
        );
    }
}

fn junction_refused(log: &Path) {
    let scratch = Scratch::new("junction");
    let outside = Scratch::new("junction-out");
    fs::write(outside.path().join("secret.txt"), b"sentinel-not-logged\n").unwrap();
    let link = scratch.path().join("link");
    let spec = scratch.path().join("attack-spec.txt");
    write_spec(
        &spec,
        &[
            ("op", "junction"),
            ("target", "unused"),
            ("link", link.to_str().unwrap_or("")),
            ("dest", outside.path().to_str().unwrap_or("")),
            ("workspace", scratch.path().to_str().unwrap_or("")),
            (
                "ready",
                scratch.path().join("attack-ready").to_str().unwrap_or(""),
            ),
            (
                "done",
                scratch.path().join("attack-done").to_str().unwrap_or(""),
            ),
            (
                "report",
                scratch
                    .path()
                    .join("attack-report.txt")
                    .to_str()
                    .unwrap_or(""),
            ),
        ],
    );
    fs::write(scratch.path().join("attack-ready"), b"go").unwrap();
    let child = ChildGuard::spawn(&spec, "LCA_01K_ATTACK");
    let status = child.wait();
    assert!(status.success());
    let outcome = read_attack(&scratch.path().join("attack-report.txt"));
    if outcome.ok {
        let opened = crate::open_tree(scratch.path(), &["link".to_owned()]);
        match &opened {
            Err(PlatformError::Reparse) => {}
            Err(error) => panic!("junction open {error}"),
            Ok(_) => panic!("junction was opened"),
        }
        assert_eq!(
            fs::read(outside.path().join("secret.txt")).unwrap(),
            b"sentinel-not-logged\n"
        );
        note(
            log,
            "strategy=A-production op=junction result=publication_blocked",
        );
    } else {
        note(
            log,
            &format!(
                "strategy=A-production op=junction code={} result=skipped",
                outcome.code
            ),
        );
    }
}

fn symlink_attempt(log: &Path) {
    let scratch = Scratch::new("symlink");
    let outside = Scratch::new("symlink-out");
    fs::write(outside.path().join("secret.txt"), b"sentinel-not-logged\n").unwrap();
    let link = scratch.path().join("link");
    let outcome = attack_sync(
        scratch.path(),
        &[
            ("op", "symlink"),
            ("target", "unused"),
            ("link", link.to_str().unwrap_or("")),
            (
                "dest",
                outside.path().join("secret.txt").to_str().unwrap_or(""),
            ),
        ],
    );
    if outcome.ok {
        let opened = crate::open_tree(scratch.path(), &["link".to_owned()]);
        match &opened {
            Err(PlatformError::Reparse) => {}
            Err(error) => panic!("symlink open {error}"),
            Ok(_) => panic!("symlink was opened"),
        }
        assert_eq!(
            fs::read(outside.path().join("secret.txt")).unwrap(),
            b"sentinel-not-logged\n"
        );
        note(
            log,
            "strategy=A-production op=symlink result=publication_blocked",
        );
    } else {
        assert!(
            outcome.code == ERROR_PRIVILEGE_NOT_HELD || outcome.code == ERROR_ACCESS_DENIED,
            "symlink code {}",
            outcome.code
        );
        assert!(!link.exists());
        note(
            log,
            &format!(
                "strategy=A-production op=symlink code={} result=skipped",
                outcome.code
            ),
        );
    }
}

fn conditional_bind(log: &Path) {
    let scratch = Scratch::new("cas");
    fs::write(scratch.path().join("notes.txt"), ORIGINAL).unwrap();
    let parent = open_dir(scratch.path()).unwrap();
    let held = nt_open(
        parent.raw(),
        "notes.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .unwrap();
    let checked = query(held.raw()).unwrap();
    let (staged, staged_info) = stage_file(parent.raw(), "staged.tmp", PROPOSED).unwrap();
    let again = query(held.raw()).unwrap();
    assert_eq!(again.file_id, checked.file_id);
    let outcome = attack_sync(scratch.path(), &[("op", "swap"), ("target", "notes.txt")]);
    assert!(
        outcome.ok,
        "swap before the rename did not land: {outcome:?}"
    );
    let publish = posix_replace(staged.raw(), parent.raw(), scratch.path(), "notes.txt");
    assert!(publish.is_ok(), "{publish:?}");
    let name = crate::inspect(&scratch.path().join("notes.txt")).unwrap();
    assert_ne!(name.file_id(), checked.file_id);
    assert_eq!(name.file_id(), staged_info.file_id);
    assert_eq!(
        fs::read(scratch.path().join("notes.txt")).unwrap(),
        PROPOSED
    );
    assert_eq!(read_handle(held.raw()).unwrap(), ORIGINAL);
    assert_eq!(
        fs::read(scratch.path().join("moved-away.txt")).unwrap(),
        ORIGINAL
    );
    drop(held);
    drop(staged);
    note(
        log,
        &format!(
            "strategy=E api=FileRenameInfoEx flags=0x{RENAME_EX_FLAGS:x} share=0x5 file_id_compare_field=absent checked_id={} result_id={} checked_handle=original path=proposed result=violation atomic_proven=false power_loss=unproven",
            hex_encode(&checked.file_id),
            hex_encode(&name.file_id())
        ),
    );
}
