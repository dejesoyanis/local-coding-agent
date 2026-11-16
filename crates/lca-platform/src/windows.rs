//! Windows file identity, relative opens, DPAPI, and owner-only ACLs.
//!
//! `unsafe` stays in this module. The exported functions do not take raw pointers.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileRenameInformation, NtCreateFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SHARING_VIOLATION, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    UNICODE_STRING,
};
use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData};
use windows_sys::Win32::Security::{
    ACL, AllocateAndInitializeSid, CopySid, EqualSid, FreeSid, GetLengthSid, GetTokenInformation,
    SID_IDENTIFIER_AUTHORITY, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo,
    FileIdInfo, FileStandardInfo, FlushFileBuffers, GetFileInformationByHandleEx,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_EXISTING, ReadFile,
    SetFileInformationByHandle, SetFilePointerEx, WriteFile,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::{ObjectInfo, PlatformError};

const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_LIST_DIRECTORY: u32 = 0x0001;
const FILE_ADD_FILE: u32 = 0x0002;
const FILE_DELETE_CHILD: u32 = 0x0040;
const FILE_TRAVERSE: u32 = 0x0020;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const DELETE: u32 = 0x0001_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_OPEN_REPARSE_POINT_NT: u32 = 0x0020_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
const ERROR_SUCCESS: u32 = 0;
const SE_FILE_OBJECT: i32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const GRANT_ACCESS: i32 = 1;
const TRUSTEE_IS_SID: i32 = 0;
const TRUSTEE_IS_USER: i32 = 1;
const OBJECT_AND_CONTAINER_INHERIT: u32 = 0x3;
const GENERIC_ALL: u32 = 0x1000_0000;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const ACL_SIZE_INFORMATION_CLASS: i32 = 2;

pub(crate) struct OpenedTarget {
    parent: OwnedHandle,
    file: OwnedHandle,
    info: ObjectInfo,
    file_name: Vec<u16>,
}

impl OpenedTarget {
    pub(crate) fn info(&self) -> ObjectInfo {
        self.info
    }

    pub(crate) fn refresh_links(&self) -> Result<u32, PlatformError> {
        Ok(query_handle(self.file.raw())?.link_count)
    }

    pub(crate) fn read(&self, max: u64) -> Result<Vec<u8>, PlatformError> {
        read_handle(self.file.raw(), max)
    }

    pub(crate) fn replace_with(&mut self, bytes: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let current = query_handle(self.file.raw())?;
        if current.file_id != self.info.file_id || current.volume_serial != self.info.volume_serial
        {
            return Err(PlatformError::Identity);
        }
        if current.is_reparse {
            return Err(PlatformError::Reparse);
        }
        if current.link_count != 1 {
            return Err(PlatformError::Hardlink);
        }
        let temp_name = temp_component();
        let temp = create_child(
            self.parent.raw(),
            &temp_name,
            DELETE | FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(label("temp create"))?;
        let write_result = write_handle(temp.raw(), bytes).and_then(|()| flush_handle(temp.raw()));
        if let Err(error) = write_result {
            dispose_handle(temp.raw());
            return Err(error);
        }
        let again = query_handle(self.file.raw())?;
        if again.file_id != self.info.file_id || again.link_count != 1 || again.is_reparse {
            dispose_handle(temp.raw());
            return Err(if again.link_count != 1 {
                PlatformError::Hardlink
            } else if again.is_reparse {
                PlatformError::Reparse
            } else {
                PlatformError::Identity
            });
        }
        let old = std::mem::replace(&mut self.file, OwnedHandle(ptr::null_mut()));
        drop(old);
        let renamed =
            rename_over(temp.raw(), self.parent.raw(), &self.file_name).map_err(label("rename"));
        if let Err(error) = renamed {
            dispose_handle(temp.raw());
            return Err(error);
        }
        let readback = read_handle(temp.raw(), (bytes.len() as u64).saturating_add(1));
        drop(temp);
        readback
    }
}

pub(crate) fn inspect(path: &Path) -> Result<ObjectInfo, PlatformError> {
    let handle = open_existing(path)?;
    let info = query_handle(handle.raw());
    drop(handle);
    info
}

pub(crate) fn open_tree(root: &Path, components: &[String]) -> Result<OpenedTarget, PlatformError> {
    if components.is_empty() || components.iter().any(|part| !valid_component(part)) {
        return Err(PlatformError::Io(
            "path component is not a single name".to_owned(),
        ));
    }
    let root_handle = open_with(
        root,
        FILE_LIST_DIRECTORY
            | FILE_ADD_FILE
            | FILE_DELETE_CHILD
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE,
    )?;
    let root_info = query_handle(root_handle.raw())?;
    if root_info.is_reparse {
        return Err(PlatformError::Reparse);
    }
    if !root_info.is_directory {
        return Err(PlatformError::Io(
            "workspace root is not a directory".to_owned(),
        ));
    }
    let mut parent = root_handle;
    let last = components.len() - 1;
    for (index, component) in components.iter().enumerate() {
        let wide = wide_component(component)?;
        if index != last {
            let child = create_child(
                parent.raw(),
                &wide,
                FILE_LIST_DIRECTORY
                    | FILE_ADD_FILE
                    | FILE_DELETE_CHILD
                    | FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE
                    | FILE_SYNCHRONOUS_IO_NONALERT
                    | FILE_OPEN_REPARSE_POINT_NT
                    | FILE_OPEN_FOR_BACKUP_INTENT,
            )?;
            let info = query_handle(child.raw())?;
            if info.is_reparse {
                return Err(PlatformError::Reparse);
            }
            if !info.is_directory {
                return Err(PlatformError::Io(
                    "path component is not a directory".to_owned(),
                ));
            }
            parent = child;
        } else {
            let probe = create_child(
                parent.raw(),
                &wide,
                FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT
                    | FILE_OPEN_REPARSE_POINT_NT
                    | FILE_OPEN_FOR_BACKUP_INTENT,
            )?;
            let probed = query_handle(probe.raw())?;
            drop(probe);
            if probed.is_reparse {
                return Err(PlatformError::Reparse);
            }
            if probed.is_directory {
                return Err(PlatformError::Io("patch target is a directory".to_owned()));
            }
            let file = create_child(
                parent.raw(),
                &wide,
                FILE_GENERIC_READ | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT_NT,
            )?;
            let info = query_handle(file.raw())?;
            if info.is_reparse {
                return Err(PlatformError::Reparse);
            }
            if info.file_id != probed.file_id || info.volume_serial != probed.volume_serial {
                return Err(PlatformError::Identity);
            }
            if info.file_id == [0; 16] {
                return Err(PlatformError::Identity);
            }
            return Ok(OpenedTarget {
                parent,
                file,
                info,
                file_name: wide,
            });
        }
    }
    Err(PlatformError::Io("path has no file name".to_owned()))
}

pub(crate) fn protect(plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    if plaintext.is_empty() || plaintext.len() > 16 * 1024 * 1024 {
        return Err(PlatformError::Protect);
    }
    let entropy = entropy_blob();
    let input = blob(plaintext);
    let mut output = empty_blob();
    let status = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if status == 0 {
        return Err(PlatformError::Protect);
    }
    copy_and_free(output)
}

pub(crate) fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    if ciphertext.is_empty() || ciphertext.len() > 17 * 1024 * 1024 {
        return Err(PlatformError::Protect);
    }
    let entropy = entropy_blob();
    let input = blob(ciphertext);
    let mut output = empty_blob();
    let status = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if status == 0 {
        return Err(PlatformError::Protect);
    }
    copy_and_free(output)
}

pub(crate) fn restrict_directory(directory: &Path) -> Result<(), PlatformError> {
    let user = current_user_sid()?;
    let system = local_system_sid()?;
    let mut entries = [
        explicit_access(user.as_ptr()),
        explicit_access(system.as_ptr()),
    ];
    let mut dacl = ptr::null_mut();
    let built = unsafe { set_entries(&mut entries, &mut dacl) };
    if built != ERROR_SUCCESS || dacl.is_null() {
        return Err(PlatformError::Acl);
    }
    let wide = wide_path(directory)?;
    let status = unsafe { set_dacl(wide.as_ptr(), dacl) };
    unsafe {
        LocalFree(dacl.cast());
    }
    if status != ERROR_SUCCESS {
        return Err(PlatformError::Acl);
    }
    require_restricted(directory)
}

pub(crate) fn require_restricted(directory: &Path) -> Result<(), PlatformError> {
    let user = current_user_sid()?;
    let system = local_system_sid()?;
    let wide = wide_path(directory)?;
    let mut dacl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    let status = unsafe { read_dacl(wide.as_ptr(), &mut dacl, &mut descriptor) };
    if status != ERROR_SUCCESS || dacl.is_null() {
        if !descriptor.is_null() {
            unsafe {
                LocalFree(descriptor.cast());
            }
        }
        return Err(PlatformError::Acl);
    }
    let allowed = unsafe { dacl_is_user_and_system(dacl, user.as_ptr(), system.as_ptr()) };
    unsafe {
        LocalFree(descriptor.cast());
    }
    if allowed {
        Ok(())
    } else {
        Err(PlatformError::Acl)
    }
}

pub(crate) fn try_lock_exclusive(path: &Path) -> Result<std::fs::File, PlatformError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| PlatformError::Io(error.to_string()))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error)?;
    let mut overlapped =
        std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle().cast(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            overlapped.as_mut_ptr(),
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        if code == ERROR_SHARING_VIOLATION || code == 33 {
            return Err(PlatformError::Sharing);
        }
        return Err(PlatformError::Io(format!("lock failed ({code})")));
    }
    Ok(file)
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn open_existing(path: &Path) -> Result<OwnedHandle, PlatformError> {
    open_with(
        path,
        FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
    )
}

fn open_with(path: &Path, access: u32) -> Result<OwnedHandle, PlatformError> {
    let wide = wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io_code());
    }
    Ok(OwnedHandle(handle))
}

fn create_child(
    parent: HANDLE,
    name: &[u16],
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<OwnedHandle, PlatformError> {
    let mut name_buf = name.to_vec();
    let byte_len = u16::try_from(name_buf.len().saturating_mul(2))
        .map_err(|_| PlatformError::Io("path component is too long".to_owned()))?;
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
            options,
            ptr::null_mut(),
            0,
        )
    };
    if status < 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        if status == STATUS_SHARING_VIOLATION {
            return Err(PlatformError::Sharing);
        }
        return Err(PlatformError::Io(format!(
            "relative open failed ({status:#x})"
        )));
    }
    Ok(OwnedHandle(handle))
}

const STATUS_SHARING_VIOLATION: i32 = -1_073_741_757;

fn query_handle(handle: HANDLE) -> Result<ObjectInfo, PlatformError> {
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
        return Err(io_code());
    }
    if standard.EndOfFile < 0 {
        return Err(PlatformError::Io("file length is negative".to_owned()));
    }
    Ok(ObjectInfo {
        volume_serial: identity.VolumeSerialNumber,
        file_id: identity.FileId.Identifier,
        link_count: standard.NumberOfLinks,
        end_of_file: u64::try_from(standard.EndOfFile).unwrap_or(0),
        is_reparse: tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
        is_directory: standard.Directory != 0,
    })
}

fn read_handle(handle: HANDLE, max: u64) -> Result<Vec<u8>, PlatformError> {
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
            return Err(io_code());
        }
        if read == 0 {
            break;
        }
        let count = read as usize;
        if collected.len() as u64 + count as u64 > max {
            return Err(PlatformError::Io("file exceeds the read cap".to_owned()));
        }
        collected.extend_from_slice(&buffer[..count]);
    }
    Ok(collected)
}

fn write_handle(handle: HANDLE, bytes: &[u8]) -> Result<(), PlatformError> {
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
            return Err(io_code());
        }
        offset += written as usize;
    }
    Ok(())
}

fn rewind(handle: HANDLE) -> Result<(), PlatformError> {
    let ok = unsafe { SetFilePointerEx(handle, 0, ptr::null_mut(), 0) };
    if ok == 0 { Err(io_code()) } else { Ok(()) }
}

fn label(step: &'static str) -> impl Fn(PlatformError) -> PlatformError {
    move |error| match error {
        PlatformError::Io(message) => PlatformError::Io(format!("{step}: {message}")),
        other => other,
    }
}

fn flush_handle(handle: HANDLE) -> Result<(), PlatformError> {
    let ok = unsafe { FlushFileBuffers(handle) };
    if ok == 0 { Err(io_code()) } else { Ok(()) }
}

fn dispose_handle(handle: HANDLE) {
    #[repr(C)]
    struct Disposition {
        delete_file: u8,
    }
    let disposition = Disposition { delete_file: 1 };
    unsafe {
        SetFileInformationByHandle(
            handle,
            FILE_DISPOSITION_INFO_CLASS,
            (&disposition as *const Disposition).cast(),
            u32::try_from(std::mem::size_of::<Disposition>()).unwrap_or(1),
        );
    }
}

fn rename_over(file: HANDLE, parent: HANDLE, name: &[u16]) -> Result<(), PlatformError> {
    let name_bytes = u32::try_from(name.len().saturating_mul(2))
        .map_err(|_| PlatformError::Io("file name is too long".to_owned()))?;
    #[repr(C)]
    struct Header {
        flags: u32,
        root: HANDLE,
        name_len: u32,
    }
    let name_at = std::mem::offset_of!(Header, name_len) + 4;
    let mut buffer = vec![0u8; name_at + name_bytes as usize];
    buffer[..4].copy_from_slice(&FILE_RENAME_REPLACE_IF_EXISTS.to_le_bytes());
    let root = parent as usize;
    buffer[8..16].copy_from_slice(&root.to_le_bytes());
    buffer[name_at - 4..name_at].copy_from_slice(&name_bytes.to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        let start = name_at + index * 2;
        buffer[start..start + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let mut io = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::zeroed();
    let status = unsafe {
        NtSetInformationFile(
            file,
            io.as_mut_ptr(),
            buffer.as_ptr().cast(),
            u32::try_from(buffer.len()).unwrap_or(0),
            FileRenameInformation,
        )
    };
    if status < 0 {
        return Err(PlatformError::Io(format!(
            "rename status {status:#x} (name_at={name_at}, bytes={name_bytes})"
        )));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>, PlatformError> {
    let mut wide: Vec<u16> = OsStr::new(path).encode_wide().collect();
    if wide.is_empty() || wide.len() > 32_000 {
        return Err(PlatformError::Io("path length is not allowed".to_owned()));
    }
    wide.push(0);
    Ok(wide)
}

fn wide_component(name: &str) -> Result<Vec<u16>, PlatformError> {
    if !valid_component(name) {
        return Err(PlatformError::Io(
            "path component is not a single name".to_owned(),
        ));
    }
    Ok(name.encode_utf16().collect())
}

fn valid_component(name: &str) -> bool {
    !name.is_empty() && !name.contains(['/', '\\', ':', '\0']) && name != "." && name != ".."
}

fn temp_component() -> Vec<u16> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let name = format!(".lca-{pid}-{nanos}.tmp", pid = std::process::id());
    name.encode_utf16().collect()
}

fn io_error(error: std::io::Error) -> PlatformError {
    if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) {
        PlatformError::Sharing
    } else {
        PlatformError::Io(error.to_string())
    }
}

fn io_code() -> PlatformError {
    let code = unsafe { GetLastError() };
    if code == ERROR_SHARING_VIOLATION || code == 33 {
        PlatformError::Sharing
    } else {
        PlatformError::Io(format!("windows error {code}"))
    }
}

fn entropy_blob() -> windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    blob(b"LCA-01G-PROPOSAL-V1")
}

fn blob(bytes: &[u8]) -> windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).unwrap_or(0),
        pbData: bytes.as_ptr().cast_mut(),
    }
}

fn empty_blob() -> windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
    windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    }
}

fn copy_and_free(
    output: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Result<Vec<u8>, PlatformError> {
    if output.pbData.is_null() || output.cbData == 0 {
        return Err(PlatformError::Protect);
    }
    let copy =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(copy)
}

struct SidBuf(Vec<u8>);

impl SidBuf {
    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.0.as_ptr().cast_mut().cast()
    }
}

fn current_user_sid() -> Result<SidBuf, PlatformError> {
    let mut token = ptr::null_mut();
    let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if opened == 0 {
        return Err(PlatformError::Acl);
    }
    let token = OwnedHandle(token);
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token.raw(), TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 4096 {
        return Err(PlatformError::Acl);
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(PlatformError::Acl);
    }
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    let source = user.User.Sid;
    if source.is_null() {
        return Err(PlatformError::Acl);
    }
    let length = unsafe { GetLengthSid(source) };
    if length == 0 || length > 256 {
        return Err(PlatformError::Acl);
    }
    let mut owned = vec![0u8; length as usize];
    let copied = unsafe { CopySid(length, owned.as_mut_ptr().cast(), source) };
    if copied == 0 {
        return Err(PlatformError::Acl);
    }
    Ok(SidBuf(owned))
}

fn local_system_sid() -> Result<SidBuf, PlatformError> {
    let authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 5],
    };
    let mut sid = ptr::null_mut();
    let ok = unsafe { AllocateAndInitializeSid(&authority, 1, 18, 0, 0, 0, 0, 0, 0, 0, &mut sid) };
    if ok == 0 || sid.is_null() {
        return Err(PlatformError::Acl);
    }
    let length = unsafe { GetLengthSid(sid) };
    let mut owned = vec![0u8; length as usize];
    let copied = unsafe { CopySid(length, owned.as_mut_ptr().cast(), sid) };
    unsafe {
        FreeSid(sid);
    }
    if copied == 0 {
        return Err(PlatformError::Acl);
    }
    Ok(SidBuf(owned))
}

fn explicit_access(
    sid: *mut std::ffi::c_void,
) -> windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W {
    windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: OBJECT_AND_CONTAINER_INHERIT,
        Trustee: windows_sys::Win32::Security::Authorization::TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.cast(),
        },
    }
}

unsafe fn set_entries(
    entries: &mut [windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W],
    dacl: &mut *mut ACL,
) -> u32 {
    unsafe {
        windows_sys::Win32::Security::Authorization::SetEntriesInAclW(
            u32::try_from(entries.len()).unwrap_or(0),
            entries.as_mut_ptr(),
            ptr::null(),
            dacl,
        )
    }
}

unsafe fn set_dacl(path: *const u16, dacl: *const ACL) -> u32 {
    unsafe {
        windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    }
}

unsafe fn read_dacl(
    path: *const u16,
    dacl: &mut *mut ACL,
    descriptor: &mut *mut std::ffi::c_void,
) -> u32 {
    unsafe {
        windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
            descriptor,
        )
    }
}

unsafe fn dacl_is_user_and_system(
    dacl: *mut ACL,
    user: *mut std::ffi::c_void,
    system: *mut std::ffi::c_void,
) -> bool {
    #[repr(C)]
    struct AclSize {
        ace_count: u32,
        bytes_in_use: u32,
        bytes_free: u32,
    }
    let mut size = AclSize {
        ace_count: 0,
        bytes_in_use: 0,
        bytes_free: 0,
    };
    let ok = unsafe {
        windows_sys::Win32::Security::GetAclInformation(
            dacl,
            (&mut size as *mut AclSize).cast(),
            u32::try_from(std::mem::size_of::<AclSize>()).unwrap_or(0),
            ACL_SIZE_INFORMATION_CLASS,
        )
    };
    if ok == 0 || size.ace_count == 0 || size.ace_count > 16 {
        return false;
    }
    for index in 0..size.ace_count {
        let mut ace = ptr::null_mut();
        let found = unsafe { windows_sys::Win32::Security::GetAce(dacl, index, &mut ace) };
        if found == 0 || ace.is_null() {
            return false;
        }
        let header = unsafe { &*(ace as *const AceHeader) };
        if header.ace_type == ACCESS_DENIED_ACE_TYPE {
            continue;
        }
        if header.ace_type != ACCESS_ALLOWED_ACE_TYPE || header.ace_size < 8 {
            return false;
        }
        let sid = unsafe { ace.cast::<u8>().add(8).cast() };
        let user_match = unsafe { EqualSid(sid, user) } != 0;
        let system_match = unsafe { EqualSid(sid, system) } != 0;
        if !user_match && !system_match {
            return false;
        }
    }
    true
}

#[repr(C)]
struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}
