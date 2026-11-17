//! Windows file identity, relative opens, DPAPI, and owner-only ACLs.
//!
//! `unsafe` stays in this module. The exported functions do not take raw pointers.
//!
//! Every `unsafe` call uses a `windows-sys` 0.59 prototype. Pointers are either null,
//! a handle this module opened and still owns, or a buffer whose length is the value
//! passed to the API. Returned buffers are read only up to the size the API reports.
//! `NtCreateFile` object attributes point at the parent handle and a name that lives
//! for the call. Directory listings copy names out of the query buffer before reuse.
//! None of these calls accept a path string as a substitute for the handle they query.

#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileBothDirectoryInformation, NtCreateFile, NtQueryDirectoryFile,
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
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_ID_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FileAttributeTagInfo, FileIdInfo, FileStandardInfo, FlushFileBuffers,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_EXISTING, ReadFile, SetEndOfFile,
    SetFileInformationByHandle, SetFilePointerEx, WriteFile,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::{ObjectInfo, PlatformError, PublishFailure, PublishPhase};

#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::{FILE_RENAME_INFO, FileRenameInfoEx, ReplaceFileW};

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
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_OPEN_REPARSE_POINT_NT: u32 = 0x0020_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const FILE_DISPOSITION_INFO_CLASS: i32 = 4;
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

    pub(crate) fn replace_with(
        &mut self,
        bytes: &[u8],
        root: &Path,
        components: &[String],
        hook: &mut dyn FnMut(PublishPhase) -> Result<(), PlatformError>,
    ) -> Result<Vec<u8>, PublishFailure> {
        let clean = |error| PublishFailure {
            error,
            published: false,
        };
        let published = |error| PublishFailure {
            error,
            published: true,
        };
        let current = match query_handle(self.file.raw()) {
            Ok(info) => info,
            Err(error) => return Err(clean(error)),
        };
        if let Err(error) = require_same_file(&current, &self.info) {
            return Err(clean(error));
        }
        if let Err(error) = confirm_bound(self.file.raw(), root, components) {
            return Err(clean(error));
        }
        let temp = match create_temp(self.parent.raw()) {
            Ok(temp) => temp,
            Err(error) => return Err(clean(error)),
        };
        if let Err(error) = hook(PublishPhase::AfterTempCreate) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        if let Err(error) = write_handle(temp.raw(), bytes) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        if let Err(error) = hook(PublishPhase::AfterWrite) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        let staged = flush_handle(temp.raw())
            .and_then(|()| read_handle(temp.raw(), (bytes.len() as u64).saturating_add(1)))
            .and_then(|readback| {
                if readback == bytes {
                    Ok(())
                } else {
                    Err(PlatformError::Verify)
                }
            });
        if let Err(error) = staged {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        if let Err(error) = hook(PublishPhase::AfterStageFlush) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        let again = match query_handle(self.file.raw()) {
            Ok(info) => info,
            Err(error) => {
                dispose_handle(temp.raw());
                return Err(clean(error));
            }
        };
        if let Err(error) = require_same_file(&again, &self.info) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        if let Err(error) = confirm_bound(self.file.raw(), root, components) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        if let Err(error) = hook(PublishPhase::BeforeRename) {
            dispose_handle(temp.raw());
            return Err(clean(error));
        }
        dispose_handle(temp.raw());
        // Publication stays on this handle. A rename would require share-delete, and that
        // share lets another caller move the directory entry first. Measured in
        // `measured_windows_publication_options`.
        if let Err(error) = publish_handle(self.file.raw(), bytes, hook) {
            return Err(published(error));
        }
        if let Err(error) = hook(PublishPhase::AfterRename) {
            return Err(published(error));
        }
        if let Err(error) = hook(PublishPhase::BeforeReadback) {
            return Err(published(error));
        }
        if let Err(error) = hook(PublishPhase::DuringReadback) {
            return Err(published(error));
        }
        let readback = match read_handle(self.file.raw(), (bytes.len() as u64).saturating_add(1)) {
            Ok(readback) => readback,
            Err(error) => return Err(published(error)),
        };
        if readback != bytes {
            return Err(published(PlatformError::Verify));
        }
        let after = match query_handle(self.file.raw()) {
            Ok(info) => info,
            Err(error) => return Err(published(error)),
        };
        if let Err(error) = require_same_file(&after, &self.info) {
            return Err(published(error));
        }
        if let Err(error) = confirm_bound(self.file.raw(), root, components) {
            return Err(published(error));
        }
        self.info = after;
        Ok(readback)
    }
}

pub(crate) fn inspect(path: &Path) -> Result<ObjectInfo, PlatformError> {
    let handle = open_existing(path)?;
    let info = query_handle(handle.raw());
    drop(handle);
    info
}

pub(crate) fn open_tree(root: &Path, components: &[String]) -> Result<OpenedTarget, PlatformError> {
    open_leaf(
        root,
        components,
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ,
        false,
    )
}

pub(crate) fn stat_tree(root: &Path, components: &[String]) -> Result<ObjectInfo, PlatformError> {
    let opened = open_leaf(
        root,
        components,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        true,
    )?;
    Ok(opened.info)
}

pub(crate) fn read_tree(
    root: &Path,
    components: &[String],
    max: u64,
) -> Result<(ObjectInfo, Vec<u8>), PlatformError> {
    let opened = open_leaf(
        root,
        components,
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        false,
    )?;
    if opened.info.is_reparse {
        return Err(PlatformError::Reparse);
    }
    if opened.info.is_directory {
        return Err(PlatformError::NotFile);
    }
    if opened.info.link_count != 1 {
        return Err(PlatformError::Hardlink);
    }
    if opened.info.file_id == [0; 16] {
        return Err(PlatformError::Identity);
    }
    if opened.info.end_of_file > max {
        return Err(PlatformError::Io("file exceeds the read cap".to_owned()));
    }
    let bytes = read_handle(opened.file.raw(), max)?;
    let after = query_handle(opened.file.raw())?;
    if after.file_id != opened.info.file_id
        || after.volume_serial != opened.info.volume_serial
        || after.link_count != 1
        || after.is_reparse
        || after.end_of_file != opened.info.end_of_file
    {
        return Err(PlatformError::Identity);
    }
    Ok((opened.info, bytes))
}

pub(crate) fn list_tree(
    root: &Path,
    components: &[String],
    max_entries: usize,
) -> Result<Vec<(String, u64, bool, bool)>, PlatformError> {
    if components.iter().any(|part| !valid_component(part)) {
        return Err(PlatformError::Io(
            "path component is not a single name".to_owned(),
        ));
    }
    let directory = if components.is_empty() {
        let handle = open_root(root)?;
        let info = query_handle(handle.raw())?;
        if info.is_reparse {
            return Err(PlatformError::Reparse);
        }
        if !info.is_directory {
            return Err(PlatformError::Io(
                "workspace root is not a directory".to_owned(),
            ));
        }
        handle
    } else {
        let opened = open_leaf(
            root,
            components,
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            true,
        )?;
        if opened.info.is_reparse {
            return Err(PlatformError::Reparse);
        }
        if !opened.info.is_directory {
            return Err(PlatformError::Io(
                "path component is not a directory".to_owned(),
            ));
        }
        opened.file
    };
    list_handle(directory.raw(), max_entries)
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
        return Err(map_nt(status));
    }
    Ok(OwnedHandle(handle))
}

fn map_nt(status: i32) -> PlatformError {
    if status == STATUS_SHARING_VIOLATION {
        PlatformError::Sharing
    } else if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
        PlatformError::NotFound
    } else if status == STATUS_FILE_IS_A_DIRECTORY || status == STATUS_NOT_A_DIRECTORY {
        PlatformError::NotFile
    } else {
        PlatformError::Io(format!("relative open failed ({status:#x})"))
    }
}

fn open_leaf(
    root: &Path,
    components: &[String],
    access: u32,
    share: u32,
    allow_directory: bool,
) -> Result<OpenedTarget, PlatformError> {
    if components.is_empty() || components.iter().any(|part| !valid_component(part)) {
        return Err(PlatformError::Io(
            "path component is not a single name".to_owned(),
        ));
    }
    let mut parent = open_root(root)?;
    let root_info = query_handle(parent.raw())?;
    if root_info.is_reparse {
        return Err(PlatformError::Reparse);
    }
    if !root_info.is_directory {
        return Err(PlatformError::Io(
            "workspace root is not a directory".to_owned(),
        ));
    }
    let last = components.len() - 1;
    for (index, component) in components.iter().enumerate() {
        let wide = wide_component(component)?;
        if index != last {
            parent = open_directory(parent, &wide)?;
        } else {
            let file = create_child(
                parent.raw(),
                &wide,
                access,
                share,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT
                    | FILE_OPEN_REPARSE_POINT_NT
                    | FILE_OPEN_FOR_BACKUP_INTENT,
            )?;
            let info = query_handle(file.raw())?;
            if info.is_reparse {
                return Err(PlatformError::Reparse);
            }
            if info.file_id == [0; 16] {
                return Err(PlatformError::Identity);
            }
            if !allow_directory && info.is_directory {
                return Err(PlatformError::NotFile);
            }
            return Ok(OpenedTarget { parent, file, info });
        }
    }
    Err(PlatformError::Io("path has no file name".to_owned()))
}

fn open_root(root: &Path) -> Result<OwnedHandle, PlatformError> {
    open_with(
        root,
        FILE_LIST_DIRECTORY
            | FILE_ADD_FILE
            | FILE_DELETE_CHILD
            | FILE_TRAVERSE
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE,
    )
}

fn open_directory(parent: OwnedHandle, name: &[u16]) -> Result<OwnedHandle, PlatformError> {
    let child = create_child(
        parent.raw(),
        name,
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
    Ok(child)
}

fn require_same_file(current: &ObjectInfo, expected: &ObjectInfo) -> Result<(), PlatformError> {
    if current.file_id != expected.file_id
        || current.volume_serial != expected.volume_serial
        || current.file_id == [0; 16]
    {
        return Err(PlatformError::Identity);
    }
    if current.is_reparse {
        return Err(PlatformError::Reparse);
    }
    if current.link_count != 1 {
        return Err(PlatformError::Hardlink);
    }
    if current.is_directory {
        return Err(PlatformError::NotFile);
    }
    Ok(())
}

fn confirm_bound(handle: HANDLE, root: &Path, components: &[String]) -> Result<(), PlatformError> {
    let actual = final_path(handle)?;
    let root_handle = open_root(root)?;
    let root_info = query_handle(root_handle.raw())?;
    if root_info.is_reparse || !root_info.is_directory {
        return Err(if root_info.is_reparse {
            PlatformError::Reparse
        } else {
            PlatformError::Io("workspace root is not a directory".to_owned())
        });
    }
    let mut expected = final_path(root_handle.raw())?;
    for component in components {
        if !expected.ends_with('\\') {
            expected.push('\\');
        }
        expected.push_str(component);
    }
    if normalize_dos(&actual).eq_ignore_ascii_case(&normalize_dos(&expected)) {
        Ok(())
    } else {
        Err(PlatformError::Identity)
    }
}

fn normalize_dos(path: &str) -> String {
    let stripped = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = path.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        path.to_owned()
    };
    stripped.trim_end_matches('\\').to_owned()
}

fn final_path(handle: HANDLE) -> Result<String, PlatformError> {
    let mut buffer = vec![0u16; 1024];
    let mut needed =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if needed == 0 {
        return Err(io_code());
    }
    if needed as usize >= buffer.len() {
        buffer.resize(needed as usize + 1, 0);
        needed = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        };
        if needed == 0 || needed as usize >= buffer.len() {
            return Err(PlatformError::Io("final path is too long".to_owned()));
        }
    }
    let text = String::from_utf16_lossy(&buffer[..needed as usize]);
    if text.is_empty() {
        Err(PlatformError::Io("final path is empty".to_owned()))
    } else {
        Ok(text)
    }
}

fn create_temp(parent: HANDLE) -> Result<OwnedHandle, PlatformError> {
    let mut last = PlatformError::Io("temporary file could not be created".to_owned());
    for _ in 0..4 {
        let name = temp_component();
        match create_child(
            parent,
            &name,
            DELETE | FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        ) {
            Ok(handle) => return Ok(handle),
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn publish_handle(
    handle: HANDLE,
    bytes: &[u8],
    hook: &mut dyn FnMut(PublishPhase) -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    rewind(handle)?;
    let mut offset = 0usize;
    let mut signaled = false;
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
        if !signaled {
            signaled = true;
            hook(PublishPhase::DuringPublish)?;
        }
    }
    if !signaled {
        hook(PublishPhase::DuringPublish)?;
    }
    let end = i64::try_from(bytes.len())
        .map_err(|_| PlatformError::Io("file is too large".to_owned()))?;
    let moved = unsafe { SetFilePointerEx(handle, end, ptr::null_mut(), 0) };
    if moved == 0 {
        return Err(io_code());
    }
    let truncated = unsafe { SetEndOfFile(handle) };
    if truncated == 0 {
        return Err(io_code());
    }
    hook(PublishPhase::BeforeFlush)?;
    flush_handle(handle)
}

fn list_handle(
    handle: HANDLE,
    max_entries: usize,
) -> Result<Vec<(String, u64, bool, bool)>, PlatformError> {
    if max_entries == 0 {
        return Err(PlatformError::Io(
            "directory listing limit is zero".to_owned(),
        ));
    }
    let name_at = std::mem::offset_of!(
        windows_sys::Wdk::Storage::FileSystem::FILE_BOTH_DIR_INFORMATION,
        FileName
    );
    let end_at = std::mem::offset_of!(
        windows_sys::Wdk::Storage::FileSystem::FILE_BOTH_DIR_INFORMATION,
        EndOfFile
    );
    let attr_at = std::mem::offset_of!(
        windows_sys::Wdk::Storage::FileSystem::FILE_BOTH_DIR_INFORMATION,
        FileAttributes
    );
    let name_len_at = std::mem::offset_of!(
        windows_sys::Wdk::Storage::FileSystem::FILE_BOTH_DIR_INFORMATION,
        FileNameLength
    );
    let mut buffer = vec![0u8; 64 * 1024];
    let mut restart = 1u8;
    let mut entries = Vec::new();
    loop {
        let mut io = std::mem::MaybeUninit::<IO_STATUS_BLOCK>::zeroed();
        let status = unsafe {
            NtQueryDirectoryFile(
                handle,
                ptr::null_mut(),
                None,
                ptr::null(),
                io.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                u32::try_from(buffer.len()).unwrap_or(0),
                FileBothDirectoryInformation,
                0,
                ptr::null(),
                restart,
            )
        };
        restart = 0;
        if status == STATUS_NO_MORE_FILES {
            break;
        }
        if status < 0 {
            return Err(PlatformError::Io(format!(
                "directory query failed ({status:#x})"
            )));
        }
        let written = unsafe { io.assume_init().Information };
        if written == 0 {
            break;
        }
        let slice = &buffer[..written.min(buffer.len())];
        let mut offset = 0usize;
        while offset + name_at <= slice.len() {
            let next = read_u32(slice, offset)? as usize;
            let attrs = read_u32(slice, offset + attr_at)?;
            let name_bytes = read_u32(slice, offset + name_len_at)? as usize;
            let end = read_i64(slice, offset + end_at)?;
            let name_off = offset + name_at;
            if name_bytes > 1024 || name_off.saturating_add(name_bytes) > slice.len() {
                return Err(PlatformError::Io("directory entry is malformed".to_owned()));
            }
            let name = utf16_name(&slice[name_off..name_off + name_bytes])?;
            if name != "." && name != ".." {
                if entries.len() >= max_entries {
                    return Err(PlatformError::Io(
                        "directory is too large to list".to_owned(),
                    ));
                }
                let size = u64::try_from(end.max(0)).unwrap_or(0);
                entries.push((
                    name,
                    size,
                    attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
                    attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0,
                ));
            }
            if next == 0 {
                break;
            }
            let Some(next_offset) = offset.checked_add(next) else {
                return Err(PlatformError::Io("directory entry is malformed".to_owned()));
            };
            if next_offset > slice.len() {
                return Err(PlatformError::Io("directory entry is malformed".to_owned()));
            }
            offset = next_offset;
        }
    }
    Ok(entries)
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, PlatformError> {
    let chunk = bytes
        .get(at..at + 4)
        .ok_or_else(|| PlatformError::Io("directory entry is malformed".to_owned()))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(chunk);
    Ok(u32::from_le_bytes(buf))
}

fn read_i64(bytes: &[u8], at: usize) -> Result<i64, PlatformError> {
    let chunk = bytes
        .get(at..at + 8)
        .ok_or_else(|| PlatformError::Io("directory entry is malformed".to_owned()))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(chunk);
    Ok(i64::from_le_bytes(buf))
}

fn utf16_name(bytes: &[u8]) -> Result<String, PlatformError> {
    if !bytes.len().is_multiple_of(2) {
        return Err(PlatformError::Io("directory entry is malformed".to_owned()));
    }
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    String::from_utf16(&units)
        .map_err(|_| PlatformError::Io("directory name is not Unicode".to_owned()))
}

const STATUS_SHARING_VIOLATION: i32 = 0xC000_0043u32 as i32;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_OBJECT_PATH_NOT_FOUND: i32 = 0xC000_003Au32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: i32 = 0xC000_00BAu32 as i32;
const STATUS_NOT_A_DIRECTORY: i32 = 0xC000_0103u32 as i32;
const STATUS_NO_MORE_FILES: i32 = 0x8000_0006u32 as i32;

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

#[cfg(test)]
fn posix_replace(staged: HANDLE, parent: HANDLE, name: &str) -> Result<(), String> {
    let mut notes = Vec::new();
    let relative = name.rsplit(['\\', '/']).next().unwrap_or(name);
    let mut forms = vec![(parent, relative.to_owned())];
    if name.contains(['\\', '/']) {
        forms.push((ptr::null_mut(), name.to_owned()));
        forms.push((ptr::null_mut(), format!(r"\\?\{name}")));
    }
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
            buffer[..4].copy_from_slice(&0x3u32.to_le_bytes());
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
                windows_sys::Wdk::Storage::FileSystem::NtSetInformationFile(
                    staged,
                    io.as_mut_ptr(),
                    buffer.as_ptr().cast(),
                    u32::try_from(name_at + wide.len() * 2).unwrap_or(0),
                    windows_sys::Wdk::Storage::FileSystem::FileRenameInformationEx,
                )
            };
            notes.push(format!(
                "root_null={} null={} name={form:?} win32={win32_error} nt={status:#x} name_at={name_at} root_at={root_at}",
                root.is_null(),
                null_terminated,
            ));
            if status >= 0 {
                return Ok(());
            }
        }
    }
    Err(notes.join(" | "))
}

#[cfg(test)]
fn probe_dir(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("lca-pub-{label}-{nanos}"));
    std::fs::create_dir_all(&path).expect("probe dir");
    path
}

/// Measured publication facts for LCA-01I. These asserts are the evidence, not the names of the APIs.
#[cfg(test)]
#[test]
fn measured_windows_publication_options() {
    let root = probe_dir("measure");
    let parent = open_root(&root).expect("parent");

    std::fs::write(root.join("held.txt"), b"alpha\n").expect("seed");
    let exclusive = open_named(
        parent.raw(),
        "held.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ,
        FILE_OPEN,
    )
    .expect("exclusive");
    let staged_blocked = open_named(
        parent.raw(),
        "staged-blocked.txt",
        DELETE | FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_CREATE,
    )
    .expect("staged");
    write_handle(staged_blocked.raw(), b"beta\n").expect("stage");
    flush_handle(staged_blocked.raw()).expect("flush");
    let blocked = posix_replace(
        staged_blocked.raw(),
        parent.raw(),
        &root.join("held.txt").to_string_lossy(),
    );
    let blocked = blocked.expect_err("posix replace must fail while share-delete is denied");
    let blocked_lower = blocked.to_ascii_lowercase();
    assert!(
        blocked_lower.contains("32")
            || blocked_lower.contains("c0000043")
            || blocked_lower.contains("c0000022"),
        "exclusive handle did not fail with a sharing status: {blocked}"
    );
    assert_eq!(
        std::fs::read(root.join("held.txt")).expect("bytes"),
        b"alpha\n"
    );
    let before = query_handle(exclusive.raw()).expect("id");
    assert_eq!(
        query_handle(exclusive.raw()).expect("same").file_id,
        before.file_id
    );
    drop(exclusive);
    drop(staged_blocked);

    std::fs::write(root.join("shared.txt"), b"alpha\n").expect("shared seed");
    let shared = open_named(
        parent.raw(),
        "shared.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("shared");
    let _shared_id = query_handle(shared.raw()).expect("shared id").file_id;
    let away = root.join("away.txt");
    let renamed = std::fs::rename(root.join("shared.txt"), &away);
    assert!(
        renamed.is_ok(),
        "share-delete lets another rename move the verified name: {renamed:?}"
    );
    assert_eq!(std::fs::read(&away).expect("moved"), b"alpha\n");
    drop(shared);
    let _ = std::fs::remove_file(&away);

    std::fs::write(root.join("target.txt"), b"alpha\n").expect("target");
    let pinned = open_named(
        parent.raw(),
        "target.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("pinned");
    let old_id = query_handle(pinned.raw()).expect("old").file_id;
    let staged = open_named(
        parent.raw(),
        "staged.txt",
        DELETE | FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_CREATE,
    )
    .expect("staged ok");
    let staged_id = query_handle(staged.raw()).expect("staged id").file_id;
    write_handle(staged.raw(), b"beta\n").expect("beta");
    flush_handle(staged.raw()).expect("flush beta");
    let replaced = posix_replace(
        staged.raw(),
        parent.raw(),
        &root.join("target.txt").to_string_lossy(),
    );
    assert!(replaced.is_ok(), "posix replace failed: {replaced:?}");
    let pending = query_handle(pinned.raw()).expect("pending");
    assert_eq!(pending.file_id, old_id);
    assert_eq!(
        read_handle(pinned.raw(), 64).expect("old bytes"),
        b"alpha\n"
    );
    assert_eq!(pending.end_of_file, 6);
    let standard_pending = {
        let mut standard = FILE_STANDARD_INFO {
            AllocationSize: 0,
            EndOfFile: 0,
            NumberOfLinks: 0,
            DeletePending: 0,
            Directory: 0,
        };
        let ok = unsafe {
            GetFileInformationByHandleEx(
                pinned.raw(),
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                u32::try_from(std::mem::size_of::<FILE_STANDARD_INFO>()).unwrap_or(0),
            )
        };
        assert_ne!(ok, 0);
        standard.DeletePending
    };
    assert_eq!(
        standard_pending, 1,
        "replaced handle must be delete-pending"
    );
    drop(pinned);
    drop(staged);
    let reopened = open_named(
        parent.raw(),
        "target.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("reopen2");
    let now = query_handle(reopened.raw()).expect("now");
    assert_eq!(now.file_id, staged_id);
    assert_ne!(now.file_id, old_id);
    assert_eq!(read_handle(reopened.raw(), 64).expect("new"), b"beta\n");
    drop(reopened);

    std::fs::write(root.join("locked.txt"), b"alpha\n").expect("locked");
    let locked = open_named(
        parent.raw(),
        "locked.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("lock open");
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
    let lock_ok = unsafe {
        LockFileEx(
            locked.raw(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    assert_ne!(lock_ok, 0, "byte lock failed {}", unsafe { GetLastError() });
    let lock_rename = std::fs::rename(root.join("locked.txt"), root.join("locked-away.txt"));
    assert!(
        lock_rename.is_ok(),
        "measured fact: an exclusive byte-range lock does not pin the directory entry when delete is shared: {lock_rename:?}"
    );
    drop(locked);

    std::fs::write(root.join("replace-held.txt"), b"alpha\n").expect("rf held");
    std::fs::write(root.join("replace-new.txt"), b"beta\n").expect("rf new");
    let held = open_named(
        parent.raw(),
        "replace-held.txt",
        FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_SHARE_READ,
        FILE_OPEN,
    )
    .expect("rf exclusive");
    let held_wide = wide_path(&root.join("replace-held.txt")).expect("wide");
    let new_wide = wide_path(&root.join("replace-new.txt")).expect("wide");
    let replace_held = unsafe {
        ReplaceFileW(
            held_wide.as_ptr(),
            new_wide.as_ptr(),
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
        )
    };
    assert_eq!(
        replace_held, 0,
        "ReplaceFile must fail against an exclusive handle"
    );
    drop(held);

    std::fs::write(root.join("replace-old.txt"), b"alpha\n").expect("old");
    std::fs::write(root.join("replace-src.txt"), b"beta\n").expect("src");
    let src = open_named(
        parent.raw(),
        "replace-src.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("src id");
    let src_id = query_handle(src.raw()).expect("src").file_id;
    drop(src);
    let old = open_named(
        parent.raw(),
        "replace-old.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("old id");
    let old_replace_id = query_handle(old.raw()).expect("old").file_id;
    drop(old);
    let old_wide = wide_path(&root.join("replace-old.txt")).expect("wide");
    let src_wide = wide_path(&root.join("replace-src.txt")).expect("wide");
    let backup = root.join("replace-backup.txt");
    let backup_wide = wide_path(&backup).expect("wide");
    let replace_ok = unsafe {
        ReplaceFileW(
            old_wide.as_ptr(),
            src_wide.as_ptr(),
            backup_wide.as_ptr(),
            0,
            ptr::null(),
            ptr::null(),
        )
    };
    assert_ne!(replace_ok, 0, "ReplaceFile failed {}", unsafe {
        GetLastError()
    });
    let result = open_named(
        parent.raw(),
        "replace-old.txt",
        FILE_GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
    )
    .expect("result");
    let result_id = query_handle(result.raw()).expect("result id").file_id;
    assert_eq!(result_id, src_id);
    assert_ne!(result_id, old_replace_id);
    assert_eq!(read_handle(result.raw(), 64).expect("rf bytes"), b"beta\n");
    assert_eq!(std::fs::read(&backup).expect("backup"), b"alpha\n");
    drop(result);
    drop(parent);
    let _ = std::fs::remove_dir_all(root);
}

#[cfg(test)]
fn open_named(
    parent: HANDLE,
    name: &str,
    access: u32,
    share: u32,
    disposition: u32,
) -> Result<OwnedHandle, PlatformError> {
    let wide = wide_component(name)?;
    create_child(
        parent,
        &wide,
        access,
        share,
        disposition,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
    )
}
