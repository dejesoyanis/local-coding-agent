//! Operating-system boundary for file identity and user-bound bytes.
//!
//! Windows uses NTFS file IDs, relative handle opens, and DPAPI. Other platforms return
//! [`PlatformError::Unsupported`]. Callers must fail closed instead of substituting a
//! timestamp identity for a verified apply.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::ffi::OsString;
use std::fs::File;
use std::path::Path;

mod sys;

#[cfg(all(test, windows))]
#[allow(clippy::too_many_lines)]
mod isolation_probe;
#[cfg(all(test, windows))]
mod publication_probe;

/// Identity of one filesystem object, taken from an open handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectInfo {
    volume_serial: u64,
    file_id: [u8; 16],
    link_count: u32,
    end_of_file: u64,
    is_reparse: bool,
    is_directory: bool,
}

impl ObjectInfo {
    /// Volume serial from `FileIdInfo`.
    #[must_use]
    pub const fn volume_serial(self) -> u64 {
        self.volume_serial
    }

    /// 128-bit file identifier. It is not a path.
    #[must_use]
    pub const fn file_id(self) -> [u8; 16] {
        self.file_id
    }

    /// Hard-link count observed on the handle.
    #[must_use]
    pub const fn link_count(self) -> u32 {
        self.link_count
    }

    /// End of file in bytes.
    #[must_use]
    pub const fn end_of_file(self) -> u64 {
        self.end_of_file
    }

    /// The object is a reparse point. The caller must not follow it.
    #[must_use]
    pub const fn is_reparse(self) -> bool {
        self.is_reparse
    }

    /// The object is a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        self.is_directory
    }
}

/// Why a platform operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformError {
    /// This operating system has no verified-apply implementation.
    Unsupported,
    /// A symlink, junction, or other reparse point was opened.
    Reparse,
    /// The file has more than one hard link.
    Hardlink,
    /// The handle is not the object that was expected.
    Identity,
    /// The path does not exist.
    NotFound,
    /// The object is not a regular file.
    NotFile,
    /// The directory entry was published and the read-back did not match.
    Verify,
    /// A test fault point fired. Production calls do not construct this.
    Injected,
    /// Another handle already has the file open in a conflicting way.
    Sharing,
    /// The directory ACL could not be restricted to the current user.
    Acl,
    /// DPAPI could not protect or unprotect the buffer.
    Protect,
    /// A filesystem call failed. The text does not include file bytes.
    Io(String),
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => {
                formatter.write_str("verified apply is not supported on this platform")
            }
            Self::Reparse => formatter.write_str("reparse point"),
            Self::Hardlink => formatter.write_str("hard link"),
            Self::Identity => formatter.write_str("file identity changed"),
            Self::NotFound => formatter.write_str("path was not found"),
            Self::NotFile => formatter.write_str("path is not a regular file"),
            Self::Verify => formatter.write_str("published bytes did not match"),
            Self::Injected => formatter.write_str("injected fault"),
            Self::Sharing => formatter.write_str("file is busy"),
            Self::Acl => formatter.write_str("directory ACL is not restricted"),
            Self::Protect => formatter.write_str("local protection failed"),
            Self::Io(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PlatformError {}

/// A file opened by walking from a root handle. The path string is not re-resolved.
pub struct OpenedTarget {
    inner: sys::OpenedTarget,
}

impl OpenedTarget {
    /// Identity captured when the file handle was opened.
    #[must_use]
    pub fn info(&self) -> ObjectInfo {
        self.inner.info()
    }

    /// Link count read again from the same handle.
    pub fn refresh_links(&self) -> Result<u32, PlatformError> {
        self.inner.refresh_links()
    }

    /// Bytes read through the open handle, capped at `max`.
    pub fn read(&self, max: u64) -> Result<Vec<u8>, PlatformError> {
        self.inner.read(max)
    }

    /// Publishes `bytes` through the open handle and returns the bytes read back.
    ///
    /// The directory entry is not renamed. `root` and `components` are checked against
    /// the handle before and after the write. A mismatch after the write is
    /// [`PublishFailure`] with `published == true`. This function does not restore the
    /// previous bytes.
    pub fn replace_with(
        &mut self,
        bytes: &[u8],
        root: &Path,
        components: &[String],
        hook: &mut dyn FnMut(PublishPhase) -> Result<(), PlatformError>,
    ) -> Result<Vec<u8>, PublishFailure> {
        self.inner.replace_with(bytes, root, components, hook)
    }
}

/// Points where a publish can be observed or faulted.
///
/// `BeforeRename` is the last point before the verified handle changes.
/// `DuringPublish` is after the first `WriteFile` transfer and before `SetEndOfFile`.
/// `AfterRename` is the first point after those bytes have been flushed.
/// The names match the fault model. The implementation does not rename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishPhase {
    /// The temporary file exists and has not been written.
    AfterTempCreate,
    /// The temporary file contains the byte image. It may not have been flushed.
    AfterWrite,
    /// The temporary file was flushed and its read-back matched.
    AfterStageFlush,
    /// The target handle is about to be overwritten.
    BeforeRename,
    /// At least one `WriteFile` to the target has returned. The file may be partial.
    DuringPublish,
    /// `SetEndOfFile` has returned. `FlushFileBuffers` has not been called.
    BeforeFlush,
    /// The target handle has the new bytes and they have been flushed.
    AfterRename,
    /// The handle is about to be read back.
    BeforeReadback,
    /// The read-back is treated as failed even if the handle bytes match.
    DuringReadback,
}

/// A publish that did not finish cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishFailure {
    error: PlatformError,
    published: bool,
}

impl PublishFailure {
    /// Why the publish stopped.
    #[must_use]
    pub fn error(&self) -> &PlatformError {
        &self.error
    }

    /// Whether the target handle may already contain new bytes.
    #[must_use]
    pub const fn published(&self) -> bool {
        self.published
    }
}

/// Bytes read from the handle a path walk opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCapture {
    info: ObjectInfo,
    bytes: Vec<u8>,
}

impl ReadCapture {
    /// Identity of the handle that was read.
    #[must_use]
    pub const fn info(&self) -> ObjectInfo {
        self.info
    }

    /// File bytes. Empty when the file is empty.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One name from a handle-based directory query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    name: String,
    end_of_file: u64,
    is_directory: bool,
    is_reparse: bool,
}

impl DirEntry {
    /// File name. `.` and `..` are omitted.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// End of file for a non-directory. Zero for directories.
    #[must_use]
    pub const fn end_of_file(&self) -> u64 {
        self.end_of_file
    }

    /// The entry is a directory and not a reparse point.
    #[must_use]
    pub const fn is_directory(&self) -> bool {
        self.is_directory && !self.is_reparse
    }

    /// The entry is a reparse point. It was not opened.
    #[must_use]
    pub const fn is_reparse(&self) -> bool {
        self.is_reparse
    }
}

/// Reads identity for an existing path without following a final reparse point.
pub fn inspect(path: &Path) -> Result<ObjectInfo, PlatformError> {
    sys::inspect(path)
}

/// Opens `components` underneath `root` by relative handle opens.
pub fn open_tree(root: &Path, components: &[String]) -> Result<OpenedTarget, PlatformError> {
    sys::open_tree(root, components).map(|inner| OpenedTarget { inner })
}

/// Identity of one relative path, taken from the handle the walk opened.
pub fn stat_tree(root: &Path, components: &[String]) -> Result<ObjectInfo, PlatformError> {
    sys::stat_tree(root, components)
}

/// Reads a regular file through the handle the walk opened.
///
/// A reparse point or a link count other than 1 is refused before the bytes are returned.
pub fn read_tree(
    root: &Path,
    components: &[String],
    max: u64,
) -> Result<ReadCapture, PlatformError> {
    sys::read_tree(root, components, max).map(|(info, bytes)| ReadCapture { info, bytes })
}

/// Lists one directory through the handle the walk opened.
///
/// Child reparse points are reported and not opened. More than `max_entries` names is an error.
pub fn list_tree(
    root: &Path,
    components: &[String],
    max_entries: usize,
) -> Result<Vec<DirEntry>, PlatformError> {
    sys::list_tree(root, components, max_entries).map(|entries| {
        entries
            .into_iter()
            .map(|(name, end_of_file, is_directory, is_reparse)| DirEntry {
                name,
                end_of_file,
                is_directory,
                is_reparse,
            })
            .collect()
    })
}

/// Protects `plaintext` so only the current Windows user can unprotect it.
pub fn protect(plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    sys::protect(plaintext)
}

/// Reverses [`protect`]. A modified ciphertext is an error.
pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    sys::unprotect(ciphertext)
}

/// Restricts `directory` to the current user and LocalSystem.
pub fn restrict_directory(directory: &Path) -> Result<(), PlatformError> {
    sys::restrict_directory(directory)
}

/// Accepts the directory only when its DACL does not grant other principals.
pub fn require_restricted(directory: &Path) -> Result<(), PlatformError> {
    sys::require_restricted(directory)
}

/// Exclusive lock released when the guard is dropped, including on process exit.
pub fn try_lock_exclusive(path: &Path) -> Result<ExclusiveLock, PlatformError> {
    sys::try_lock_exclusive(path).map(|file| ExclusiveLock { file })
}

/// Holds an exclusive lock on a file.
pub struct ExclusiveLock {
    file: File,
}

impl ExclusiveLock {
    /// The locked file. Closing it releases the lock.
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }
}

/// Windows has a verified apply path. Other systems do not.
#[must_use]
pub const fn verified_apply_supported() -> bool {
    cfg!(windows)
}

/// Exit code and the combined console transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleCapture {
    /// Process exit code.
    pub exit_code: u32,
    /// Bytes written by the child to the console.
    pub output: Vec<u8>,
}

/// Runs `program` on a pseudoconsole and writes `input` to that console.
///
/// Non-Windows builds return [`PlatformError::Unsupported`].
pub fn spawn_console(
    program: &Path,
    args: &[OsString],
    input: &str,
) -> Result<ConsoleCapture, PlatformError> {
    sys::spawn_console(program, args, input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("lca-platform-{label}-{nanos}"));
        std::fs::create_dir_all(&path).expect("temp");
        path
    }

    #[test]
    fn unsupported_platforms_fail_closed() {
        if verified_apply_supported() {
            return;
        }
        let path = temp_dir("unsupported");
        let file = path.join("notes.txt");
        std::fs::write(&file, b"alpha\n").expect("write");
        assert!(matches!(inspect(&file), Err(PlatformError::Unsupported)));
        assert!(matches!(
            protect(b"secret"),
            Err(PlatformError::Unsupported)
        ));
        assert!(matches!(
            restrict_directory(&path),
            Err(PlatformError::Unsupported)
        ));
        let _ = std::fs::remove_dir_all(path);
    }

    #[cfg(windows)]
    #[test]
    fn file_ids_are_stable_and_distinct() {
        let root = temp_dir("ids");
        let left = root.join("left.txt");
        let right = root.join("right.txt");
        std::fs::write(&left, b"alpha\n").expect("left");
        std::fs::write(&right, b"beta\n").expect("right");
        let first = inspect(&left).expect("inspect");
        let second = inspect(&left).expect("again");
        assert_eq!(first, second);
        assert_ne!(first.file_id(), [0; 16]);
        assert_eq!(first.link_count(), 1);
        assert!(!first.is_reparse());
        let other = inspect(&right).expect("right");
        assert_ne!(first.file_id(), other.file_id());
        let directory = inspect(&root).expect("dir");
        assert!(directory.is_directory());
        assert_ne!(directory.file_id(), first.file_id());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn hardlinks_share_a_file_id_and_increase_the_link_count() {
        let root = temp_dir("links");
        let left = root.join("left.txt");
        let right = root.join("right.txt");
        std::fs::write(&left, b"alpha\n").expect("left");
        std::fs::hard_link(&left, &right).expect("link");
        let info = inspect(&left).expect("inspect");
        let alias = inspect(&right).expect("alias");
        assert_eq!(info.file_id(), alias.file_id());
        assert!(info.link_count() > 1, "{}", info.link_count());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn protect_roundtrip_rejects_a_flipped_byte() {
        let plaintext = b"proposal-bytes-not-a-secret-log";
        let mut blob = protect(plaintext).expect("protect");
        let restored = unprotect(&blob).expect("unprotect");
        assert_eq!(restored, plaintext);
        let last = blob.len() - 1;
        blob[last] ^= 0x5a;
        assert!(matches!(unprotect(&blob), Err(PlatformError::Protect)));
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_is_a_reparse_point() {
        let root = temp_dir("junction");
        let outside = temp_dir("junction-out");
        std::fs::write(outside.join("secret.txt"), b"SENTINEL\n").expect("secret");
        let link = root.join("link");
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .expect("mklink");
        assert!(output.status.success(), "{output:?}");
        let info = inspect(&link).expect("inspect");
        assert!(info.is_reparse());
        let opened = open_tree(&root, &[String::from("link")]);
        assert!(matches!(opened, Err(PlatformError::Reparse)));
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn replace_with_keeps_the_file_id_and_reads_back() {
        let root = temp_dir("replace");
        std::fs::write(root.join("notes.txt"), b"alpha\n").expect("seed");
        let before = inspect(&root.join("notes.txt")).expect("before");
        let components = vec![String::from("notes.txt")];
        let mut opened = open_tree(&root, &components).expect("open");
        assert_eq!(opened.info().file_id(), before.file_id());
        let readback = opened
            .replace_with(b"beta\n", &root, &components, &mut |_| Ok(()))
            .expect("replace");
        assert_eq!(readback, b"beta\n");
        assert_eq!(
            std::fs::read(root.join("notes.txt")).expect("disk"),
            b"beta\n"
        );
        let after = inspect(&root.join("notes.txt")).expect("after");
        assert_eq!(after.file_id(), before.file_id());
        let captured = read_tree(&root, &components, 64).expect("read");
        assert_eq!(captured.bytes(), b"beta\n");
        assert_eq!(captured.info().file_id(), before.file_id());
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn read_tree_refuses_a_hardlink_without_returning_bytes() {
        let root = temp_dir("read-link");
        std::fs::write(root.join("secret.txt"), b"SENTINEL\n").expect("secret");
        std::fs::hard_link(root.join("secret.txt"), root.join("alias.txt")).expect("link");
        let error = read_tree(&root, &[String::from("alias.txt")], 64).expect_err("hardlink");
        assert!(matches!(error, PlatformError::Hardlink), "{error:?}");
        assert!(!error.to_string().contains("SENTINEL"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn list_tree_reports_a_junction_and_does_not_open_it() {
        let root = temp_dir("list-junction");
        let outside = temp_dir("list-junction-out");
        std::fs::write(outside.join("secret.txt"), b"SENTINEL\n").expect("secret");
        let link = root.join("link");
        let output = std::process::Command::new("cmd")
            .args([
                "/c",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .output()
            .expect("mklink");
        assert!(output.status.success(), "{output:?}");
        let entries = list_tree(&root, &[], 100).expect("list");
        let junction = entries
            .iter()
            .find(|entry| entry.name() == "link")
            .expect("link");
        assert!(junction.is_reparse());
        let nested = read_tree(
            &root,
            &[String::from("link"), String::from("secret.txt")],
            64,
        );
        assert!(matches!(nested, Err(PlatformError::Reparse)), "{nested:?}");
        assert!(!format!("{nested:?}").contains("SENTINEL"));
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    #[test]
    fn reserved_names_and_streams_are_rejected() {
        let root = temp_dir("reserved");
        std::fs::write(root.join("notes.txt"), b"alpha\n").expect("seed");
        for name in ["NUL", "CON", "COM1", "notes.txt:stream", ".."] {
            let opened = open_tree(&root, &[String::from(name)]);
            assert!(opened.is_err(), "{name}");
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn a_moved_parent_is_not_treated_as_the_checked_target() {
        let root = temp_dir("parent-swap");
        std::fs::create_dir(root.join("sub")).expect("sub");
        std::fs::write(root.join("sub").join("notes.txt"), b"alpha\n").expect("seed");
        let components = vec![String::from("sub"), String::from("notes.txt")];
        let mut opened = open_tree(&root, &components).expect("open");
        let renamed = std::fs::rename(root.join("sub"), root.join("sub-old"));
        if renamed.is_ok() {
            std::fs::create_dir(root.join("sub")).expect("new sub");
            std::fs::write(root.join("sub").join("notes.txt"), b"attacker\n").expect("attacker");
            let error = opened
                .replace_with(b"beta\n", &root, &components, &mut |_| Ok(()))
                .expect_err("must not publish onto the swapped name");
            assert!(!error.published(), "{error:?}");
            assert_eq!(
                std::fs::read(root.join("sub").join("notes.txt")).expect("attacker path"),
                b"attacker\n"
            );
            assert_eq!(
                std::fs::read(root.join("sub-old").join("notes.txt")).expect("original"),
                b"alpha\n"
            );
        } else {
            let readback = opened
                .replace_with(b"beta\n", &root, &components, &mut |_| Ok(()))
                .expect("original directory stayed in place");
            assert_eq!(readback, b"beta\n");
            assert_eq!(
                std::fs::read(root.join("sub").join("notes.txt")).expect("same object"),
                b"beta\n"
            );
        }
        drop(opened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn an_open_target_cannot_be_renamed_away() {
        let root = temp_dir("held");
        std::fs::write(root.join("notes.txt"), b"alpha\n").expect("seed");
        let components = vec![String::from("notes.txt")];
        let opened = open_tree(&root, &components).expect("open");
        let moved = root.join("moved.txt");
        let rename = std::fs::rename(root.join("notes.txt"), &moved);
        assert!(rename.is_err(), "{rename:?}");
        assert_eq!(
            std::fs::read(root.join("notes.txt")).expect("still there"),
            b"alpha\n"
        );
        drop(opened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn a_pseudoconsole_runs_a_child_and_returns_its_output() {
        let dir = temp_dir("conpty-child");
        let source = dir.join("child.rs");
        let program = dir.join("child.exe");
        let marker = dir.join("marker.txt");
        std::fs::write(
            &source,
            r#"fn main() {
                let stdin = std::io::IsTerminal::is_terminal(&std::io::stdin());
                let stdout = std::io::IsTerminal::is_terminal(&std::io::stdout());
                let path = std::env::args().nth(1).unwrap();
                std::fs::write(path, format!("{stdin} {stdout}")).unwrap();
                println!("lca-console-ok");
            }"#,
        )
        .expect("source");
        let compiled = std::process::Command::new("rustc")
            .args([
                "--edition",
                "2021",
                "-o",
                program.to_str().unwrap(),
                source.to_str().unwrap(),
            ])
            .output()
            .expect("rustc");
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let capture = spawn_console(
            &program,
            &[OsString::from(marker.as_os_str())],
            "approve probe\n",
        )
        .expect("console");
        let marker_body = std::fs::read_to_string(&marker).unwrap_or_default();
        let text = String::from_utf8_lossy(&capture.output);
        assert_eq!(capture.exit_code, 0, "{text}");
        assert_eq!(marker_body, "true true", "{marker_body} output {text:?}");
        assert!(text.contains("lca-console-ok"), "{text:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn restricted_directory_rejects_a_world_readable_default_only_after_we_can_set_it() {
        let root = temp_dir("acl");
        restrict_directory(&root).expect("restrict");
        require_restricted(&root).expect("check");
        let _ = std::fs::remove_dir_all(root);
    }
}
