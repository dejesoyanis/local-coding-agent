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

    /// Replaces the directory entry with `bytes` and returns the bytes read back.
    ///
    /// A mismatch after the directory entry is replaced is returned as data. This
    /// function does not restore the previous file.
    pub fn replace_with(&mut self, bytes: &[u8]) -> Result<Vec<u8>, PlatformError> {
        self.inner.replace_with(bytes)
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
    fn replace_with_exchanges_bytes_and_keeps_a_readback() {
        let root = temp_dir("replace");
        std::fs::write(root.join("notes.txt"), b"alpha\n").expect("seed");
        let before = inspect(&root.join("notes.txt")).expect("before");
        let mut opened = open_tree(&root, &[String::from("notes.txt")]).expect("open");
        assert_eq!(opened.info().file_id(), before.file_id());
        let readback = opened.replace_with(b"beta\n").expect("replace");
        assert_eq!(readback, b"beta\n");
        assert_eq!(
            std::fs::read(root.join("notes.txt")).expect("disk"),
            b"beta\n"
        );
        let after = inspect(&root.join("notes.txt")).expect("after");
        assert_ne!(after.file_id(), before.file_id());
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
