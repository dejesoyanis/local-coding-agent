//! Platform selection. Non-Windows builds fail closed.

use std::path::Path;

use crate::{ObjectInfo, PlatformError, PublishFailure, PublishPhase};

#[cfg(windows)]
#[path = "console.rs"]
mod console;
#[cfg(windows)]
#[path = "windows.rs"]
pub(crate) mod windows;
#[cfg(windows)]
pub(crate) use windows as imp;

#[cfg(not(windows))]
#[path = "unsupported.rs"]
pub(crate) mod unsupported;
#[cfg(not(windows))]
pub(crate) use unsupported as imp;

pub(crate) struct OpenedTarget {
    inner: imp::OpenedTarget,
}

impl OpenedTarget {
    pub(crate) fn info(&self) -> ObjectInfo {
        self.inner.info()
    }

    pub(crate) fn refresh_links(&self) -> Result<u32, PlatformError> {
        self.inner.refresh_links()
    }

    pub(crate) fn read(&self, max: u64) -> Result<Vec<u8>, PlatformError> {
        self.inner.read(max)
    }

    pub(crate) fn replace_with(
        &mut self,
        bytes: &[u8],
        root: &Path,
        components: &[String],
        hook: &mut dyn FnMut(PublishPhase) -> Result<(), PlatformError>,
    ) -> Result<Vec<u8>, PublishFailure> {
        self.inner.replace_with(bytes, root, components, hook)
    }
}

pub(crate) fn inspect(path: &Path) -> Result<ObjectInfo, PlatformError> {
    imp::inspect(path)
}

pub(crate) fn open_tree(root: &Path, components: &[String]) -> Result<OpenedTarget, PlatformError> {
    imp::open_tree(root, components).map(|inner| OpenedTarget { inner })
}

pub(crate) fn stat_tree(root: &Path, components: &[String]) -> Result<ObjectInfo, PlatformError> {
    imp::stat_tree(root, components)
}

pub(crate) fn read_tree(
    root: &Path,
    components: &[String],
    max: u64,
) -> Result<(ObjectInfo, Vec<u8>), PlatformError> {
    imp::read_tree(root, components, max)
}

pub(crate) fn list_tree(
    root: &Path,
    components: &[String],
    max_entries: usize,
) -> Result<Vec<(String, u64, bool, bool)>, PlatformError> {
    imp::list_tree(root, components, max_entries)
}

pub(crate) fn protect(plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    imp::protect(plaintext)
}

pub(crate) fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    imp::unprotect(ciphertext)
}

pub(crate) fn restrict_directory(directory: &Path) -> Result<(), PlatformError> {
    imp::restrict_directory(directory)
}

pub(crate) fn require_restricted(directory: &Path) -> Result<(), PlatformError> {
    imp::require_restricted(directory)
}

pub(crate) fn try_lock_exclusive(path: &Path) -> Result<std::fs::File, PlatformError> {
    imp::try_lock_exclusive(path)
}

pub(crate) fn spawn_console(
    program: &Path,
    args: &[std::ffi::OsString],
    input: &str,
) -> Result<crate::ConsoleCapture, PlatformError> {
    #[cfg(windows)]
    {
        console::spawn_console(program, args, input)
    }
    #[cfg(not(windows))]
    {
        let _ = (program, args, input);
        Err(PlatformError::Unsupported)
    }
}
