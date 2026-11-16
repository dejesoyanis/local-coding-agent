//! Fail-closed stubs. A timestamp or inode is not treated as a verified apply.

use std::path::Path;

use crate::{ObjectInfo, PlatformError};

pub(crate) struct OpenedTarget;

impl OpenedTarget {
    pub(crate) fn info(&self) -> ObjectInfo {
        ObjectInfo {
            volume_serial: 0,
            file_id: [0; 16],
            link_count: 0,
            end_of_file: 0,
            is_reparse: false,
            is_directory: false,
        }
    }

    pub(crate) fn refresh_links(&self) -> Result<u32, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub(crate) fn read(&self, _max: u64) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::Unsupported)
    }

    pub(crate) fn replace_with(&mut self, _bytes: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
}

pub(crate) fn inspect(_path: &Path) -> Result<ObjectInfo, PlatformError> {
    Err(PlatformError::Unsupported)
}

pub(crate) fn open_tree(
    _root: &Path,
    _components: &[String],
) -> Result<OpenedTarget, PlatformError> {
    Err(PlatformError::Unsupported)
}

pub(crate) fn protect(_plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    Err(PlatformError::Unsupported)
}

pub(crate) fn unprotect(_ciphertext: &[u8]) -> Result<Vec<u8>, PlatformError> {
    Err(PlatformError::Unsupported)
}

pub(crate) fn restrict_directory(_directory: &Path) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported)
}

pub(crate) fn require_restricted(_directory: &Path) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported)
}

pub(crate) fn try_lock_exclusive(_path: &Path) -> Result<std::fs::File, PlatformError> {
    Err(PlatformError::Unsupported)
}
