//! Size and count limits for the filesystem tools.
//!
//! Missing configuration uses [`FsLimits::conservative`]. A zero limit is rejected.

use crate::fs_error::FsError;

/// Default maximum size of one text file, in bytes (1 MiB).
pub const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 1_048_576;

/// Default maximum tool response, in bytes (256 KiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: u64 = 262_144;

/// Default maximum directory entries returned after sorting.
pub const DEFAULT_MAX_DIRECTORY_ENTRIES: usize = 1_000;

/// Default maximum search hits.
pub const DEFAULT_MAX_SEARCH_MATCHES: usize = 100;

/// Default maximum files a search may read.
pub const DEFAULT_MAX_SEARCH_FILES: usize = 1_000;

/// Default maximum bytes a search may read (32 MiB).
pub const DEFAULT_MAX_SEARCH_TOTAL_BYTES: u64 = 33_554_432;

const MAX_FILE_SIZE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_SEARCH_MATCHES: usize = 10_000;
const MAX_SEARCH_FILES: usize = 100_000;
const MAX_SEARCH_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Hard cap on names held for one directory so a huge folder cannot exhaust memory.
pub(crate) const MAX_DIRECTORY_SCAN: usize = 100_000;

/// Limits that accompany one sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsLimits {
    read_enabled: bool,
    write_enabled: bool,
    max_file_size_bytes: u64,
    max_response_bytes: u64,
    max_directory_entries: usize,
    max_search_matches: usize,
    max_search_files: usize,
    max_search_total_bytes: u64,
}

/// Values accepted by [`FsLimits::try_new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsLimitValues {
    /// Whether read tools may run.
    pub read_enabled: bool,
    /// Whether patch preparation may run. Application still requires approval.
    pub write_enabled: bool,
    /// Maximum file size in bytes.
    pub max_file_size_bytes: u64,
    /// Maximum bytes returned by one read.
    pub max_response_bytes: u64,
    /// Maximum directory entries returned.
    pub max_directory_entries: usize,
    /// Maximum search hits.
    pub max_search_matches: usize,
    /// Maximum files a search may read.
    pub max_search_files: usize,
    /// Maximum bytes a search may read.
    pub max_search_total_bytes: u64,
}

impl FsLimits {
    /// Conservative defaults used when configuration omits the tools section.
    #[must_use]
    pub const fn conservative() -> Self {
        Self {
            read_enabled: true,
            write_enabled: true,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_directory_entries: DEFAULT_MAX_DIRECTORY_ENTRIES,
            max_search_matches: DEFAULT_MAX_SEARCH_MATCHES,
            max_search_files: DEFAULT_MAX_SEARCH_FILES,
            max_search_total_bytes: DEFAULT_MAX_SEARCH_TOTAL_BYTES,
        }
    }

    /// Rejects a zero limit and any limit above the hard cap.
    pub fn try_new(values: FsLimitValues) -> Result<Self, FsError> {
        if values.max_file_size_bytes == 0 || values.max_file_size_bytes > MAX_FILE_SIZE_BYTES {
            return Err(invalid_limit("max_file_size_bytes"));
        }
        if values.max_response_bytes == 0 || values.max_response_bytes > values.max_file_size_bytes
        {
            return Err(invalid_limit("max_response_bytes"));
        }
        if values.max_directory_entries == 0 || values.max_directory_entries > MAX_DIRECTORY_ENTRIES
        {
            return Err(invalid_limit("max_directory_entries"));
        }
        if values.max_search_matches == 0 || values.max_search_matches > MAX_SEARCH_MATCHES {
            return Err(invalid_limit("max_search_matches"));
        }
        if values.max_search_files == 0 || values.max_search_files > MAX_SEARCH_FILES {
            return Err(invalid_limit("max_search_files"));
        }
        if values.max_search_total_bytes == 0
            || values.max_search_total_bytes > MAX_SEARCH_TOTAL_BYTES
        {
            return Err(invalid_limit("max_search_total_bytes"));
        }
        Ok(Self {
            read_enabled: values.read_enabled,
            write_enabled: values.write_enabled,
            max_file_size_bytes: values.max_file_size_bytes,
            max_response_bytes: values.max_response_bytes,
            max_directory_entries: values.max_directory_entries,
            max_search_matches: values.max_search_matches,
            max_search_files: values.max_search_files,
            max_search_total_bytes: values.max_search_total_bytes,
        })
    }

    /// Copy of these limits with patch preparation turned off.
    ///
    /// Read limits are unchanged. This does not grant a write and does not disable approval.
    #[must_use]
    pub fn read_only(&self) -> Self {
        let mut limits = self.clone();
        limits.write_enabled = false;
        limits
    }

    #[must_use]
    pub const fn read_enabled(&self) -> bool {
        self.read_enabled
    }

    #[must_use]
    pub const fn write_enabled(&self) -> bool {
        self.write_enabled
    }

    #[must_use]
    pub const fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_bytes
    }

    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    #[must_use]
    pub const fn max_directory_entries(&self) -> usize {
        self.max_directory_entries
    }

    #[must_use]
    pub const fn max_search_matches(&self) -> usize {
        self.max_search_matches
    }

    #[must_use]
    pub const fn max_search_files(&self) -> usize {
        self.max_search_files
    }

    #[must_use]
    pub const fn max_search_total_bytes(&self) -> u64 {
        self.max_search_total_bytes
    }
}

fn invalid_limit(name: &str) -> FsError {
    FsError::InvalidArguments {
        message: format!("filesystem limit `{name}` is outside the accepted range"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_defaults_match_the_documented_caps() {
        let limits = FsLimits::conservative();
        assert!(limits.read_enabled());
        assert!(limits.write_enabled());
        assert_eq!(limits.max_file_size_bytes(), 1_048_576);
        assert_eq!(limits.max_response_bytes(), 262_144);
        assert_eq!(limits.max_directory_entries(), 1_000);
        assert_eq!(limits.max_search_matches(), 100);
        assert_eq!(limits.max_search_files(), 1_000);
        assert_eq!(limits.max_search_total_bytes(), 33_554_432);
    }

    #[test]
    fn zero_and_oversized_limits_are_rejected() {
        let mut values = FsLimitValues {
            read_enabled: true,
            write_enabled: true,
            max_file_size_bytes: 32,
            max_response_bytes: 16,
            max_directory_entries: 2,
            max_search_matches: 2,
            max_search_files: 2,
            max_search_total_bytes: 64,
        };
        assert!(FsLimits::try_new(values).is_ok());
        values.max_file_size_bytes = 0;
        assert_eq!(
            FsLimits::try_new(values).expect_err("zero").kind(),
            "invalid_arguments"
        );
        values.max_file_size_bytes = 32;
        values.max_response_bytes = 64;
        assert!(FsLimits::try_new(values).is_err());
    }
}
