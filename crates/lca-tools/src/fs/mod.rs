//! Filesystem tools that run only after LCA-01C validation.
//!
//! [`execute_validated`] never writes. [`apply_granted`] writes one reviewed patch.
//! Restoration uses `apply_image_controlled`, which calls that same NTFS publisher.

mod limits;
mod list;
mod patch;
mod read;
mod search;

use crate::action::ValidatedAction;
use crate::fs_error::FsError;
use crate::sandbox::WorkspaceSandbox;

pub use limits::{
    DEFAULT_MAX_DIRECTORY_ENTRIES, DEFAULT_MAX_FILE_SIZE_BYTES, DEFAULT_MAX_RESPONSE_BYTES,
    DEFAULT_MAX_SEARCH_FILES, DEFAULT_MAX_SEARCH_MATCHES, DEFAULT_MAX_SEARCH_TOTAL_BYTES,
    FsLimitValues, FsLimits,
};
pub use list::{DirectoryEntry, ListResult};
pub use patch::{ApplyFault, ApplyResult, ApprovalGrant, ApprovalLedger, KillHold, PreparedPatch};
pub(crate) use patch::{
    BoundFileId, RESTORATION_IMAGE_MARKER, StoredPatch, apply_granted_controlled,
    apply_image_controlled, restore_prepared,
};
pub use read::ReadResult;
pub use search::{SearchMatch, SearchResult};

/// What a validated filesystem action produced.
///
/// `Prepared` means the new bytes exist only in memory.
#[derive(Debug)]
pub enum FsOutcome {
    /// `diagnostic_echo` stays validated and unexecuted.
    NotExecuted {
        /// Tool name.
        tool: String,
    },
    /// Directory listing.
    Listed(ListResult),
    /// File read.
    Read(ReadResult),
    /// Literal search.
    Searched(SearchResult),
    /// Patch preview. The workspace file is unchanged.
    Prepared(Box<PreparedPatch>),
}

/// Runs a validated action.
///
/// Read tools run immediately. `apply_patch` prepares a change and returns it.
/// This function does not accept an approval line, so model text cannot grant a write.
pub fn execute_validated(
    action: &ValidatedAction,
    sandbox: &WorkspaceSandbox,
    limits: &FsLimits,
) -> Result<FsOutcome, FsError> {
    match action.name() {
        "diagnostic_echo" => Ok(FsOutcome::NotExecuted {
            tool: "diagnostic_echo".to_owned(),
        }),
        "list_directory" => {
            let path = required_string(action, "path")?;
            Ok(FsOutcome::Listed(list::list_directory(
                sandbox, limits, path,
            )?))
        }
        "read_file" => {
            let path = required_string(action, "path")?;
            Ok(FsOutcome::Read(read::read_file(sandbox, limits, path)?))
        }
        "search_files" => {
            let query = required_string(action, "query")?;
            let path = optional_string(action, "path").unwrap_or(".");
            Ok(FsOutcome::Searched(search::search_files(
                sandbox, limits, query, path,
            )?))
        }
        "apply_patch" => {
            let path = required_string(action, "path")?;
            let patch = required_string(action, "patch")?;
            let prepared = patch::prepare_patch(sandbox, limits, action.id().get(), path, patch)?;
            Ok(FsOutcome::Prepared(Box::new(prepared)))
        }
        other => Err(FsError::UnsupportedTool {
            name: other.chars().take(64).collect(),
        }),
    }
}

/// Writes a prepared patch when `grant` was issued for it.
pub fn apply_granted(
    sandbox: &WorkspaceSandbox,
    prepared: &PreparedPatch,
    grant: ApprovalGrant,
    ledger: &ApprovalLedger,
) -> Result<ApplyResult, FsError> {
    patch::apply_granted(sandbox, prepared, grant, ledger)
}

fn required_string<'a>(action: &'a ValidatedAction, field: &str) -> Result<&'a str, FsError> {
    action
        .arguments()
        .as_value()
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| FsError::InvalidArguments {
            message: format!("field `{field}` must be a non-empty string"),
        })
}

fn optional_string<'a>(action: &'a ValidatedAction, field: &str) -> Option<&'a str> {
    action
        .arguments()
        .as_value()
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
}
