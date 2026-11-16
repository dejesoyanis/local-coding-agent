//! Stores a prepared patch outside the workspace.
//!
//! The agent run does not approve the proposal and does not modify the source file.

use lca_tools::{PreparedPatch, ProposalStore, WorkspaceSandbox};

pub(crate) fn persist_prepared(
    sandbox: &WorkspaceSandbox,
    patches: &[&PreparedPatch],
) -> Result<Vec<String>, String> {
    if patches.is_empty() {
        return Ok(Vec::new());
    }
    let store = ProposalStore::user_local().map_err(|error| error.to_string())?;
    let mut ids = Vec::with_capacity(patches.len());
    for patch in patches {
        let summary = store
            .save(sandbox, patch)
            .map_err(|error| error.to_string())?;
        ids.push(summary.id);
    }
    Ok(ids)
}
