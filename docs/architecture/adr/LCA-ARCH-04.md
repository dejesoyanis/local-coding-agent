# LCA-ARCH-04: Capability-based workspace sandbox

- Status: Accepted
- Decision: C
- Milestone: LCA-01D

## Context

LCA-01A confines some paths with `WorkspaceScope` and then refuses to run them. That scope still accepts an absolute path when the normalized result stays inside the root. LCA-01C validates structured calls and does not execute them. `diagnostic_echo` stays unexecuted. `lca ask` still streams text.

The next tools read and, after an explicit local confirmation, patch one existing text file. Model output is not a trusted path and not a trusted approval.

## Decision

Use a capability-based workspace sandbox, separate from the LCA-01C validator.

1. `WorkspaceSandbox` captures one canonical directory at construction. That root does not change for the life of the value. Model arguments cannot replace it.
2. Caller paths are relative components only. Absolute paths, drive prefixes, UNC paths, device paths, alternate data streams, NUL and other control characters, and `..` are rejected before any join. Each existing component is checked with `symlink_metadata`. A symlink, junction, or other reparse point is rejected instead of followed. The canonical result must stay inside the root, compared component-wise, including Windows case folding.
3. Read tools run after `validate_batch` when policy allows `WorkspaceRead` plus a read-only effect. `apply_patch` is registered as `WorkspaceMutation` plus `ApprovalRequired`. Validation still does not write. `execute_validated` prepares the patch in memory. `apply_granted` is the only write, and only with a grant issued from the confirmation line of that prepared action.
4. `ToolRegistry::diagnostic` stays the single-tool probe registry. Filesystem tools live on `ToolRegistry::workspace`. `RejectingToolExecutor` is unchanged.
5. `require_write_approval = false` is a configuration error. There is no blanket write permission and no model-controlled `--yes`.

```text
model tool call
  -> propose_actions
  -> validate_batch          schema, size, policy
  -> WorkspaceSandbox        relative path, reparse, root
  -> read tool, or prepare
  -> user confirmation line  same process, exact binding
  -> apply_granted           re-resolve, re-hash, rename
```

`lca ask` does not enter this path.

## Consequences

- `WorkspaceScope` and `WorkspaceSandbox` both exist. The older scope still answers the LCA-01A question "is this path inside the root?". The sandbox answers the stricter question "is this an untrusted relative path that can be opened without following a reparse point?".
- On Windows the stable standard library does not expose the NTFS file index. File identity is creation time, last write time, and length. Content SHA-256 is the conflict check. Neither value closes a check-then-open race.
- `FILE_FLAG_OPEN_REPARSE_POINT` is set on the final open. It does not stop the operating system from following an intermediate junction. The component walk is the control that rejects those components. Directory listing still uses `read_dir` after that walk.
- A same-directory `std::fs::rename` replaces one file. It is not a transaction. A failed verify after the rename does not roll the target back.
- Write approval cannot be turned off in configuration. A new process starts with an empty in-memory ledger, so a previous confirmation does not survive.

## Alternatives not taken

- Extending `WorkspaceScope` and executing through `RejectingToolExecutor`. That would make the LCA-01C "validation does not execute" tests false, and it would keep accepting absolute paths.
- A persisted approval token or a separate `patch apply` command. The confirmation would then have to be stored and replayed. This milestone keeps the grant inside the process that printed the diff.
- Treating a model argument, a JSON field, or a CLI flag as approval.
- Following symlinks that point back inside the workspace. Any reparse point is denied, including a cloud placeholder that Windows reports as a reparse point.
