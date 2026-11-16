# LCA-ARCH-10: Windows filesystem identity and race hardening

- Status: Accepted
- Decision: Verified apply is Windows-only and uses NTFS file identity plus a relative open
- Milestone: LCA-01G

## Context

LCA-01D identified these limits and did not claim to have closed them:

- Check-then-open races on path strings
- A junction swapped in after a component check
- No NTFS file id, so identity was creation time, last write, and length
- A hardlink inside the workspace can name the same bytes as a path outside it
- A failed read-back after `rename` does not restore the previous bytes

Those limits stay limits until a test shows otherwise. Linux and macOS do not inherit a Windows result.

## Decision

`lca-platform` is the only crate that uses `unsafe`. The workspace forbids `unsafe` everywhere else. On Windows the verified apply path uses:

- `CreateFileW` on the workspace root with backup semantics and `FILE_FLAG_OPEN_REPARSE_POINT`
- `NtCreateFile` relative to the parent handle, opening the last component with `FILE_OPEN_REPARSE_POINT`
- `GetFileInformationByHandleEx` for `FileIdInfo`, `FileStandardInfo`, and `FileAttributeTagInfo`

`FileIdInfo` supplies the volume serial and the 128-bit file id. Prepare stores that pair. Apply opens the tree again and refuses the write unless the id matches. A zero file id is unverifiable and is refused. A reparse point, including a symlink or junction, is refused. A non-directory with `link_count != 1` is refused, so a patch target that is a hardlink is not written. Ordinary reads do not use this rule: a hardlink alias of a protected name can still be read, which is the same privacy limit LCA-01D recorded.

The replacement file is created in the target's parent directory, on the same volume, with a relative open. The target handle is closed, then `NtSetInformationFile` with `FileRenameInformation` and `ReplaceIfExists` swaps the names. The bytes are read back from the handle that was written. A hash mismatch returns `verify_failed`. The previous bytes are not restored. That is not a transaction and not a rollback.

The in-process approval binding is now `LCA-01G-APPROVAL-V2` and includes the volume serial and the file id in addition to the path and the hashes.

Non-Windows `lca-platform` returns `Unsupported`. Persistent save and verified apply fail closed there. The legacy string-based temp-file rename is not used on Windows. It remains only for non-Windows builds of the in-memory path, and those builds still cannot persist a proposal.

## Consequences

- The apply walk does not re-canonicalize the string for each component. It still has a window after the target handle is closed and before the relative rename. That window is not closed.
- Directory fsync is not claimed. The proposal file is `sync_all`'d before its own rename. The workspace replace is not a crash-atomic transaction.
- Alternate data streams, device paths, and UNC paths stay rejected by the existing relative-path policy. This milestone does not add a new opener for them.
- A parent directory swapped for a junction fails the relative open when the component is a reparse point. A race that replaces a component with a non-reparse directory after the handle walk is not separately tested.
