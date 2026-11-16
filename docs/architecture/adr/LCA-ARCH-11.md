# LCA-ARCH-11: Handle-bound Windows filesystem access

- Status: Accepted
- Decision: Workspace reads, listings, and verified apply open each path component from the parent handle and use that same handle for the access
- Milestone: LCA-01H

## Context

LCA-01G checked reparse points on the apply walk, then closed the target before the rename. Ordinary reads still resolved a path, checked it, and opened it again by string. A hardlink of a protected file was readable under the second name. A path string that survived a check is not the object that a later open returns.

## Decision

`lca-platform` remains the only crate that uses `unsafe`. The other crates stay safe Rust. On Windows, `read_tree`, `list_tree`, `stat_tree`, and `open_tree` share one walk:

1. `CreateFileW` opens the workspace root with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`. That handle is the trust anchor. A reparse root is refused.
2. Each earlier component is opened with `NtCreateFile` relative to the checked parent, with `FILE_OPEN_REPARSE_POINT` and `FILE_DIRECTORY_FILE`. A reparse point, including a junction or a symlink, is refused. The parent handle is not reopened by path.
3. The leaf is opened once, with the same relative `NtCreateFile` and `FILE_OPEN_REPARSE_POINT`. There is no probe-then-reopen. The leaf is not opened with `FILE_NON_DIRECTORY_FILE`, so a junction is observed as a reparse point instead of `STATUS_FILE_IS_A_DIRECTORY`.
4. `GetFileInformationByHandleEx` reads `FileIdInfo`, `FileStandardInfo`, and `FileAttributeTagInfo` from that handle. A zero file id is refused.

`read_tree` then reads with `ReadFile` on that handle. It returns bytes only when the handle is a regular file, `link_count == 1`, and a second query on the same handle still reports the same file id, volume, link count, reparse state, and size. `list_tree` uses `NtQueryDirectoryFile` with `FileBothDirectoryInformation` on the directory handle. Child reparse points are reported and are not opened. Names that the privacy policy hides are dropped before any content read.

Rejected before any open of that component: an empty name, `.`, `..`, a trailing space or dot, a slash, a backslash, a colon (which covers alternate data streams and drive-absolute forms), NUL, a control character, a name longer than 255 bytes, and the reserved stems `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and `LPT1`–`LPT9`. Absolute paths, UNC paths, and device paths never become components. The sandbox rejects them before the walk.

## Hardlink policy

`link_count` is read from the opened handle. `read_tree` returns `Hardlink` before copying bytes when the count is not 1. `search_files` treats that as a skip and does not put the bytes in a match. Patch prepare and verified apply use the same refusal. A second hardlink of a benign file is refused too. That is a false positive, and it is accepted.

`link_count == 1` does not prove the file is harmless. Unlinking the protected name can leave the remaining name at count 1. The policy cannot see a name that no longer exists. Case folding of the remaining name is still applied by the privacy policy before the open.

## API choice

`NtCreateFile` is used because `CreateFileW` has no relative-to-handle form that also keeps `FILE_OPEN_REPARSE_POINT` on every component. The structures are the `windows-sys` 0.59 definitions: `OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `IO_STATUS_BLOCK`, `FILE_ID_INFO`, `FILE_STANDARD_INFO`, `FILE_ATTRIBUTE_TAG_INFO`, and `FILE_BOTH_DIR_INFORMATION`. No custom ABI struct is declared for those calls.

Read and list share modes include read, write, and delete so an editor or indexer does not make a read fail. That share mode is not used for the apply target. Apply opens the leaf with `FILE_SHARE_READ` only.

## Consequences

- Windows reads and listings have no path-open fallback. A failure is a failure.
- Non-Windows reads stay on the existing nofollow path and also refuse `nlink > 1`. They were not executed in this milestone.
- A same-user process can still create a hardlink before the open. After the open, a count other than 1 is refused. A link created and removed before the open is not visible.
- Directory handles still share delete. Holding every directory exclusively conflicts with Explorer and antivirus. The file handle, not the directory share mode, is the read binding.
