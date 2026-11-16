# LCA-ARCH-12: Verified apply without a close-then-rename window

- Status: Accepted
- Decision: Verified apply publishes by writing the already checked file handle. The close-then-rename path is removed. Atomic directory replacement is not claimed.
- Milestone: LCA-01H

## Context

LCA-01G closed the target handle and then called `NtSetInformationFile` with `FileRenameInformation`. The file id proved the identity of the closed handle. It did not prove that the directory entry still named that object at the rename.

## What Windows actually does

These results were measured on this machine, not inferred:

- `FileRenameInformation` (class 10) while the destination is open without `FILE_SHARE_DELETE` returns `STATUS_ACCESS_DENIED` (`0xC0000022`).
- `FileRenameInformationEx` (class 65) with `FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS` against a handle opened with only `FILE_SHARE_READ` returns `STATUS_SHARING_VIOLATION` (`0xC0000043`). POSIX rename does not replace a file that lacks `FILE_SHARE_DELETE`.
- `std::fs::rename` against that same handle fails with Win32 error 32. The file id does not change.
- `WriteFile` on that handle changes the bytes and keeps the file id. Writing a shorter buffer without `SetEndOfFile` leaves the previous tail in place.

A handle on a new temporary file does not bind the directory entry that the rename would replace. Holding the destination open without share-delete prevents the rename. The close-then-rename race therefore cannot be closed by keeping an exclusive handle across a rename. Transactional NTFS is not used.

## Decision

The unsafe close-then-rename path is deleted. There is no fallback that closes the handle and renames.

Publication is an in-place write on the verified handle:

1. The apply leaf is opened with `FILE_GENERIC_READ | FILE_WRITE_DATA | SYNCHRONIZE` and `FILE_SHARE_READ` only. If another writer already holds the file, the open fails closed with a sharing error. Apply does not retry with share-delete.
2. The handle's file id, volume, reparse tag, and link count must match the proposal. The original bytes are read from that handle and must match the original SHA-256.
3. A temporary file is created with `FILE_CREATE` under the parent handle, using a `.lca-{pid}-{nanos}.tmp` name. It is a staged image on the same volume. It is flushed, read back, and must equal the proposed bytes. It is not the published object.
4. The target handle is queried again. `GetFinalPathNameByHandleW` must still match the workspace root's final path plus the relative components, compared case-insensitively after stripping `\\?\` and `\\?\UNC\`. A mismatch aborts before the target is modified.
5. `publish_handle` rewinds the target, writes the bytes, sets the end of file with `SetEndOfFile`, and calls `FlushFileBuffers`.
6. The same handle is read back. Success requires the bytes, the file id, `link_count == 1`, a non-reparse file, and the same final path.

Any error after step 5 sets `published = true`. The proposal becomes `Unclear`. Nothing is written back.

## What this closes, and what it does not

Closed, and tested: another process cannot rename the open target away while share-delete is denied (`an_open_target_cannot_be_renamed_away`). A parent directory that can be moved is not treated as the checked target (`a_moved_parent_is_not_treated_as_the_checked_target`). On this machine the parent move failed while the child handle was open, and the publish stayed on the original object. If a future system allowed the parent move, the final-path check runs before the write and refuses.

Not closed, and not claimed:

- A parent rename that is undone before `confirm_bound` still names the same open object. The write stays on that object. It does not retarget the handle.
- A hardlink added during `WriteFile` can change `link_count` after the bytes are written. The post-write check then fails and the state is `Unclear`. The bytes are not rolled back.
- A crash during `WriteFile` can tear the file. `FlushFileBuffers` is a flush of this handle, not a transaction and not a directory-entry fsync.
- The staged temp file is delete-on-close. Its successful read-back is not atomic visibility of the target.
- Another process running as the same user, with a debugger or with code already inside this process, is outside the boundary LCA-01G accepted. DPAPI does not change that.
- ReFS, FAT, and non-Windows filesystems are not supported. A zero file id fails closed. Non-Windows persistent apply stays `Unsupported`.

## Separate properties

| Property | What this milestone provides |
| --- | --- |
| Identity of the written bytes | The open handle. The file id is unchanged by a successful publish. |
| Atomic visibility of the directory entry | Not provided. Readers can observe a short write. |
| Crash durability | `FlushFileBuffers` on the target after `SetEndOfFile`. Not a journaled transaction. |
| Rollback | Not performed. A failed check after the write leaves `Unclear`. |
