# LCA-ARCH-14: Pinned in-place publication

- Status: Accepted
- Decision: Verified apply keeps publishing through the exclusive handle opened in LCA-01H. Directory replacement is not used. Atomic visibility is not claimed.
- Milestone: LCA-01I

## Context

LCA-01H writes the new bytes to the handle whose file id was checked. A crash during `WriteFile` can leave a prefix of the new bytes and a tail of the old bytes. `SetEndOfFile` has not run yet in that window, so a shorter replacement also keeps the previous tail. Readers can observe that mixture.

The question for this milestone was whether a directory-entry swap can remove that torn state without giving up the binding to the checked object.

## What was measured on this machine

`measured_windows_publication_options` recorded these results. They are not inferred from the API names.

| Operation | Handle on the target | Result |
| --- | --- | --- |
| `FileRenameInformationEx` with `FILE_RENAME_REPLACE_IF_EXISTS \| FILE_RENAME_POSIX_SEMANTICS` | `FILE_SHARE_READ` only | Fails. The recorded statuses include a sharing denial (`32`, `0xC0000043`, or `0xC0000022`). |
| `std::fs::rename` of that name | `FILE_SHARE_READ \| FILE_SHARE_DELETE` | Succeeds. The verified name can be moved while the handle is open. |
| POSIX replace of a flushed staged file onto that name | `FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE` | Succeeds. The old handle keeps the old file id and the old bytes and is delete-pending. A later open of the name has the staged file's id and the new bytes. |
| Exclusive byte-range lock, then `std::fs::rename` | `FILE_SHARE_DELETE` plus `LockFileEx` | The rename still succeeds. The lock does not pin the directory entry. |
| `ReplaceFileW` | `FILE_SHARE_READ` only | The call fails. |
| `ReplaceFileW` with a backup name, no handle held | none | Succeeds. The name's file id becomes the replacement's file id. The backup contains the old bytes. |

Microsoft documents the same split. [MS-FSCC] FileRenameInformationEx says that with `FILE_RENAME_POSIX_SEMANTICS`, existing handles to the replaced file stay valid and later opens of the name open the renamed file. `ReplaceFileW` says the resulting file has the same file id as the replacement file, and it documents intermediate failures: `ERROR_UNABLE_TO_MOVE_REPLACEMENT` can remove the replaced name, and `ERROR_UNABLE_TO_MOVE_REPLACEMENT_2` can leave the replaced file under another name. `REPLACEFILE_WRITE_THROUGH` is documented as not supported. `ReplaceFileW` opens the replaced file with `FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE`, so it cannot run while this process holds the exclusive handle.

Transactional NTFS is not used. Microsoft's TxF deprecation note recommends `ReplaceFile` for document-like files. That recommendation does not supply a file-id precondition, and the error contract shows the call is several steps.

`FlushFileBuffers` is documented for a file handle with write access, and for a volume handle with administrative rights. It is not a documented directory-metadata flush for an ordinary process. A successful flush is not a power-loss proof.

## Decision

Publication stays an in-place write on the handle opened with `FILE_SHARE_READ` only.

1. The handle's file id, volume, link count, and reparse state are checked, and the original bytes are read from that handle.
2. Those original bytes are sealed in a DPAPI evidence file and `FlushFileBuffers` is not the evidence flush: the evidence file is written, `sync_all` is called, and the file is renamed into place before the target is modified.
3. A same-directory temporary file receives the full new image, is flushed, and is read back. It is not published.
4. The target handle is checked again.
5. `WriteFile` then `SetEndOfFile` then `FlushFileBuffers` run on that same handle.
6. The handle is read back. Success requires the new bytes and the same file id.

There is no fallback to `ReplaceFileW`, `FileRenameInformationEx`, or `std::fs::rename`. If the exclusive open fails, apply stops.

## Trade-off

Identity and atomic visibility were not both available.

The exclusive handle is what stops another caller from moving the name before the write. POSIX replace and `ReplaceFileW` need that pin to be released, and once delete is shared the name can move first. A byte-range lock did not close that hole. Writing the checked handle can tear. Swapping the directory entry can show either the old file or the new file to a later open, and it changes the file id.

Priority is the checked object. The torn write is reported as `Unclear` when the bytes match neither hash. It is not repaired.

## What is not claimed

- A reader never observes a partial file. A kill after the first `WriteFile` and before `SetEndOfFile` left `beta\n\n` for a replacement of `alpha\n` with `beta\n`.
- Power-loss durability of the directory entry or of the evidence rename. Process kill and power loss are different. The kill tests use `taskkill /F`.
- That `link_count == 1` means the file was never linked under a protected name.
- A same-user boundary. DPAPI and the store ACL do not stop this user.
