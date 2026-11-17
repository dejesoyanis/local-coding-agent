# LCA-ARCH-20: Atomic publication feasibility

- Status: Accepted
- Decision: Atomic publication is not established. The production publisher stays the pinned in-place write from LCA-ARCH-14 and LCA-ARCH-19. No rename, `MoveFileExW`, or `ReplaceFileW` path is added.
- Milestone: LCA-01K

## Context

LCA-01H pins the target with an exclusive handle (`FILE_SHARE_READ` only) and writes that handle. LCA-01I measured that a directory swap needs `FILE_SHARE_DELETE` and then changes the file id. LCA-01J kept that publisher and added a separate restoration for the torn file. This milestone asks whether any available Windows operation can meet the identity pin and whole-file visibility at the same time.

The measurements are from Windows 10.0.26200 on NTFS (`volume_flags=0x3e72eff`). They are process observations. None of them is a power-loss result.

## What was compared

| Strategy | Operation | Joint result |
| --- | --- | --- |
| A | `WriteFile`, `SetEndOfFile`, `FlushFileBuffers` on the checked handle | The file id stays. A second process cannot rename the name while `FILE_SHARE_DELETE` is absent (`32`). The same write is visibly torn, and `taskkill /F` during the write leaves `beta\n\n` for `alpha\n` replaced by `beta\n`. |
| B | `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH` (`0x9`) | Succeeds when no conflicting handle is held and the name's file id becomes the staged file's id. An exclusive handle makes the call return `5`. |
| C | `ReplaceFileW` with flags `0`, backup name set | Succeeds when no conflicting handle is held. The name's file id becomes the replacement's id. The backup keeps the old id and the old bytes. An exclusive handle makes the call return `32`. Flags `1` also returned success. That return is not a durability result. Microsoft documents `REPLACEFILE_WRITE_THROUGH` as unsupported. |
| D | `FileRenameInfoEx` with `FILE_RENAME_REPLACE_IF_EXISTS \| FILE_RENAME_POSIX_SEMANTICS` (`0x3`) | Against the exclusive pin, `NtSetInformationFile` returns `0xC0000043`. With `FILE_SHARE_DELETE`, a completed call leaves the old handle on the old id and the old bytes, delete-pending, and a later open sees the staged id. |
| E | Check the file id, then rename | `FILE_RENAME_INFORMATION_EX` has flags, a root handle, a name length, and a name. It has no file-id field. A swap inserted between the check and the rename published the staged bytes onto the swapped name. The checked handle still held the original bytes. |

## Decision

No measured strategy shows all of the following at once:

1. the name readers open is still the checked object at the swap
2. a concurrent rename cannot win
3. a crash leaves either the old bytes or the new bytes
4. reparse points and hard links stay refused
5. the crash evidence is `taskkill /F`, and power loss is not inferred from it

Strategy A has (2) and (5) for the rename pin, and fails (3). Strategies B, C, and D can show a later open of the name with the full staged bytes, and they fail (1) and (2) once the pin is released. Strategy E is not an API. A hard link created after the link-count check and before the write made an outside name observe the new bytes. That window is recorded. It is not closed here.

The production apply path is unchanged.

## What is not claimed

- Power-loss durability of any strategy. `FlushFileBuffers` flushes a file handle. It is not a directory flush, and a volume flush needs administrative rights. A kill after `SetEndOfFile` already showed `beta\n` to the next process. That is not a disk-platter result.
- That a spinner which saw no mixed file has proved atomic visibility.
- That eight successful or denied renames are a formal race proof.
- That `ReplaceFileW` flags `1` enabled write-through because the call returned success.
- A same-user boundary. The attacker in these tests is another process of the same user.
