# LCA-01K: Atomic publication feasibility

Decisions: [LCA-ARCH-20](adr/LCA-ARCH-20.md), [LCA-ARCH-21](adr/LCA-ARCH-21.md), [LCA-ARCH-22](adr/LCA-ARCH-22.md).

## Decision

Atomic publication is not established. The Windows apply path stays the pinned in-place publisher. This milestone does not add a second publisher, a rename fallback, or a `ReplaceFileW` fallback.

The host for every row below is Windows 10.0.26200, filesystem NTFS, `GetVolumeInformationW` flags `0x3e72eff`. Power loss was not produced. A line that says a crash left a full file means `taskkill /F` after that point, read back by the parent. It does not mean the disk would contain that image after power loss.

## Repository inspection

On the Windows build, `apply_granted_controlled` calls `apply_ntfs`. `apply_ntfs` opens the leaf with `open_tree` and publishes with `OpenedTarget::replace_with`. That function stages a temp image, discards it, and calls `publish_handle`: `WriteFile`, then `SetEndOfFile`, then `FlushFileBuffers`, then a read-back. The share mode on that leaf is `FILE_SHARE_READ` (`0x1`). `FILE_SHARE_DELETE` is not granted. `ReplaceFileW` and `FileRenameInfoEx` appear in this crate only inside tests.

`apply_image_controlled` uses the same `apply_ntfs` path. On non-Windows it returns `UnsupportedPlatform`. `ProposalStore::save` returns `UnsupportedPlatform` when `verified_apply_supported` is false, so the `#[cfg(not(windows))]` rename inside `apply_granted_controlled` is not the verified publisher and is not compiled into the Windows binary.

Workspace identity is the volume serial and file id of the workspace root (`LCA-01G-WORKSPACE-V1`). The target file id is captured from the handle. Proposal states are `Prepared`, `Approved`, `Applying`, `Applied`, `Rejected`, `Expired`, `Conflict`, `Failed`, and `Unclear`. Restoration states are a separate machine (`LCA-01J-RESTORATION-V1`) and still require a new confirmation line. Publication evidence is `LCA-01I-EVIDENCE-V1` with strategy byte `1`. A different strategy byte is rejected. The digest binds the file id. A matching hash on a different file id stays `Unclear`.

The file id is stable across the in-place write. The bytes are not replaced atomically.

## Threat model

The attacker is another process of the same user with write access in the workspace. The invariants are INV-01 through INV-09 in [LCA-ARCH-21](adr/LCA-ARCH-21.md). A hash is not an identity. An unclear file is not retried. An approval is not reused. The privacy policy is unchanged because the experimental code is not on the apply path.

## API contracts and what this run actually saw

Documented behavior and this run are separate.

| API | Documented | Observed on this NTFS volume |
| --- | --- | --- |
| `NtCreateFile` / `CreateFileW` share mode | A later open that needs `DELETE` fails unless existing handles passed `FILE_SHARE_DELETE`. | Second-process `MoveFileExW` of a name held with share `0`, `0x1`, or `0x3` returned `32` (`ERROR_SHARING_VIOLATION`). Share `0x5` and `0x7` let that rename return `0`. |
| `WriteFile` + `SetEndOfFile` + `FlushFileBuffers` | Byte writes on a handle. `FlushFileBuffers` flushes that file's buffers. A volume flush needs an administrator. Not a whole-file atomic replace. | File id unchanged. Shorter replacements and the 1 MiB equal-length file were mixed at `DuringPublish`. `taskkill /F` at `during_publication` left the torn image on the same file id. |
| `MoveFileExW` `MOVEFILE_REPLACE_EXISTING \| MOVEFILE_WRITE_THROUGH` (`0x9`) | Path operation. Replace is not a file-id precondition. | Uncontended: the name's file id became the staged id and the bytes were the staged bytes. Exclusive handle: return `5` (`ERROR_ACCESS_DENIED`), bytes unchanged. A concurrent `File::open` loop made the call return `5`; a later call with no reader returned `0`. |
| `ReplaceFileW` flags `0`, backup set | Several steps. On success the resulting file has the replacement's file id. The replaced file is opened with `FILE_SHARE_READ \| FILE_SHARE_WRITE \| FILE_SHARE_DELETE`. Documented failures can drop or rename the original. `REPLACEFILE_WRITE_THROUGH` is not supported. | Uncontended flags `0`: name id became the staged id, backup id stayed the original id, backup bytes stayed original. Exclusive handle: return `32`, bytes unchanged. Flags `1`: the call returned success. That is not a power-loss result and not evidence the flag was honored. The intermediate errors `1175`, `1176`, and `1177` were not induced. |
| `SetFileInformationByHandle` / `NtSetInformationFile` `FileRenameInfoEx` flags `0x3` | POSIX semantics: existing handles of the replaced file stay valid; later opens of the name see the renamed file. No file-id field. | Relative rename against the exclusive pin: `NtSetInformationFile` returned `0xC0000043` (`STATUS_SHARING_VIOLATION`). The Win32 wrapper also returned `87` for that buffer; `87` is not the sharing decision. With share `0x7`, the old handle kept the old id, the old bytes, and `DeletePending=1`. A new open saw the staged id and the staged bytes. |
| `LockFileEx` exclusive, fail-immediately, whole file | A byte lock is not a directory-entry lock. | With share `0x5` the rename still returned `0`. A fresh read of the moved name returned `33` (`ERROR_LOCK_VIOLATION`) until the locking handle closed. |
| `CreateHardLinkW` | Same file id, another name, same volume. | Returned `0` while the production handle was inside `BeforeRename`. The outside name then contained the new bytes. |
| `CreateSymbolicLinkW` flags `0x2` | May require `SeCreateSymbolicLinkPrivilege`. | Returned `1314` (`ERROR_PRIVILEGE_NOT_HELD`). Skipped. Not a pass. |
| `cmd mklink /J` | Junction, no symlink privilege. | The junction was created. `open_tree` returned `Reparse`. The outside file was unchanged. |

`FILE_RENAME_INFORMATION_EX` fields used here are the flags dword (`0x1` replace, `0x2` POSIX), the root handle, the name length, and the name. There is no compare-and-swap on a file id. Transactional NTFS is not used. Microsoft's alternatives note recommends `ReplaceFile` for a document-like file and recommends not taking a new dependency on TxF. That recommendation does not add a file-id precondition.

## Harness

`publication_probe` is the isolated harness described in [LCA-ARCH-22](adr/LCA-ARCH-22.md). Strategy A for the production rows calls `OpenedTarget::replace_with`. The share-mode matrix uses the same in-place sequence on a handle opened with the share under test. Strategies B, C, and D are local to the test module. Strategy E is the check-then-rename experiment, reported as a violation, not as an implementation.

## Target identity

Uncontended strategy A kept the file id and published `beta\n` over `alpha\n`.

Uncontended B and C changed the name's file id to the staged id. C's backup kept the original id and `alpha\n`. Uncontended D split the handles as in the table above.

With the pin omitting `FILE_SHARE_DELETE`, the second process's rename and swap returned `32`, strategy A then published on the same id, and strategy D's rename did not change the bytes. With share `0x5` or `0x7`:

- Strategy A wrote the still-open object. After a rename the path was missing and the moved name held `beta\n`. After a swap the path held the decoy and the moved name held `beta\n`. Classified as a violation.
- Strategy D then replaced whatever the name denoted. The path held `beta\n` under the staged id. The moved name held `alpha\n` under the checked id. Classified as a violation.

The production `replace_with` pause, with the real share `0x1`, denied rename, swap, and delete/recreate with `32`, and denied replace and parent rename with `5`. The file id was unchanged and the bytes were `beta\n`.

## Concurrent namespace

The production pin results are the rows above. Eight renames against share `0x1` all returned a denial. Eight renames against share `0x5` all succeeded. Both counts are labeled `formal_proof=false`.

The byte-range lock did not pin the name. Strategy E, after a successful file-id check on a share-`0x5` handle, allowed the second process to swap the name. The following `FileRenameInfoEx` published the staged bytes onto that swapped name. The checked handle still read `alpha\n`.

## Atomic visibility

Strategy A, production `replace_with`, eight reads of a fresh open and of an existing handle at `DuringPublish`:

| Size | Shape | Samples | Verdict |
| --- | --- | --- | --- |
| 4 KiB, 64 KiB, 1 MiB, 8 MiB | Proposed length was half. The hook ran before `SetEndOfFile`. | 8 mixed, 0 other. Length still the original length, first byte `0x22`, last byte `0x11`. | Mixed observed. Not atomic. |
| 4 KiB equal length | One `WriteFile` covers the file before the hook. | 8 full proposed, 0 mixed. | No mixed sample. Not a proof. |
| 1 MiB equal length | First chunk is 64 KiB. | 8 mixed. | Mixed observed. |

Final bytes after the call were the proposed image and the file id was unchanged. The tear is the window, not the successful return.

Strategy D, equal lengths 4 KiB through 8 MiB: the pre-opened handle read the full original pattern, a new open read the full proposed pattern, and the spinner mixed count was 0. Verdict `no_mixed_sample_not_a_proof`. The handle split matches the POSIX rename documentation. It is not a proof that a reader cannot observe a third state, and it was not a power-loss test.

Strategy B's in-call `MoveFileExW` returned `5` at each size while a reader loop was opening the name. After that loop stopped, the same call returned `0` and the file id changed. Spinner mixed count was 0. Not a proof.

Strategy C's `ReplaceFileW` returned `0` during the reader loop. The spinner recorded original reads and read errors (`spinner_other` from 15 to 31). Mixed count was 0. Not a proof. The backup held the original bytes.

## Process kill

The parent used `taskkill /F` on a child that was still running. The token stayed `single-use`. The parent did not write the target again. No audit marker was created. Power loss stays unproven.

| Point | A | B, C, D |
| --- | --- | --- |
| `before_staging`, `after_staging`, `after_flush`, `before_publication` | `alpha\n`, same file id | `alpha\n`, same file id |
| `during_publication` | `beta\n\n`, same file id | Not instrumentable. One syscall, no hook inside it. |
| `before_flush` | `beta\n`, same file id | Not instrumentable. |
| `after_publication`, `before_verification`, `before_audit` | `beta\n`, same file id | `beta\n`, new file id |

`before_flush` is after `SetEndOfFile` and before `FlushFileBuffers`. On this kill the next process already saw `beta\n`. That does not describe the disk cache after power loss.

## Reparse and hard links

| Case | Result |
| --- | --- |
| `CON`, `NUL`, `COM1`, `notes.txt:stream`, `..`, trailing space | Production `open_tree` rejected the component. |
| Hard link already present | `replace_with` returned `Hardlink` with `published=false`. Both names stayed `alpha\n`. |
| Hard link created at `BeforeRename` | `CreateHardLinkW` returned `0`. The outside name contained `beta\n` and the same file id. Classified as a violation. The publisher was not changed. |
| Directory junction | Created. `open_tree` returned `Reparse`. The outside sentinel was unchanged. |
| File symlink | `CreateSymbolicLinkW` returned `1314`. Skipped. Not a pass. |

## Comparison

| Property | A, current publisher | B `MoveFileExW` | C `ReplaceFileW` | D `FileRenameInfoEx` | E check then rename |
| --- | --- | --- | --- | --- | --- |
| Identity | Same file id on the pinned handle | Name takes the staged id | Name takes the replacement id; backup keeps the old id | Name takes the staged id; old handle keeps the old id | Check does not bind the rename |
| Namespace | Pin holds without share-delete | Exclusive handle returns `5` | Exclusive handle returns `32` | Relative rename returns `0xC0000043` | Swap-then-rename published the other name |
| Visible bytes | Torn window measured | No mixed sample; not a proof | No mixed sample; readers also saw errors | Old handle and new open differed; not a proof | Not a publisher |
| `taskkill /F` | Torn during the write; full image after `SetEndOfFile` | Full old or full new around the call; middle not instrumented | Same as B | Same as B | Not run as a publisher |
| Power loss | Unproven | Unproven | Unproven, including flags `1` | Unproven | Unproven |
| Privacy | Unchanged production policy | Not on the apply path | Not on the apply path | Not on the apply path | Not on the apply path |
| Hard link | Refused before the write. A link created in the pause was updated. | Not a fix | Not a fix | Not a fix | Not a fix |
| Reparse | Junction refused. File symlink not created (`1314`). | Would follow a later open of a path | `ReplaceFileW` takes paths | Rename takes a name | Same hole as D |
| ACL | Same file object. The DACL was not dumped. | Not measured | Documented preservation. Not measured here. | Not measured | Not measured |
| Git and editors | Not re-measured. The file id stays, so a watcher sees a write. A torn file is visible until restoration. | A new file id. Not re-measured against git. | Same as B | Same as B | Not a candidate |
| Recovery | Existing evidence and a separate restoration | Would reject strategy byte `1` and the same-id rule | Same | Same | Not safe to adapt while the swap succeeds |

## Architecture gate

**C. Atomic publication is not established.**

A is feasible only as the current identity-first publisher, and that publisher is not atomic. B, C, and D are not identity-preserving under the pin that stops the rename. E is not a conditional publish. No integration proposal is made for LCA-01L. The prohibition on an unsafe fallback is observed: the failed strategies are not called when the pin or the file-id check fails.

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | `apply_ntfs` and `replace_with` are unchanged. The new module is `cfg(test)`. |
| AC-02 | PASS | [LCA-ARCH-21](adr/LCA-ARCH-21.md). |
| AC-03 | PASS | The API table above. Flags and codes are the ones this run recorded. |
| AC-04 | PASS | `crates/lca-platform/src/publication_probe.rs`. |
| AC-05 | PASS | `experiment_a_target_identity`. Share-delete renames are classified as violations. |
| AC-06 | PASS | `experiment_b_concurrent_namespace`. Stress is marked `formal_proof=false`. |
| AC-07 | PASS | `experiment_c_atomic_visibility`. Mixed samples are reported as mixed. A zero mixed count is `no_mixed_sample_not_a_proof`. |
| AC-08 | PASS | `experiment_d_process_kill`. `taskkill /F` on a live child. No second write. |
| AC-09 | PARTIAL | Hard link and junction ran. File symlink returned `1314` and is skipped, not passed. |
| AC-10 | PASS | File ids are in the harness lines and in the assertions. |
| AC-11 | PASS | `0`, `5`, `32`, `33`, `87`, `1314`, `0xC0000043`, `0xC0000033`. |
| AC-12 | PASS | Windows 10.0.26200, NTFS, flags `0x3e72eff`. |
| AC-13 | PASS | Cases use temp directories and remove them. The outside hard link was an instrumented alias, observed, and removed with its temp directory. The repository tree was not the workspace. |
| AC-14 | PASS | No call from `apply_ntfs` into the probe. |
| AC-15 | PASS | `cargo test --workspace` exited 0. Publication, restoration, kill, and security tests ran. `live_ollama_smoke` is ignored and is not counted as a pass. |
| AC-16 | PASS | `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` each exited 0. |
| AC-17 | PASS | [LCA-ARCH-20](adr/LCA-ARCH-20.md). |
| AC-18 | PASS | [LCA-ARCH-21](adr/LCA-ARCH-21.md). |
| AC-19 | PASS | [LCA-ARCH-22](adr/LCA-ARCH-22.md). |
| AC-20 | PASS | Gate C above. No production integration. |

## Known limitations

- Strategy A can tear. Restoration can tear too. Neither is closed by this milestone.
- A hard link inserted after the link-count check and before `WriteFile` shares the written bytes, including outside the workspace. The post-write check can fail the call and still leave those bytes in place.
- `link_count == 1` is still not a history of names that were unlinked earlier.
- File symlink behavior was not executed (`1314`).
- `FlushFileBuffers`, `MOVEFILE_WRITE_THROUGH`, and `ReplaceFileW` flags `1` are not a power-loss proof. The parent directory was not flushed.
- The documented `ReplaceFileW` intermediate failures were not induced.
- DPAPI and the store ACL do not stop this user.
- Non-Windows verified apply stays unsupported.
