# LCA-01I: Crash-safe patch publication and recovery

Decisions: [LCA-ARCH-14](adr/LCA-ARCH-14.md), [LCA-ARCH-15](adr/LCA-ARCH-15.md), [LCA-ARCH-16](adr/LCA-ARCH-16.md).

## Threat model

The writer we defend against can create, rename, and replace files in the workspace between two of our calls. The same user can decrypt DPAPI. That user is not a boundary. We do not claim a defense against a debugger attached to this process.

The failure we add is a hard process kill during publication. Power loss is a larger failure and was not produced.

## What LCA-01H already guaranteed

Implemented and covered by the existing Windows tests: relative `NtCreateFile`, reparse refusal, `link_count != 1` refusal, exclusive apply handle, file id preserved by the in-place write, no close-then-rename, `Unclear` without a second write, ten in-process fault points, no model retry, no shell, no auto-approve.

Not provided, and said so in LCA-ARCH-12: atomic visibility, rollback, and crash durability across a killed process. The in-process faults return an error. They do not stop the process between `WriteFile` and `SetEndOfFile`.

## Strategy comparison

| Strategy | Identity | Visibility | Crash | Why it lost or won |
| --- | --- | --- | --- | --- |
| A. In-place write on the exclusive handle | The same file object. File id does not change. Measured. | Not atomic. A kill before `SetEndOfFile` left a mixed file. | `FlushFileBuffers` after the write. Not a power-loss transaction. | Chosen. It is the only option that keeps the checked object. |
| B. Staged file plus rename | The rename hits the current directory entry, not the held object. | Later opens see the staged file or the old file. | The staged flush is durable for that file's bytes only if the flush completes. The name swap was not power-loss tested. | Rejected. Share-delete, which the rename needs, lets another rename move the name first. |
| C. `ReplaceFileW` | Documented and measured: the result has the replacement's file id. | Microsoft recommends it for document-like files. The error codes also describe intermediate names. | `REPLACEFILE_WRITE_THROUGH` is not supported. | Rejected. It fails while the exclusive handle is held, and its failure states can drop the original name. |
| D. `FileRenameInformationEx` POSIX replace | Measured: old handle keeps the old id and bytes; the name's id becomes the staged id. | Documented: later opens see the renamed file. | One system call for the name. Not a power-loss proof. | Rejected for the same share-delete hole. An exclusive byte lock did not close it. |
| E. Journal plus the in-place write | Same as A. | The journal does not make `WriteFile` atomic. | The preimage is sealed before the write, so a torn file is recognizable. | Used as recovery evidence, not as a publication mechanism. |
| F. Versioned container | Would stop being the file `rustc` and git read. | Depends on an extra publish step. | Not a normal workspace file. | Rejected. |

## Publication

`replace_with` still refuses to rename. The new phases are `AfterStageFlush`, after the temporary file is flushed and read back, and `DuringPublish`, after the first successful `WriteFile` to the target and before `SetEndOfFile`. For `alpha\n` replaced by `beta\n`, that point leaves `beta\n\n`: the new bytes were written and the old length was not truncated. The state becomes `Unclear`. `status`, `inspect`, and `recover` leave those bytes in place.

A same-length file can be fully replaced by one `WriteFile` before `DuringPublish` runs. The tests use a shorter replacement so the torn tail is reproducible. A file larger than the 64 KiB chunk can also tear between chunks. That larger shape was not required once the shorter shape already produced a mixed file.

## Evidence and commands

`{id}.lcae` is the sealed preimage and phase record from [LCA-ARCH-16](adr/LCA-ARCH-16.md). `lca patch inspect` reads it and the target. `lca patch recover` reconciles state only. Restoring a torn file is a new proposal and a new confirmation line. This milestone does not ship a restore command, because that command would be a second write.

## Kill tests

`killed_child_is_recovered_without_a_rewrite` starts `publication_kill.exe` with `LCA_KILL_SPEC` set, waits until the child creates the ready file, checks the child is still running, and runs `taskkill /F /PID`. The library does not read that variable. The `lca` binary does not construct `KillHold`.

| Hold point | Bytes after the kill | State after `recover` |
| --- | --- | --- |
| `after_intent`, `after_temp_create`, `after_write`, `after_stage_flush`, `before_rename` | `alpha\n` | `failed` |
| `during_publish` | neither `alpha\n` nor `beta\n` | `unclear` |
| `after_rename`, `before_readback`, `after_verification`, `before_audit` | `beta\n` | `applied` |

Every row kept the file id, kept a single `apply_started`, and rejected a second approve. The bytes were identical before and after `recover`.

These rows are process-kill evidence. They do not show what a disk cache would contain after power loss.

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | `measured_windows_publication_options` plus the API notes in LCA-ARCH-14. |
| AC-02 | PASS | LCA-ARCH-14 chooses the exclusive handle because the alternatives failed the identity measurement. |
| AC-03 | PASS | Successful publish keeps the file id. The kill recovery asserts `current_file_id == recorded_file_id`. POSIX replace and `ReplaceFileW` changed the id and are not called. |
| AC-04 | PARTIAL | Atomic visibility was not achieved. The rename and `ReplaceFileW` paths are not implemented. The in-place write remains and can tear. That is the documented trade-off, not a disabled publisher. |
| AC-05 | PASS | Evidence is synced before the target write. `after_intent` dies after that seal and the file is still `alpha\n`. |
| AC-06 | PASS | Proposal and evidence writes use `sync_all` and rename. Audit `sync_all` includes the sequence file. Directory fsync is not claimed. |
| AC-07 | PASS | LCA-ARCH-16 and `ProposalInspection`. |
| AC-08 | PASS | `recover` and the kill test leave the bytes unchanged and do not call `approve` again. |
| AC-09 | PASS | `taskkill /F` on a child that was still running. |
| AC-10 | PASS | The ten hold points above. |
| AC-11 | PASS for recognition, not for restoration | `DuringPublish` leaves a mixed file, `observed` is `matches_neither`, and the file is not repaired. |
| AC-12 | PASS | `lca patch inspect` and `lca patch recover`. |
| AC-13 | PASS | Second approve fails in the fault test and in the kill test. |
| AC-14 | PASS | Privacy, hardlink, and reparse checks are unchanged. The workspace suite still runs them. |
| AC-15 | PASS | The Windows platform tests, including the new measurement, and the filesystem security tests. |
| AC-16 | PARTIAL | Live `lca agent execute` with `lca-30b-agent` on an isolated temp workspace. The file stayed `61 6C 70 68 61 0A`. Proposal `a22149b6-07ff-43f9-861e-8ba8963168ce` was prepared and shown with `target_status: matches_original`. Approve was not run. |
| AC-17 | PASS | The four cargo gates in the commit that contains their green run. |
| AC-18 | PASS | This file, the three ADRs, and the cursor prompt. |
| AC-19 | PASS | No rename fallback. A failed exclusive open stops the apply. |
| AC-20 | PASS | The limits below. |

## Live agent

Isolated workspace `lca-01i-live-40a4f3c916604ae8b3af9c109494c62b` under the temp directory. Model `lca-30b-agent` at `127.0.0.1:11434`. `LCA_STATE_DIR` pointed at a directory inside that workspace.

1. `notes.txt` was `61 6C 70 68 61 0A`.
2. The first execute read the file and then stopped with `tool_error` / `context mismatch around line 1`. The file was still `61 6C 70 68 61 0A`.
3. A second execute read the file and prepared proposal `a22149b6-07ff-43f9-861e-8ba8963168ce`. Stop reason `prepared_patch`. `applied: false`. Two model turns.
4. `lca patch show` printed `-alpha` / `+beta`, `target_status: matches_original`, and the confirmation line.
5. `lca patch approve` was not run. There was no interactive confirmation.

## Remaining risks

- In-place publication can tear. Detection is not a restore.
- `FlushFileBuffers` and `sync_all` are not a power-loss proof, and the parent directory is not flushed by a documented non-admin call.
- `FILE_SHARE_DELETE` is still not used, so a concurrent publisher that already has the file open makes apply fail closed.
- `link_count == 1` can be true after a protected name was unlinked.
- DPAPI does not protect the proposal from this user.
- Non-Windows verified apply stays unsupported and was not executed.
- A same-length `WriteFile` that finishes in one call is not split by `DuringPublish`. The torn case we executed is the window before `SetEndOfFile`.
