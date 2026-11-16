# LCA-01H: Filesystem security and verified apply hardening

LCA-01H closes the Windows read and apply gaps that LCA-01G recorded, and it stops claiming a rename that the platform cannot perform safely.

Decisions: [LCA-ARCH-11](adr/LCA-ARCH-11.md), [LCA-ARCH-12](adr/LCA-ARCH-12.md), [LCA-ARCH-13](adr/LCA-ARCH-13.md).

## Pre-change analysis

This is the inspection of `34cef062` before the code in this milestone changed. "Proven" means a test on this tree demonstrated the behavior. "Race" means a window that follows from the API sequence and was not separately won by an exploit harness.

| Gap | Functions | Flow | Boundary | Attacker | Impact | Defense chosen | Residual |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Check-then-open reads. Proven by the LCA-01G design: the walk checked a path, then a later open used the string. | `read_file`, `search_files`, `list_directory` | Resolve, classify, open by path | Workspace root versus the object a second open returns | A writer who can replace a component between the check and the open | Read or list follows a junction or symlink | One relative open, then use that handle | A same-user writer who wins the race before the open still hits the policy on the opened object |
| Hardlink read of a protected name. Proven: the old filesystem test expected the alias content and observed `HardlinkDenied` only after this milestone's read path. Before the change, the alias was returned. | `read_file`, `search_files` | Privacy matches the requested name, then the open returns the shared bytes | Name policy versus object identity | A second hardlink name that is not itself protected | Protected bytes are disclosed | Refuse `link_count != 1` before copying bytes | `link_count == 1` after the protected name was unlinked |
| Close-then-rename. Race, measured: rename over a `FILE_SHARE_READ` handle is denied (`0xC0000022`, `0xC0000043`, Win32 32). The window exists only because LCA-01G closed the handle first. | `OpenedTarget::replace_with` | Check file id, close, `FileRenameInformation` | Directory entry versus the closed handle | A writer who replaces the entry in that window | The rename replaces a different object than the one whose id was checked | Delete that path. Write the open handle. | Torn in-place write; no atomic directory swap |
| `verify_failed` does not restore. Proven by inspection of the LCA-01G state table: the new bytes stayed, and the state became `Conflict`. | proposal apply | Rename, then hash the read-back | "verification failed" versus "bytes restored" | None required; a crash or a short write is enough | The caller can believe the old bytes are back | `Unclear` until the bytes and the file id match one evidence rule. No rewrite. | The file can stay torn until a person looks |
| Parent replacement. Race. | directory walk | Parent handles shared delete | Parent directory object versus the child handle | A writer who renames a parent directory | A path-based reopen would see the new parent | Final path of the still-open file must match the root final path plus the components, and it is checked before the write | A parent move that is undone before the check still names the same handle. The write is not retargeted. |
| Non-Windows verified apply | `ProposalStore::save` | `verified_apply_supported` is false | Platform | Any caller | A string rename would be a weaker apply | Stay `Unsupported` | Not executed on Linux or macOS |
| Same-user DPAPI | proposal store | `CryptProtectData` for the current user | Other users versus this user | Code running as this user | Forged or decrypted proposals | Unchanged. Not claimed as a process boundary. | The same user |

## Handle-bound access

Windows bytes come from `lca_platform::read_tree`. Listings come from `lca_platform::list_tree`. There is no path-open fallback. The privacy policy still runs on the requested name, case-insensitively, before the open. Junctions, symlinks, and other reparse points fail that open. Alternate data streams, `..`, absolute paths, UNC paths, device paths, and reserved names are rejected as path components.

`read_file` and `search_files` both refuse a file whose opened handle has `link_count != 1`. Search increments its skip count and does not return the contents. The existing size, match, file, and byte budgets are the same values the tools already enforced. The handle read checks the file size against the read cap before `ReadFile` copies more than that cap.

## Verified apply

The checks before the target bytes change are the proposal digest, the workspace volume and file id, the relative path, the target file id, the original SHA-256 read from the handle, the proposed SHA-256, the approval line, the state, the TTL, the privacy policy, the reparse tag, and `link_count == 1`. A different file id is not accepted.

The temporary file is a staged image. The published bytes are the write to the verified handle, followed by `SetEndOfFile` and `FlushFileBuffers`. The file id does not change. Atomic visibility, crash durability, and rollback are specified separately in [LCA-ARCH-12](adr/LCA-ARCH-12.md). This milestone provides the first as "not atomic", the second as a handle flush, and the third as "not done".

## Recovery and audit

`Unclear` means the target may already contain a mutation and the process will not guess by writing. Reconciliation can later record `Applied` when the proposed hash and the same file id are both present, or `Failed` when the original hash and the same file id are both present. A matching hash on a different file id stays `Unclear`. The audit event for that reconstruction is `recovered`, not `apply_succeeded`.

`ApplyFault` is reachable only from `approve_with`. Production `approve` passes `None`.

## Tests

Automated on this Windows machine:

- `read_tree_refuses_a_hardlink_without_returning_bytes`
- `list_tree_reports_a_junction_and_does_not_open_it`
- `reserved_names_and_streams_are_rejected`
- `a_moved_parent_is_not_treated_as_the_checked_target`
- `an_open_target_cannot_be_renamed_away`
- `replace_with_keeps_the_file_id_and_reads_back`
- `every_fault_point_records_the_bytes_that_are_actually_present` (all ten points; `DuringReadback` leaves `beta`, audits `verification_failed` and `unclear`, then `status` recovers to `applied` without a second write)
- Filesystem: traversal, UNC, device, ADS, reserved names, junctions, symlinks, protected-name case, hardlink prepare, hardlink read, hardlink search
- Offline agent eval: `hardlink_alias` is `hardlink_denied`, `reparse_denied` is `reparse_denied`, `prepared_patch` does not apply, a tampered proposal is rejected, a changed target conflicts and keeps the edited bytes, and a `DuringReadback` fault recovers without a second write. `patches_applied` stays 0. The scripted runtime does not call `approve`.

Live, on an isolated temporary workspace, model `lca-30b-agent`, local Ollama, not the project tree:

1. `notes.txt` was `alpha` plus CR LF (`61 6C 70 68 61 0D 0A`).
2. `lca agent execute` read the file and prepared proposal `8b0ba868-d615-42bf-b2ab-802f698fef25`. Stop reason `prepared_patch`. Two model turns. No apply.
3. The workspace file was still `61 6C 70 68 61 0D 0A`.
4. `lca patch show` printed the diff `-alpha` / `+beta`, `target_status: matches_original`, and a confirmation line.
5. `lca patch approve` was not run. A pipe, a pseudoconsole, and a second apply were not used. Those steps are not live-tested.

Not demonstrated:

- Linux and macOS execution. Those builds fail closed by construction.
- A same-user debugger, or a hardlink that is created and removed before the open.
- Crash durability across a killed process. The fault points stop the process in-process; they do not kill it between `WriteFile` and `FlushFileBuffers`.

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | `read_tree` returns bytes from the opened handle. No Windows path reopen. |
| AC-02 | PASS | Relative `NtCreateFile` per component. `reserved_names_and_streams_are_rejected`. Sandbox traversal tests. |
| AC-03 | PASS | Junction, symlink, and reparse tests refuse the open. `list_tree` reports a junction and does not open it. |
| AC-04 | PASS | Hardlink reads, search, prepare, and apply refuse `link_count != 1`. The unlink residual is a known limit, not a bypass of this check. |
| AC-05 | PASS | Tool limit fields and the read-cap check are unchanged. Existing limit tests still apply. |
| AC-06 | PASS | `require_same_file` on the handle that is written. `replace_with_keeps_the_file_id_and_reads_back`. |
| AC-07 | PASS | The close-then-rename path is gone. The held handle cannot be renamed away. This is not a claim of atomic replace. |
| AC-08 | PASS | Windows read and apply have no string fallback. Non-Windows save and apply stay unsupported. |
| AC-09 | PASS | `approve` takes the same line, digest, and single-use ledger. The CLI still requires a terminal and constructs `ApplyFault::None`. |
| AC-10 | PASS | [LCA-ARCH-12](adr/LCA-ARCH-12.md) separates visibility, durability, and rollback. |
| AC-11 | PASS | `ApplyFault` has the ten points. No environment variable arms them. |
| AC-12 | PASS | `DuringReadback` asserts the on-disk bytes are the proposed bytes and the pre-status audit says `unclear`. |
| AC-13 | PASS | Recovery does not write. A second approve fails. Original bytes become `Failed`, not a reused grant. |
| AC-14 | PASS | `mutation_started`, `mutation_published`, `verified`, `verification_failed`, `state_unclear`, and `recovered` are distinct. `BeforeAudit` has no `apply_succeeded`. |
| AC-15 | PASS | The Windows tests named above. Skipped non-Windows tests are not counted. |
| AC-16 | PASS | The agent loop still prepares and does not approve. Eval records `patches_applied: 0`. |
| AC-17 | PASS | `offline_runs_cover_the_scenarios_and_apply_nothing`. |
| AC-18 | PARTIAL | Live prepare and show with `lca-30b-agent` on an isolated workspace. The file stayed `alpha`. Approve was not run. |
| AC-19 | PASS | `cargo fmt`, `cargo check`, `cargo test`, and `cargo clippy -D warnings` for the workspace. |
| AC-20 | PASS | This document, the three ADRs, and the cursor prompt. |

AC-19 is PASS only for the commit that contains a green run of those four commands.

## Known limits

- In-place publication can tear if the process dies during `WriteFile`. There is no rollback.
- `link_count == 1` is not evidence that a file was never protected under another name.
- A same-user process can unprotect a proposal. DPAPI is not a boundary against that user.
- Directory handles still share delete. The file handle is the binding.
- Non-Windows verified apply is fail-closed and was not run.
- Apply fails closed when another writer already has the file open. There is no share-delete retry.
