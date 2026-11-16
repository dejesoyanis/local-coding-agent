# LCA-01D: Secure filesystem tools

This milestone adds four workspace tools and a capability-based sandbox. The architecture decision is [LCA-ARCH-04](adr/LCA-ARCH-04.md) (option C).

Read tools run after validation. `apply_patch` prepares a diff and writes only after a confirmation line typed in the same process. There is no shell, no agent loop, and no write from `lca ask`.

The guarantees below are the ones the code and tests enforce. Check-then-open races are not described as closed.

## Module boundaries

| Crate | Responsibility |
| --- | --- |
| `lca-tools` | `WorkspaceSandbox`, path checks, `FsLimits`, the four tools, patch prepare and apply, the in-process approval ledger |
| `lca-core` | `dispatch_validated` and `commit_prepared`. Dispatch has no approval parameter |
| `lca-config` | Optional `[tools]` limits. `require_write_approval = false` is a configuration error |
| `lca-cli` | `tools list`, `tools read`, `tools search`, `tools patch prepare`. The probe registry is unchanged |

`validate_batch` still does not call a tool and does not read a project file. `ToolRegistry::diagnostic` still contains only `diagnostic_echo`. The filesystem tools are registered on `ToolRegistry::workspace`. `RejectingToolExecutor` still returns not-implemented for in-workspace reads and denies writes and commands. LCA-01A `WorkspaceScope` still accepts an absolute path that stays inside the root. The sandbox does not.

## Workspace sandbox

`WorkspaceSandbox::new` requires an existing directory and stores its canonical path. The stored root is not updated by tool arguments.

`resolve` accepts only a relative path:

- empty paths, control characters including NUL, a leading `/` or `\`, and any `:` are rejected (drive prefixes, UNC-looking forms, and alternate data streams)
- `.` is the root; `..` is rejected rather than popped
- a component that ends with a dot or space is rejected
- `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and `LPT1`–`LPT9` are rejected, including a name such as `NUL.txt`
- a component named `.git` is a protected path for every resolve
- each existing component is opened with `symlink_metadata`; a symlink or `FILE_ATTRIBUTE_REPARSE_POINT` is `reparse_denied`
- the canonical path must be the root or a child of the root, compared component-wise (`paths_equivalent` folds case on Windows)
- the parent of each component must still be the directory the walk believes it is in

A missing final component is `not_found`. A path that cannot be classified is an error, not a file.

## Windows limits that are not closed

`FILE_FLAG_OPEN_REPARSE_POINT` (`0x00200000`) is passed through `OpenOptionsExt::custom_flags` on file reads and on the exclusive create of the patch temporary file. That flag applies to the final component. The operating system can still follow a junction in an intermediate component between the `symlink_metadata` check and the later open. Directory listing uses `read_dir` after the walk, then compares directory identity. That check-then-list race is not closed. `GetFinalPathNameByHandle` is not used; this workspace forbids `unsafe`.

Rust 1.99 `MetadataExt::file_index` and `volume_serial_number` are unstable. Windows identity is therefore creation time, last write time, and length. A zero timestamp is `unverifiable_identity`. This is not an NTFS file id. Two different files can share it. Content SHA-256 is what detects a changed file. On Unix the same struct stores device and inode in those time fields.

`is_symlink` is true for name-surrogate reparse tags, which covers symlinks and mount-point junctions. The listing kind is `reparse`. The code does not split junction from symlink, because reading the reparse tag would need `unsafe`. Any reparse attribute fails closed, so a cloud placeholder can be rejected even when it points inside the workspace.

Hard links are not a separate class. A hard link inside the workspace is an ordinary file. A hard link whose other name is outside the workspace is still the same file; the sandbox does not detect that.

Long paths are left to the standard library. A failure is an I/O error.

## Tool contracts

Schemas live on `ToolRegistry::workspace`. `additionalProperties` is false. Unknown tools still fail in `validate_batch`.

| Tool | Effect | Permission | Arguments |
| --- | --- | --- | --- |
| `diagnostic_echo` | read-only | diagnostic | `message` string, unchanged from LCA-01C |
| `list_directory` | read-only | workspace read | required `path` |
| `read_file` | read-only | workspace read | required `path` |
| `search_files` | read-only | workspace read | required `query` (at most 1024 characters), optional `path` |
| `apply_patch` | approval required | workspace mutation | required `path` and `patch` (at most 20000 characters); argument object at most 64 KiB |

`authorize_proposal` still denies `ToolEffect::Mutating` first. It allows diagnostic plus read-only, workspace-read plus read-only, and workspace-mutation plus approval-required. Any other pair is `permission_not_granted`. A validated `apply_patch` is permission to prepare, not permission to write.

`execute_validated` ignores any approval text. The schema rejects an extra `approval` field before execution.

## Read tools

`list_directory` is not recursive. Names are sorted by name, then by kind. The result is then cut to `max_directory_entries`. `.` and `..` from `read_dir` are skipped. A non-UTF-8 name, or a name containing `:`, a slash, or a control character, is an error entry and is not opened. Hidden names are listed. A reparse point is reported as `reparse` and is not followed. A directory entry that cannot be classified is an error entry.

`read_file` reads one file up to `max_file_size_bytes`. A larger file is `too_large` and returns no body. NUL is a binary file even when the other bytes are UTF-8. Invalid UTF-8 is an error. Directories are `not_a_file`. When the file fits the file limit but exceeds `max_response_bytes`, the response is a UTF-8 prefix and `truncated` is true.

`search_files` is a literal `str::contains` search. It does not compile a regular expression. One hit is recorded per matching line, with a 1-based line number. Line text is capped at 512 characters. Directory names are walked in sorted order. `target`, `.git`, and `node_modules` are not descended into, compared case-insensitively. Starting the search inside one of those directories is `excluded_path`. Invalid UTF-8 and NUL files are skipped and counted. An oversized file is skipped. Hitting the match, file, or byte limit sets `truncated`. A directory with more than 100000 names stops the walk with `truncated` instead of returning an unsorted partial listing.

## Patch preparation

`apply_patch` accepts one unified diff for one existing text file.

- the diff starts with `--- ` and `+++ `; one `a/` or `b/` prefix is stripped; the two headers must name the same relative path
- `/dev/null`, a `diff --git` preamble, and a `\ No newline at end of file` marker are rejected
- context and deletion lines must match the file exactly
- the file must be entirely LF or entirely CRLF and must end with that ending; mixed endings and a missing trailing newline are `unsupported_layout`
- an empty file is treated as LF when the patch only adds lines
- added lines are stored with the file's ending; context lines are copied with that ending
- the preview envelope uses LF
- `.git` and `target` components are rejected for the write even if a future resolve change allowed them

Prepare reads the file, hashes it, applies the hunks in memory, hashes the result, and builds the diff. It does not create a temporary file and does not change the target. Tests compare the file bytes before and after prepare.

## Approval

Read tools do not ask for confirmation.

A write needs `ApprovalGrant::issue`. The function compares the typed line with `approve {action_id} {first 16 hex characters of the binding}`. Anything else, including model text that contains the word approve, is `approval_rejected`. The grant is not `Clone`. Model JSON cannot construct one, and `dispatch_validated` has no confirmation argument.

The binding is SHA-256 of a length-prefixed payload: the label `LCA-01D-APPROVAL-V1`, the action id, the workspace root string, the relative path, creation time, last write time, length, the original hash, the new hash, and the patch hash. A different patch, path, workspace, or file identity produces a different line. `apply_granted` checks the action id, the binding, the patch hash, and the workspace root again.

The ledger is a process-local `Mutex<HashSet>`. It is not written to disk. A poisoned lock is `ledger_unavailable`. The binding is inserted only after the pre-write checks and immediately before `rename`. A second use in the same process is `approval_consumed`. A new process has an empty ledger, so a crashed session does not leave a reusable approval. If `rename` fails after the insert, the target is unchanged, the temporary file is removed, and the binding is already spent. The user prepares again.

The CLI reads the line from stdin after printing the preview. `tools patch prepare --yes` is not a command. `dispatch` refuses a patch invocation so tests cannot block on stdin. `lca ask` does not parse tools and does not approve.

## Patch application

`apply_granted` re-resolves the relative path, rejects a reparse point, and compares identity and SHA-256 with the prepared values. A mismatch is `identity_changed` or `conflict`. The hunks are applied again and the bytes must equal the prepared result.

The new bytes are written to `.lca-apply-{action}-{pid}-{nanos}.tmp` in the target directory with create-new and the no-follow flag, then `sync_all`. Identity and the original hash are checked again. The binding is inserted. `std::fs::rename` replaces the target. On this toolchain that is `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING` for a same-volume replace. It is atomic as a directory entry replacement on NTFS. It is not Transactional NTFS. The directory is not fsynced. A crash during the temporary write leaves the target unchanged. A crash during the replace is the operating system's replace, not a two-phase commit.

After the rename the file is read back and hashed. `verify_failed` does not roll the target back. A second write would be a new decision, and the code does not make that decision.

Multi-file patches, file creation, deletion, and rename are out of scope and rejected as invalid patches or missing files. There is no shell.

## Configuration

`[tools]` is optional and denies unknown fields. A missing section uses the defaults below. A zero limit, a file limit above 16 MiB, a response larger than the file limit, or `require_write_approval = false` is a configuration error. `AgentConfig::require_write_approval` always returns true.

| Key | Default |
| --- | --- |
| `read_enabled` | true |
| `write_enabled` | true |
| `require_write_approval` | true, and false is rejected |
| `max_file_size_bytes` | 1048576 |
| `max_response_bytes` | 262144 |
| `max_directory_entries` | 1000 |
| `max_search_matches` | 100 |
| `max_search_files` | 1000 |
| `max_search_total_bytes` | 33554432 |

`write_enabled = false` disables preparation. It does not disable the approval requirement for a later write. The workspace root still comes from `workspace_root`, not from a tool argument.

## Errors

Filesystem failures use `FsError`. `kind()` is a stable token such as `invalid_path`, `outside_workspace`, `reparse_denied`, `not_found`, `binary_file`, `invalid_utf8`, `too_large`, `conflict`, `approval_required`, `approval_rejected`, `approval_mismatch`, `approval_consumed`, `identity_changed`, or `verify_failed`. Displayed paths are capped. A security failure is not turned into an empty success.

## Tests

Integration tests use temporary directories. They cover traversal, device names, absolute paths, limits, literal search order, excluded directories, prepare-without-mutation, grant binding, a changed file, a changed patch, CRLF preservation, an exclusive lock, junctions, and a replaced target. A property test checks that arbitrary relative strings either fail or resolve inside the root. Symlink creation is attempted; if the process lacks the privilege (`1314`) or is denied (`5`), that test records the environment limit instead of pretending a symlink was followed. Junctions do not need that privilege and are denied.

`cargo test --workspace` does not call a live model unless `LCA_OLLAMA_SMOKE=1`. The diagnostic probe tests still expect one tool and `execution: disabled`.

## Residual risk

- Intermediate reparse points can change between the component check and the open. The code fails closed when it can see the reparse point. It does not claim the race is gone.
- Windows identity is timestamps plus length, not a file id.
- A successful rename that then fails verification leaves the new bytes in place.
- A grant inserted before a failed rename cannot be reused. That is fail-closed for the write, and it forces a new prepare.
- Search and listing can observe a directory that changes while they walk it.
- Hard links and reparse points that Windows does not mark on `symlink_metadata` are outside what this code can see.

## Next step

LCA-01E can attach the workspace registry to a non-streaming model turn, still one validated batch, still with prepare separated from apply. It should not start a loop, should not execute `lca ask` tools, and should not persist an approval that outlives the process unless the binding is checked again against the file bytes.
