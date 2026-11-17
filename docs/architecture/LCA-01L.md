# LCA-01L: Workspace trust boundaries

Decisions: [LCA-ARCH-23](adr/LCA-ARCH-23.md), [LCA-ARCH-24](adr/LCA-ARCH-24.md), [LCA-ARCH-25](adr/LCA-ARCH-25.md).

## Decision

**B. Additional isolation is required** before a same-user process is treated as outside the threat model, and before command execution. The current tools stay in one process under this user. The new mutation mode is enforced. The publisher is the pinned in-place writer from LCA-01H. Atomic publication remains not established.

A documented boundary is not a control. The rows below say what the code does and what this run measured.

## Repository inspection

Branch `lca-development` at `d5f03831518bb6d4d3b9c07680e0f60c86194c49` before this milestone. Untracked `lca.toml`, `opencode.json`, and `lca-test/` were left untracked.

| Piece | Implemented state |
| --- | --- |
| `lca-core` | Single-turn and bounded controllers call the model runtime. They do not call `commit_prepared`. |
| `lca-tools` | Registry: `diagnostic_echo`, `list_directory`, `read_file`, `search_files`, `apply_patch`. Mutating effects are denied. `execute_validated` reads or prepares. `RejectingToolExecutor` still has no success path. |
| `lca-platform` | Windows file ids, relative opens, DPAPI, owner ACL. Other platforms return unsupported for verified apply. |
| `lca-config` | One TOML file. `require_write_approval = false` is an error. The workspace root is canonicalized. |
| `lca-cli` | Reads the confirmation line after a preview. The model string `approve` is not that line. |
| `lca-model-runtime`, `lca-ollama` | HTTP to the configured endpoint. No filesystem handles and no approval API. |
| Proposal store | States from LCA-01G through LCA-01J. Evidence is `LCA-01I-EVIDENCE-V1`, strategy byte `1`. Restoration is a second grant. |
| Publisher | `apply_ntfs` → `OpenedTarget::replace_with`. Share mode `FILE_SHARE_READ`. No `ReplaceFileW` and no rename on that path. |

Not present before this milestone, and still not a production boundary: a second process, a restricted token, an AppContainer, another Windows user, a VM, or a shell.

## Trust boundaries

| Id | From | To | Allowed flow | Authority | Validation | Audit | Residual risk |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TB-01 | Human | Controller | Configuration, confirmation line | Host user | CLI reads one line and binds it to the prepared action | Proposal audit log | The user can approve a bad patch. The user is not sandboxed. |
| TB-02 | Controller | Model | Prompt, tool catalog, prior tool results as untrusted data | Configuration budgets | Protocol selection and schema | Turn report | The prompt is not the security check. |
| TB-04 | Model | Controller | Text or tool calls | None | Registry, schema, policy, mode | Rejected calls stay errors | A well-formed dangerous patch can be prepared when the mode allows it. |
| TB-02 | Controller | Executor | Validated action | `FsLimits` from configuration | Sandbox, privacy, size limits | Tool result | Library callers that build `FsLimits` themselves are trusted code, not the model. |
| TB-03 | Executor | Workspace | Read, or an in-memory patch | Mode | Relative open, file id, link count, reparse | Publication evidence on apply | Torn writes and the hard-link window from LCA-01K. |
| TB-06 | Executor | Store | Proposal, evidence, restoration records | This user via DPAPI | Digest, file id, single-use grant | `events.log` | This user can unprotect and rewrite the files. Measured again below. |
| TB-07 | Other process | Workspace or store | Anything this user can do | This user | None at the OS boundary | Not an agent audit | TM-C. |

## Threat models

| Model | In scope | Guarantee that exists | Accepted or deferred |
| --- | --- | --- | --- |
| TM-A untrusted model | Bad calls, injection, protected paths, mode tampering | Schema rejects `mutation_mode`. Policy rejects a mutating tool. Controllers do not write. Mode comes from the file. | A human can still approve. |
| TM-B trusted tools | Concurrent edit, rename, locks | Exclusive pin: rename `32`, parent rename `5`, repeated here | Torn in-place bytes. Not atomic. |
| TM-C same-user process | Hard link, store read, evidence write, new process | Pin still denies the measured renames. Nothing else in this table stops TM-C. | Needs variant D or E before a stronger claim. Command execution stays off. |

DPAPI in this user's context is not isolation. The second process unprotects `sealed-evidence` and replaces the blob with `tampered`.

## Authority separation

Checked in code and tests:

- `apply_patch` with an extra `mutation_mode` field fails schema validation (`invalid_arguments`).
- `read_only` does not prepare. `prepare_only` prepares and `apply_granted` returns `tool_disabled` with the file unchanged.
- A stored proposal cannot be approved under `prepare_only`. The same id can be approved after the limits are `human_approved`, and that call uses the existing publisher.
- `WriteConfirmation::Absent` and a model line that is not the bound confirmation still do not write. Those tests were already in the tree.
- Controllers still do not call `commit_prepared`.

## Windows isolation

The harness is `crates/lca-platform/src/isolation_probe.rs`, `cfg(all(test, windows))`. `apply_ntfs` does not reference it. Temporary directories are removed with the test value. No account was created or modified. Production ACLs were not edited.

| Experiment | Result | Class |
| --- | --- | --- |
| IPC wrong token | `DENY auth`, process exit 2 | Rejected |
| IPC `mutate` and a 1100-byte line | `DENY mutate`, `DENY size` | Rejected |
| IPC identity | Child pid matches `CreateProcessW` | Observed |
| Worker `TerminateProcess` | Process ended | Observed |
| Controller exit | Watcher wrote `parent_exit` | Observed |
| Inherited handle | Child read `in` (`bytes=696e`) | Passed through |
| Non-inherited handle | `ReadFile` error 6 | Not inherited |
| Job assignment | `AssignProcessToJobObject` returned 0 and `echo` still worked | Not a rights boundary |
| Restricted token | Created. Privileges 5 → 1. Groups 14 → 14. | Observed |
| Impersonated read | Allowed file `0`, user-only file `5` | Split holds for that thread |
| `CreateProcessAsUserW` | API returned 0. Process exit `0xC0000022`. No child report. | User code did not run. Not a pass. |
| Low integrity impersonation | Read `0`, write `5`. Medium user then wrote. | Not a sandbox against this user |
| ACL deny write | Same-process `open_write` returned 5. Second process write was non-zero. Owner then replaced the DACL and wrote. | Owner is not isolated |
| Hard link while the pin is held | Link created. Outside name read `beta\n` after the handle write. | Attack succeeded |
| Target rename against the pin | Code 32, name unchanged | Prevented by the share mode |
| Parent rename against the pin | Code 5, directory unchanged | Prevented by the share mode |
| Evidence read and write | DPAPI plaintext matched. Overwrite succeeded. | Attack succeeded |

`0xC0000022` is `STATUS_ACCESS_DENIED`. The restricted process is not counted as a passing sandbox. Impersonation is the access result that actually ran.

## Filesystem mutation policy

Enforced, not only described:

- Missing `tools.mutation_mode` loads `read_only` even when `write_enabled` stays at its old default.
- `unrestricted` is `invalid_value` and the file is rejected.
- The CLI copies the mode onto `FsLimits`. A default agent request no longer advertises `apply_patch`.
- `human_approved` still does not write from the controller. The prepare-without-write tests set that mode explicitly and the file stays `alpha\n`.
- `apply_ntfs` is still the only publisher. The mode check returns before it when the mode is lower.

## Command execution

Not implemented. The boundary in [LCA-ARCH-25](adr/LCA-ARCH-25.md) stands: a name on an allowlist, including `cargo test`, is not a sandbox. `build.rs`, tests, macros, and dependency scripts would run as this user. That stays disabled until variant D or E is actually present.

## Architecture gate

**B.**

Variant A is sufficient only for TM-A plus the already accepted TM-B publication limits: torn in-place writes, the hard-link window, and no power-loss proof. It is not sufficient for TM-C. Variant B was measured and is the same user. Variant C's process did not start. Variant D or E would be a new milestone, with a broker, and is not claimed as a current control.

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | Inspection table above. Publisher path is still `apply_ntfs`. |
| AC-02 | PASS | [LCA-ARCH-23](adr/LCA-ARCH-23.md) and the boundary table. |
| AC-03 | PASS | TM-A, TM-B, and TM-C in that ADR. |
| AC-04 | PASS | Schema test, mode tests, controllers do not write. |
| AC-05 | PASS | Five variants in [LCA-ARCH-24](adr/LCA-ARCH-24.md). D and E were not installed. |
| AC-06 | PASS | Evaluation table in that ADR. |
| AC-07 | PASS | `isolation_probe` controller and worker processes. |
| AC-08 | PASS | Wrong token, `mutate`, oversize, pid, kill, controller exit. |
| AC-09 | PARTIAL | Token and impersonation ran. The spawned process exited `0xC0000022` before user code and is not a pass. |
| AC-10 | PASS | Temp-file DACL. Read allowed, write denied, owner could replace the DACL. |
| AC-11 | PASS | Hard link and evidence tamper succeeded. Renames were denied by the pin. |
| AC-12 | PASS | Mode is loaded and checked. See [LCA-ARCH-25](adr/LCA-ARCH-25.md). |
| AC-13 | PASS | Requirements recorded. No shell. |
| AC-14 | PASS | [LCA-ARCH-23](adr/LCA-ARCH-23.md). |
| AC-15 | PASS | [LCA-ARCH-24](adr/LCA-ARCH-24.md). |
| AC-16 | PASS | [LCA-ARCH-25](adr/LCA-ARCH-25.md). |
| AC-17 | PASS | No new publisher. Probe is `cfg(test)`. |
| AC-18 | PASS | Workspace tests, including publication, restoration, and filesystem security. See the milestone record after the run. |
| AC-19 | PASS | `fmt`, `check`, `test`, and `clippy -D warnings`. See the milestone record after the run. |
| AC-20 | PASS | Gate B above. |

`cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` each exited 0 on this tree. The Ollama smoke test in `crates/lca-ollama/tests/smoke.rs` is ignored unless `LCA_OLLAMA_SMOKE=1`. It did not run and is not a pass.

## Known limitations

- The hard-link window from LCA-01K is still open. This milestone reproduced it across a process boundary and did not close it.
- DPAPI and the owner ACL do not stop this user.
- A pipe token does not stop this user from reading a child process.
- Restricted-token process startup failed (`0xC0000022`). That is not evidence the token would confine a process that did start.
- Low integrity did not stop the medium user.
- One privilege remained after `DISABLE_MAX_PRIVILEGE` (count 5 → 1). Its name was not required for the access split.
- Power loss and atomic publication are unchanged from LCA-01K.
- Non-Windows verified apply stays unsupported.
