# LCA-01M: Windows principal isolation and capability broker

Decisions: [LCA-ARCH-26](adr/LCA-ARCH-26.md), [LCA-ARCH-27](adr/LCA-ARCH-27.md), [LCA-ARCH-28](adr/LCA-ARCH-28.md).

## Decision

**B. Isolation partially validated.**

A restricted-token worker process reached its test code. Windows denied that process the user-only fixtures, including a test proposal store, a test evidence file, and a hard link onto the protected file. The broker accepted only the process it had started. The job ended the worker and blocked `cmd.exe`.

The worker is still the interactive user. That user opened the same denied file. DPAPI decrypted a ciphertext the harness had placed in the environment. Objects granted to Everyone or Users stay readable, which is also why the process can start. A separate local user, an AppContainer process, and a VM were not run. Command execution stays disabled. The production apply path is still `apply_ntfs`.

`implemented` means the harness contains it. `tested` means this run measured it. `documented` means this record states the limit. `unproven` means that configuration was not executed.

## Repository inspection

Branch `lca-development` at `793511a77689bfdb7de84b97b3092193f3e5bf6f` before this milestone. Untracked `lca.toml`, `opencode.json`, and `lca-test/` stay untracked.

| Piece | State |
| --- | --- |
| `lca-core` | Controllers still do not call `commit_prepared`. |
| `lca-tools` | Registry unchanged: `diagnostic_echo`, `list_directory`, `read_file`, `search_files`, `apply_patch`. No shell tool. |
| `lca-platform` | Publisher in `windows.rs` unchanged. New code is `principal_probe`, `cfg(all(test, windows))` only. |
| `lca-config`, `lca-cli` | Unchanged. Mutation modes from [LCA-ARCH-25](adr/LCA-ARCH-25.md) stay in force. |
| Proposal store and evidence | Production layout unchanged. The harness builds its own temporary files. |
| `isolation_probe.rs` | LCA-01L harness left in place. This milestone does not rewrite it. |

The model cannot call the harness. It is not in the tool registry.

## Threat model

TM-A and TM-B are unchanged from [LCA-ARCH-23](adr/LCA-ARCH-23.md). TM-C is the subject of this milestone: a process that already has this user's logon.

The restricted worker is a narrower token inside that logon. It is inside TM-C for anything the DACL grants to Everyone, Users, or the logon SID, and for DPAPI of this user. It is outside the worker's reach only where the DACL grants none of the restricting SIDs. The interactive user remains inside TM-C with the full token.

## Token and launch

Details and the measurement table are in [LCA-ARCH-26](adr/LCA-ARCH-26.md).

Restricting SIDs: Users, Everyone, logon SID. Flags: `DISABLE_MAX_PRIVILEGE | SANDBOX_INERT`. Primary token. Medium integrity. Privileges `5 → 1`. The executable was staged where Users can read and execute it. `CreateProcessAsUserW` on the `detached` attempt reached `reached=1` and exited `0`. Without Everyone in the restricting list, the same launch exited `0xC0000022` before user code. That earlier exit is not a pass.

No privilege was added to the parent. `SeAssignPrimaryTokenPrivilege` was not used.

## Broker, IPC, and handles

Details are in [LCA-ARCH-27](adr/LCA-ARCH-27.md).

Capabilities are `ping`, `worker_info`, and `read_fixture`. `fixture-001` is a map key. The scripted worker run matched the expected allow and deny labels, and the parent pid was `deny:identity` even with the real worker id. The inherited file handle was read-only. The store handle was not inherited (`ReadFile` returned `6`).

## Lifecycle and job

Details are in [LCA-ARCH-28](adr/LCA-ARCH-28.md).

The state machine rejects a restart from `Failed`. The job report was `limits=0 memory=1 time=1 cpu=0`. Closing the job left exit `0x0` and no `wait_returned=1`. `CreateProcessW` of `cmd.exe` returned `1816`.

## Security boundary tests

| Test | Result | Class |
| --- | --- | --- |
| Allowed fixture | open `0` | tested |
| Denied file read and write | `5` and `5` | tested |
| Test proposal store | `5` | tested |
| Test evidence file | `5` | tested |
| Path outside the stage | read `5`, write `5` | tested |
| Hard link onto the denied file | `5`, path absent | tested |
| IPC spoof, replay, capability, foreign id, lifetime, rate, size | denied as scripted | tested |
| Foreign handle | `6` | tested |
| Granted handle write | `5` | tested |
| Second process under the job | `1816` | tested |
| Worker still running after job close | exit not `259` | tested |
| DPAPI of an in-environment blob | `ok` | tested, not a boundary |
| Parent open of the denied file | `0` | tested, same user is not confined |
| Separate user | not provisioned | unproven |
| AppContainer process | not started | unproven |
| VM | binaries absent, not started | unproven |

## Evaluation

| Property | Same user | Restricted token | Separate user | VM |
| --- | --- | --- | --- | --- |
| Worker isolation | documented | tested, same logon | unproven | unproven |
| Proposal store | documented | tested on the fixture | unproven | unproven |
| Evidence | documented | file tested; DPAPI does not hold | unproven | unproven |
| Workspace | in-process only | fixtures tested | unproven | unproven |
| Hard link | documented | tested | unproven | unproven |
| IPC authentication | documented | tested, same user | unproven | unproven |
| Process containment | documented | tested | unproven | unproven |
| Operational complexity | product | harness only | account required | feature absent |

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | Inspection table. `apply_ntfs` unchanged. |
| AC-02 | PASS | `detached` reached `reached=1`, exit `0`. |
| AC-03 | PASS | Worker-reported token line in [LCA-ARCH-26](adr/LCA-ARCH-26.md). |
| AC-04 | INCONCLUSIVE | No account. Contract rejects a same SID. |
| AC-05 | PASS | Profile create `0`, delete `0x0`, `appcontainer_launched=0`. Not a process sandbox. |
| AC-06 | PASS | `vmcompute=0 sandbox=0 vmwp=0 vm_started=0`. Not a VM sandbox. |
| AC-07 | PASS | Broker capabilities and audit in [LCA-ARCH-27](adr/LCA-ARCH-27.md). |
| AC-08 | PASS | Protocol version 1. `resource_id` is not a path. |
| AC-09 | PASS | Parent pid denied. Same-user limit is documented. |
| AC-10 | PASS | Granted read `0`, write `5`, foreign `6`. |
| AC-11 | PASS | Lifecycle unit test and the successful trace. |
| AC-12 | PASS | `in_job=1`, job close, `spawn=1816`. |
| AC-13 | PASS | Allowed fixture open `0` and hex payload. |
| AC-14 | PASS | Denied read and write `5`. |
| AC-15 | PASS | Store open `5` on the temporary file. |
| AC-16 | PARTIAL | Evidence file `5`. DPAPI of the supplied blob returned `ok`. |
| AC-17 | PASS | Hard link `5`, path absent. |
| AC-18 | PASS | Scripted IPC labels, including the parent identity deny. |
| AC-19 | PASS | Workspace tests include the existing filesystem and restoration tests. Recorded after the quality run. |
| AC-20 | PASS | `fmt`, `check`, `test`, and `clippy -D warnings`. Recorded after the quality run. |
| AC-21 | PASS | [LCA-ARCH-26](adr/LCA-ARCH-26.md). |
| AC-22 | PASS | [LCA-ARCH-27](adr/LCA-ARCH-27.md). |
| AC-23 | PASS | [LCA-ARCH-28](adr/LCA-ARCH-28.md). |
| AC-24 | PASS | Gate B above. |

AC-05 and AC-06 pass as research. They are not a pass for process isolation. AC-04 stays inconclusive because the separate principal was not created. AC-16 is partial because the file ACL held and DPAPI did not.

`cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` each exited 0. The Ollama smoke test in `crates/lca-ollama/tests/smoke.rs` is ignored unless `LCA_OLLAMA_SMOKE=1`. It did not run and is not a pass. Filesystem security, publication, and restoration tests ran with the workspace suite and passed.

## Remaining risks

- The interactive user can open, relabel, or delete the objects the worker cannot open.
- Everyone and Users remain usable restricting SIDs, so anything granted to them is available to the worker, including enough of the system to map the image.
- DPAPI for this user still unprotects. File ACL is what stopped the evidence file.
- The worker can create its own named pipe (`own_pipe=0`).
- Medium integrity was not lowered. Low integrity was already shown, in LCA-01L, not to confine this user.
- One privilege remains after `DISABLE_MAX_PRIVILEGE`.
- No private desktop was required for the passing run. `WinSta0` was left alone.
- AppContainer and VM behavior are unproven here.
- The hard-link window against this user's own token, from LCA-01K, is unchanged for the production publisher.
- The harness is not a production sandbox and is not called by the model.

## Recommendation for LCA-01N

Keep command execution off. A later milestone that wants a boundary against TM-C has to run a worker that is not this logon: a separate local principal, or a VM, with the broker on the far side of that boundary. The restricted token can stay as a tested ACL experiment. It should not be described as the production sandbox, and the agent should not move onto it until that stronger principal exists.
