# LCA-01N: Cross-identity worker isolation

Decisions: [LCA-ARCH-29](adr/LCA-ARCH-29.md), [LCA-ARCH-30](adr/LCA-ARCH-30.md), [LCA-ARCH-31](adr/LCA-ARCH-31.md).

## Decision

**C. Cross-identity boundary not established.**

`LCA_01N_ACCOUNT` was unset. `LogonUserW` and `CreateProcessWithLogonW` were not called. No account was created. The report was `gate=C worker_started=0 account_created=0 logon_attempted=0`.

Mode A ran: the principal contract, the protocol-2 broker, replay, capability denial, the launch contract, `AccessCheck`, a same-user pipe denial, and a same-user hard link. Those results do not establish a second principal. Command execution stays disabled. The production publisher stays `apply_ntfs`.

`implemented` means the harness contains it. `tested` means this run measured it. `documented` means this record states the limit. `unproven` means that configuration was not executed.

## Repository inspection

Branch `lca-development` at `b0a7cf419b18da38ab5178ad937f61b1ab9f8471` before this milestone. Untracked `lca.toml`, `opencode.json`, and `lca-test/` stay untracked.

| Piece | State before this milestone | After |
| --- | --- | --- |
| `lca-core` | Controllers do not call `commit_prepared`. | Unchanged. |
| `lca-tools` | Registry: `diagnostic_echo`, `list_directory`, `read_file`, `search_files`, `apply_patch`. No shell. | Unchanged. |
| `lca-platform` | Publisher in `windows.rs`. `principal_probe` is the LCA-01M restricted-token harness, test-only. | `windows.rs` unchanged. New code is `principal_probe::cross`, still `cfg(all(test, windows))`. |
| `lca-config`, `lca-cli` | Mutation modes from [LCA-ARCH-25](adr/LCA-ARCH-25.md). | Unchanged. |
| Proposal store and evidence | Production layout. | Unchanged. The harness would build temporary files only if Mode B ran. |
| `isolation_probe.rs` | LCA-01L harness. | Not rewritten. |

The model cannot call the harness. It is not in the tool registry.

## Gap this milestone started from

[LCA-ARCH-26](adr/LCA-ARCH-26.md) measured a restricted token of this user. Windows denied that token the user-only fixtures. The interactive user still opened them. DPAPI of this user decrypted a blob the harness had supplied. `LogonUserW` had not been called. That is an ACL split inside one logon, not a second principal. TM-C is still inside that logon.

## Mode A and Mode B

Mode A does not need a second account. It ran.

Mode B runs only when `LCA_01N_ACCOUNT` names an existing local account and Credential Manager already holds a generic secret at `LCA-01N-Worker` for that account. The harness does not create the account, does not write the secret, and does not put the secret on a command line or in an environment block. This run took the missing-account branch.

## Principal

Details are in [LCA-ARCH-29](adr/LCA-ARCH-29.md).

The current process token is primary, medium integrity, with a logon SID, a non-zero authentication id, 11 enabled groups, no restricted groups, and 5 privileges, none of them on the dangerous list. `CheckTokenMembership` for Administrators was `0`. `AccessCheck` denied an unrelated SID and allowed this user. A same-user hard link returned `0`.

## Broker

Details are in [LCA-ARCH-30](adr/LCA-ARCH-30.md).

Protocol version is 2. Identity is not read from JSON. The live pipe matched the client process SID to this user and then denied the session. Impersonation comparison was `impersonation=0`. A smuggled `user_sid` was `deny:schema`.

## Resources

Details are in [LCA-ARCH-31](adr/LCA-ARCH-31.md).

Store, evidence, restoration, workspace, and host opens from another principal were not run. The same user can still hard-link a file it owns.

## Threat model

TM-A and TM-B are unchanged from [LCA-ARCH-23](adr/LCA-ARCH-23.md). The model has no new tool.

TM-C is not reduced. A different SID was not started, so nothing here stops a process that already has this user's token. The broker does refuse to treat that token as a worker session. Those are different statements.

| Goal | Result |
| --- | --- |
| Host protected from the worker | Unproven. |
| Worker protected from the host | Not claimed. The host hard link succeeded. |
| Broker protected from the worker | Contract tested. Live cross-identity session not run. |
| Broker protected from other host processes | Same-user pipe was `deny:session`. Not a hostile-process trial. |

## Evaluation

| Property | Restricted token | Separate principal | VM |
| --- | --- | --- | --- |
| Different user SID | tested, same user | unproven | unproven |
| Store isolation | tested on a fixture in LCA-01M | inconclusive | unproven |
| Evidence isolation | file tested in LCA-01M; DPAPI is not a boundary | inconclusive | unproven |
| Workspace isolation | fixtures tested in LCA-01M | inconclusive | unproven |
| IPC authentication | tested for that restricted process | same-user pipe denied; other user not run | unproven |
| Hard link protection | tested for the restricted token | same user still creates a link | unproven |
| Handle isolation | explicit list tested in LCA-01M | contract only | unproven |
| Process containment | job tested in LCA-01M | contract only | unproven |
| Host compromise resistance | not a boundary | not established | unproven |
| Operational complexity | harness only | account and Credential Manager, not supplied | not started |

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | Inspection table. `apply_ntfs` unchanged. |
| AC-02 | PASS | `PrincipalSnapshot` and the current-token line in [LCA-ARCH-29](adr/LCA-ARCH-29.md). |
| AC-03 | INCONCLUSIVE | `worker_started=0`. No second SID. |
| AC-04 | PARTIAL | Launch contract rejects `cmd.exe` and implicit handles. No process was created. |
| AC-05 | PARTIAL | Broker token was read from Windows. The other principal's token was not. |
| AC-06 | PASS | No password in the repo, command line, environment builder, or report. Account was not created. |
| AC-07 | PARTIAL | Protocol 2 broker is unit-tested. It did not serve another user. |
| AC-08 | PARTIAL | Live pipe: `observed_sid_match=1`, `decision=deny:session`, `impersonation=0`. |
| AC-09 | PASS | Replay, expired request, closed session, and foreign session were denied in memory. The set is not persisted. |
| AC-10 | PASS | The eight forbidden capability names were denied. `fixture-001` is hex. A path id was denied. |
| AC-11 | INCONCLUSIVE | Store open from another principal was not run. |
| AC-12 | INCONCLUSIVE | Recovery evidence open was not run. |
| AC-13 | INCONCLUSIVE | Restoration evidence open was not run. |
| AC-14 | INCONCLUSIVE | Workspace open from another principal was not run. |
| AC-15 | INCONCLUSIVE | Host-file open from another principal was not run. |
| AC-16 | INCONCLUSIVE | Worker hard link was not run. This user created one (`same_user_hardlink=0`). |
| AC-17 | PARTIAL | Handle contract tested. No handle was passed to another user. |
| AC-18 | PARTIAL | Restart and abort predicates tested. No cross-identity process. |
| AC-19 | PARTIAL | Spoofed SID, logon id, pid, pipe, replay, and capability were denied in process. TM-C was not rerun as another user. |
| AC-20 | PASS | `Debug` of the password buffer is `redacted`. Reports have no password field. |
| AC-21 | PASS | Filesystem, publication, and restoration tests ran with the workspace suite. |
| AC-22 | PASS | `fmt`, `check`, `test`, and `clippy -D warnings` each exited 0. |
| AC-23 | PASS | [LCA-ARCH-29](adr/LCA-ARCH-29.md). |
| AC-24 | PASS | [LCA-ARCH-30](adr/LCA-ARCH-30.md). |
| AC-25 | PASS | [LCA-ARCH-31](adr/LCA-ARCH-31.md). |
| AC-26 | PASS | Gate C above. That is not a pass for the boundary. |

AC-11 through AC-16 are inconclusive because the integration did not run. A contract test is not recorded as a pass for those rows. AC-21 and AC-22 are recorded from the quality run.

The Ollama smoke test in `crates/lca-ollama/tests/smoke.rs` is ignored unless `LCA_OLLAMA_SMOKE=1`. It is not a pass when it does not run.

## Remaining risks

- TM-C still includes every process of this user. The same-user hard link is the control.
- No separate SID was started, so store, evidence, and workspace denial by Windows for that SID are unproven.
- `impersonation=0` on the same-user pipe. A live allow also requires the impersonation token, which this run did not match.
- `CreateProcessWithLogonW` cannot pass an explicit handle list. The unimplemented part of a future launch is inheritance of nothing, with bytes only from the broker.
- Executable ACL, DLL load, profile, and window station for another user were not exercised. The harness does not grant Everyone full control to find out.
- In-memory replay dies with the broker. Sessions are not saved.
- DPAPI of this user is still not a boundary. That was measured in LCA-01M and was not repeated as a success.
- The restricted token remains a same-user ACL experiment. It is not this milestone's sandbox.
- The harness is not called by the model.

## Recommendation for LCA-01O

Keep command execution off. Do not move the agent onto this harness.

A later run can set `LCA_01N_ACCOUNT` to an existing local account and store the secret in Credential Manager under `LCA-01N-Worker` through the Windows UI. The harness will then attempt `LogonUserW` and `CreateProcessWithLogonW`. If that process does not start, the result stays inconclusive. If it starts and can open a protected test file, that is a failure of the boundary. Contract tests alone do not change gate C.
