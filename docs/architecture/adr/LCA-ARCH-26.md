# LCA-ARCH-26: Windows security principal isolation

- Status: Accepted
- Decision: **B. Isolation partially validated.** A restricted-token worker process reached its test code, and the fixture denials below were enforced by Windows. The worker is still this user. That is not a boundary against TM-C. The production agent stays in the interactive process. No account, profile, AppContainer process, or VM was deployed.
- Milestone: LCA-01M

## What was compared

| Variant | What it is | What this milestone did |
| --- | --- | --- |
| Same user | Another process with this token | Already measured in [LCA-ARCH-24](LCA-ARCH-24.md). Not treated as isolation. |
| Restricted token | `CreateRestrictedToken` and `CreateProcessAsUserW` | The process reached user code. Access checks below are from that process. |
| Separate local user | Another logon, ACLs, no shared DPAPI scope | Not provisioned. `LogonUserW` was not called. |
| AppContainer | AppContainer profile and capability SIDs | Profile created and deleted. No process was started. |
| VM | Hyper-V or Windows Sandbox | The host binaries were absent. Nothing was installed or started. |

## Restricted token that actually ran

`CreateRestrictedToken` used `DISABLE_MAX_PRIVILEGE | SANDBOX_INERT`. Restricting SIDs were BUILTIN\Users (`S-1-5-32-545`), Everyone (`S-1-1-0`), and the logon SID. The interactive user SID was not a restricting SID.

The worker reported, from its own process token:

| Field | Measured |
| --- | --- |
| Token type | `1` (primary) |
| Integrity RID | `8192` (medium). Not low (`4096`). |
| Privileges | `5` before the restriction, `1` inside the worker |
| Groups / enabled | `14` / `11` |
| Restricting SIDs | `3` |
| Default DACL ACEs | `3` |
| Logon SID present | `1` |

Launch was `CreateProcessAsUserW` on a copy of the test executable staged outside the user profile, with a DACL granting Users read and execute. The successful attempt was `detached` (suspended, Unicode environment, explicit handle list, inherited desktop). Process exit of that run was `0`. `AssignProcessToJobObject` returned success and `IsProcessInJob` was `1`.

A prior run whose restricting SIDs were only Users and the logon SID started the process and then exited `0xC0000022` (`STATUS_ACCESS_DENIED`) before `reached=1`, on detached, no-window, and empty-desktop attempts. Impersonation of that same token could already open the staged executable (`0`), `ntdll.dll` (`0`), and the Users-readable fixture (`0`), and was denied the user-only file (`5`). Adding Everyone is what let user code run. The likely missing grant is a system object, such as a KnownDlls section, whose DACL grants Everyone and not Users. This run did not take a kernel trace of that object. A private window station was implemented as a later attempt and was not the attempt that reached user code. `WinSta0` was not modified. The process was not elevated.

## What that process could and could not open

Temporary objects only. The protected files used a protected DACL for this user and SYSTEM, so Users, Everyone, and the logon SID were not granted.

| Probe | Result |
| --- | --- |
| Users-readable fixture | open `0` |
| User-only file read and write | `5` |
| Test proposal store | `5` |
| Test evidence file | `5` |
| Sibling path outside the stage, read and write | `5` |
| Hard link from the writable directory onto the user-only file | `5`, link path absent |
| Writable drop directory | `0` |
| Broker-duplicated read handle | read `0`, write `5`, bytes `fixture-bytes` |
| Handle omitted from the inheritance list | `ReadFile` `6` |
| DPAPI on the ciphertext supplied in the environment | `ok` |
| Named pipe created by the worker | `0` |
| Same interactive user opening the user-only file afterwards | `0` |

`5` is `ERROR_ACCESS_DENIED`. `6` is `ERROR_INVALID_HANDLE`. DPAPI succeeded because the blob was already in the worker environment and the logon is still this user. The evidence file itself stayed unreadable. A file whose DACL grants Everyone or Users is still readable: the allowed fixture is that case. This is an ACL split inside one user, not a second principal.

## Separate user, AppContainer, VM

| Probe | Measured | Isolation claim |
| --- | --- | --- |
| Account creation and `LogonUserW` | not called | INCONCLUSIVE |
| Same SID accepted as a separate principal | rejected by the contract | Contract only |
| `CreateAppContainerProfile` | `0` | Profile API works |
| `DeleteAppContainerProfile` | `0x0` | Profile removed |
| AppContainer process | `appcontainer_launched=0` | Not tested |
| `vmcompute.exe`, `WindowsSandbox.exe`, `vmwp.exe` | absent | Not installed here |
| VM process | `vm_started=0` | Not tested |

A separate account would need a local user, a password, and a profile. Those were not created. No Windows feature was enabled.

## Evaluation

`tested` means this process measured it. `documented` means the record states the limit. `unproven` means this milestone did not run that configuration.

| Property | Same user | Restricted token | Separate user | VM |
| --- | --- | --- | --- | --- |
| Worker isolation | documented, not a boundary | tested, still this user | documented, unproven | documented, unproven |
| Proposal store | documented, this user can open it | tested on a user-only test file (`5`) | unproven | unproven |
| Evidence | documented, DPAPI is this user | file `5`; supplied ciphertext unprotects | unproven | unproven |
| Workspace | in-process checks only | tested on the fixtures above | unproven | unproven |
| Hard link | documented, still reproducible against this user | tested, create returned `5` | unproven | unproven |
| IPC authentication | a shared secret is not a boundary | tested, pid and token, same user | unproven | unproven |
| Process containment | a job is not a different principal | tested, see [LCA-ARCH-28](LCA-ARCH-28.md) | unproven | unproven |
| Operational complexity | current product | test harness only | account, profile, ACLs | hypervisor feature, absent here |

## What is not claimed

- That the interactive user is confined. That user opened the denied file after the worker was denied.
- That Everyone or Users objects are hidden from the worker.
- That DPAPI changes scope under this token.
- That an AppContainer or a VM would pass the same tests. They were not started.
- That the production publisher, registry, or controllers moved.
