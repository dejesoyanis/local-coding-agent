# LCA-ARCH-31: Workspace, evidence, and handle isolation contract

- Status: Accepted
- Decision: The cross-identity resource rules are implemented and unit-tested. They were not measured from a process with a different user SID. A same-user hard link still succeeds. No production ACL, proposal store, or evidence file was modified.
- Milestone: LCA-01N

## Rules the harness encodes

| Object | Worker rule |
| --- | --- |
| Proposal store | No direct open. The test file is locked to the broker user and SYSTEM. |
| Recovery evidence | Same lock. DPAPI of the broker user is not a substitute for that lock. |
| Restoration evidence | Same lock. |
| Workspace | No direct open of an unregistered file. `fixture-001` is broker memory, not a path. |
| Outside the stage | A protected sibling is the same class of denial as the store. |
| Hard link | `hardlink_is_violation` is true when a link to a protected target is created. |
| Handles | The type has standard null, a report write, and a fixture read. There is no store handle, evidence handle, or process handle in the list. |
| Grants | Only the broker inserts `fixture-001`. |

`INV-04` and `INV-05` stay inconclusive until `Verification::AccessChecked` and every measured open is denied. A missing measurement is not a pass.

## What was measured without a second user

| Probe | Result | Meaning |
| --- | --- | --- |
| `AccessCheck` for an unrelated SID | `foreign_denied=1` | The broker token does not receive `FILE_READ_DATA` from an ACE that does not grant it. |
| `AccessCheck` for the broker user | `self_allowed=1` | The same API allows an ACE that names this token. |
| Temporary owner and DACL | `owner_match=1`, `ace_count=2` | `GetNamedSecurityInfoW` on a file this process locked to itself. The file was deleted. |
| Hard link by this user | `same_user_hardlink=0` | The link was created. `cross_identity=0`. |
| Mode B worker opens | not run | `worker_started=0`. |

The temporary DACL is protected and not inherited (`grfInheritance = 0`). It is not a production ACL. Everyone was not granted.

## Handles

An inherited handle is itself a capability. The launch contract sets `inherit_unlisted` to false and rejects a fixture mask that can write or change the DACL. `CreateProcessWithLogonW`, if it is reached, is called with `bInheritHandles = FALSE` because that API has no explicit handle list. No handle was duplicated into another user's process in this run.

LCA-01M still holds the measurement for a restricted token of this user: the granted read handle returned the fixture, the omitted handle returned `6`, and the store file returned `5`. That token is the same user. It is not evidence for this decision.

## Four boundaries that are not the same

| Goal | This milestone |
| --- | --- |
| Host protected from the worker | Not established. No other principal ran. |
| Worker protected from the host | Not claimed. A different SID does not take the host user's rights away from the host. The same-user hard link shows the host can still name its own file. |
| Broker protected from the worker | The broker denies unregistered capabilities, paths, replays, and its own SID. A live worker of another user did not connect. |
| Broker protected from other host processes | A same-user pipe client was denied a session. That client was this test, not a hostile program. PID recycle is the reason the logon id and the impersonation token are required. The impersonation half returned `impersonation=0` here. |

## Threat models

TM-A, the untrusted model, cannot see this module. It is `cfg(all(test, windows))`. The tool registry is unchanged: no `execute`, `shell`, or `open_path`.

TM-B, concurrent trusted tools, is unchanged. This milestone did not take a new publication race.

TM-C, a malicious process of the host user, is not stopped by the contract. That process can still open what the host user can open, including a hard link (`same_user_hardlink=0`). It cannot become a broker session merely by sending the worker's session id: the session is refused for the broker's own SID, and a foreign SID inside JSON is `deny:schema`. It was not shown whether that process can satisfy `ImpersonateNamedPipeClient`. No second principal was available to compare.

## What is not claimed

- That the temporary ACE layout is the production store ACL.
- That a hard link across a user boundary was attempted. It was not.
- That job close was observed for a cross-identity process. The predicate `abort_contains` is unit-tested. The process was not started.
