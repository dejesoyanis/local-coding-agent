# LCA-ARCH-27: Capability broker and authenticated IPC

- Status: Accepted
- Decision: An experimental broker in the Windows test harness authenticates the process it started and serves three capabilities. A well-formed request is not a grant. The broker is not on the model path, and it does not open the workspace.
- Milestone: LCA-01M

## Responsibilities that exist in the harness

| Duty | Enforcement |
| --- | --- |
| Worker identity | Pipe peer pid from `GetNamedPipeClientProcessId`, then `OpenProcess` and `OpenProcessToken`. User SID compared with `EqualSid`. Restricting-SID count taken from that process token. |
| Claimed id | `worker_id` must equal the id the broker stored at construction. A matching string from another pid is denied. |
| Message shape | Version 1, one occurrence of each field, identifier charset, printable ASCII. |
| Capability | `ping`, `worker_info`, `read_fixture` only. |
| Resource | `resource_id` is a key in the broker map. It is not opened as a path. `read_fixture` resolves `fixture-001` to bytes the broker already holds. |
| Limits | 1024 bytes, 8 accepted messages per pid, 30 seconds, 5 seconds of future skew, one use of each request id. |
| Audit | One line per decision: pid, id, capability, decision, error. |
| Rejection | Identity failures do not consume the rate budget. There is no retry. |

`shell`, `write_file`, `execute`, and `apply_patch` are denied as capabilities. The unit test covers those names. The pipe server never receives a filesystem path from `resource_id`.

## Contract

```json
{"protocol_version":1,"request_id":"req-read","capability":"read_fixture","resource_id":"fixture-001","worker_id":"worker-ipc","issued_unix_ms":0}
```

The response is the same version, with `decision`, `error`, and `payload`. `read_fixture` returns the fixture as hex. The payload measured for `fixture-001` was `666978747572652d6279746573` (`fixture-bytes`).

## Authorization order

Size and ASCII, then schema, then `protocol_version == 1`, then identity, then the per-pid counter, then rate, lifetime, replay, capability, and resource. The worker run produced:

`allow, allow, allow, deny:resource, deny:replay, deny:capability, deny:identity, deny:resource, deny:lifetime, deny:rate, deny:size`

The parent process sent `ping` with the real worker id. The audit line for that parent pid is `deny` / `identity`. The worker's own pid received the allows.

## IPC

The channel is a message-mode named pipe. `PIPE_REJECT_REMOTE_CLIENTS` is set. The DACL grants this user and SYSTEM full access, and grants Users read and write so the restricted worker can connect. That DACL does not stop another process of this user. The identity check does.

Impersonation of the pipe client is used only to compare the user SID. A successful impersonation whose SID differs is rejected. The restricting-SID count is read from the process token, not from the impersonation token. The broker does not accept a pid that is not the pid it launched.

A secret in the message is not the boundary. The tested boundary is the Windows pid plus that process's token, and it still sits in this logon.

## Handles

`CreateProcessAsUserW` used `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. The list held the NUL standard handles, the report-pipe write end, the request-pipe read end, and one file handle opened with `FILE_GENERIC_READ` and the inherit bit. The test store handle was not inheritable and was not in the list. The worker's `ReadFile` on that numeric value returned `6`. The granted handle read the fixture and rejected a write with `5`.

The worker does not receive a directory handle for the workspace. The one file it can use is the handle the broker chose. Revocation in this harness is process exit and job close, not a later `DuplicateHandle` undo.

## What is not claimed

- That a same-user process cannot open the pipe. It can. It cannot pass the pid and token check unless it is the launched worker.
- That the worker cannot create some other pipe. It created one (`own_pipe=0`).
- That this broker is wired to `lca-tools` or the model.
