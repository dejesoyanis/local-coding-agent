# LCA-ARCH-30: Cross-identity broker authentication and authorization

- Status: Accepted
- Decision: Protocol 2 is an experimental broker in the Windows test harness. A well-formed message is not a grant. The broker did not authenticate a process running as another user. It is not on the model path.
- Milestone: LCA-01N

## What the broker accepts

Capabilities: `ping`, `worker_info`, `read_fixture`.

Denied by name: `execute`, `shell`, `write_file`, `apply_patch`, `restore`, `approve`, `change_policy`, `open_path`.

`read_fixture` resolves `fixture-001` to bytes the broker already holds and returns them as hex. `resource_id` is not opened as a path. `C:/secret` is `deny:resource`.

The worker cannot add a grant. After `approve` is denied, the map still has only `fixture-001`.

## Message

```json
{"protocol_version":2,"session_id":"session-a","request_id":"req-ping","capability":"ping","resource_id":"","issued_at":0,"expires_at":1000,"policy_version":1}
```

`policy_version` must be 1. A body that contains `user_sid`, `logon_sid`, `password`, or `token` is `deny:schema` before a session lookup. The unit test sent a claimed SID and got `deny:schema`.

## Authorization order

Size and printable ASCII, smuggled identity fields, schema, protocol version, policy version, then the session table. The session must be alive and its user SID must not be the broker's. The observed peer must match the session's pid, user SID, impersonation SID, logon id, and pipe instance. Then lifetime, rate, replay, capability, and resource.

A syntactically valid `ping` with no session is `deny:session`. A matching session with a different logon id, pipe instance, pid, or impersonation SID is `deny:identity`.

The peer is an argument to `decide`. The pipe server is responsible for filling it from `GetNamedPipeClientProcessId`, the process token, and `ImpersonateNamedPipeClient`. The JSON body is not that source.

## What the live pipe showed

A same-user client connected to a pipe whose DACL grants the current user and SYSTEM, not Everyone. The server read the client process token. `observed_sid_match=1`. The message did not carry a SID. The decision was `deny:session` because the broker refuses to open a session for its own user SID. A second body that added `user_sid` was `deny:schema` (`message_sid_used=0`).

`impersonation=0` on that connection. `ImpersonateNamedPipeClient` did not produce a token whose SID and authentication id both matched the process token. The process token was still read. A future allow path requires `impersonation_ok`. This run did not get an allow from a live pipe, and it did not get one from another user.

## Replay

The replay set is in memory, keyed by session id and request id. This run denied:

| Case | Result |
| --- | --- |
| Same request id in the same live session | `deny:replay` |
| `expires_at` already past | `deny:lifetime` |
| Unknown session id | `deny:session` |
| Session closed, then the old id reused | `deny:session` |
| New session id with the previous logon id | `open_session` is refused while the old id is still stored |

A new process that constructs an empty broker has no sessions, so an old session id cannot be replayed until something inserts that session again. The harness does not persist either table. Persisting sessions without the replay set would be unsafe. That configuration was not built.

The rate cap is 8 messages per session. The frame cap is 1024 bytes. The lifetime cap is 30 seconds, with 5 seconds of future skew.

## Launch interface

`LaunchSpec` carries the account name, the executable path, the working directory, an explicit handle list, `inherit_unlisted`, the pipe endpoint, and a timeout. `validate_launch` accepts only the executable the harness selected. `cmd.exe`, `powershell.exe`, `cargo.exe`, and `rustc.exe` are rejected. `inherit_unlisted` is rejected. A fixture handle whose mask includes write, delete, `WRITE_DAC`, or `WRITE_OWNER` is rejected. The endpoint must be `\\.\pipe\lca-01n-` plus an identifier.

The command line is the quoted executable plus `principal_probe::cross_identity_child --exact`. It has no password parameter. The environment builder refuses secret-shaped keys.

`CreateProcessWithLogonW` is the implemented launch call for a second principal because `CreateProcessAsUserW` needs `SeAssignPrimaryTokenPrivilege`, which this process does not enable. `CreateProcessWithLogonW` cannot take `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, so a cross-identity launch uses `bInheritHandles = FALSE` and an empty handle list. The fixture would have to move through the broker, not through an inherited handle. That launch was not executed.

## What is not claimed

- That a same-user process is a worker. The broker refuses that SID.
- That `impersonation=0` was diagnosed past the comparison result.
- That protocol 2 replaces the LCA-01M restricted-token broker. That broker is unchanged and still version 1.
- That the model can call either broker.
