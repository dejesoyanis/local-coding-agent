# LCA-ARCH-24: Windows isolation strategy

- Status: Accepted
- Decision: **B. Additional isolation is required** before the agent claims a boundary against a malicious same-user process, and before any command execution. The current process remains variant A. No production component moves to another token, user, or job. A separate Windows principal (variant D) or a VM (variant E) is the class of isolation that would change TM-C. Variant B does not. Variant C, as measured here, does not either.
- Milestone: LCA-01L

## What was compared

| Variant | What it is | What this milestone did |
| --- | --- | --- |
| A | Controller and tools in one process, this user | Already the product. Not changed. |
| B | Another process, same user | Test harness only. IPC, handle inheritance, job assignment, and the LCA-01K-style attacks. |
| C | Restricted token, and a low-integrity impersonation token | Created without changing accounts. Impersonation was measured. `CreateProcessAsUserW` returned success and the process exited `0xC0000022` before user code. |
| D | Another local user, ACLs, a broker | Not created. No account or privilege was changed. |
| E | Hyper-V or Windows Sandbox | Not installed and not started. |

None of these is a control against the host user who can administer the machine. A host principal that can change tokens, ACLs, or the hypervisor can bypass a local boundary.

## What the runs showed

Variant B, on this machine:

- A wrong 32-byte token on an inherited pipe is rejected (`DENY auth`, exit 2). `mutate` is rejected. A frame over 1024 bytes is rejected. The worker's reported pid matches `CreateProcessW`.
- `TerminateProcess` ends the worker. A watcher that opened the controller with `SYNCHRONIZE` observed the controller exit.
- An inheritable file handle read `in` in the child (`bytes=696e`). The non-inheritable handle returned `ReadFile` error 6 (`ERROR_INVALID_HANDLE`). Handle inheritance is real when the bit is set, and it is not a security boundary against a process that can open the same path itself.
- `AssignProcessToJobObject` returned 0. The worker still answered `echo`. A job without a different token did not remove the worker's rights.
- The second process created a hard link, read DPAPI, and overwrote the evidence file. Rename of the pinned name returned 32. Parent rename returned 5. Those denials come from the share mode, which production already uses, not from having two processes.

Variant C:

- `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` and a restricting SID of BUILTIN\Users succeeded. Privilege count went from 5 to 1. Group count stayed 14.
- Impersonating that token read the file whose DACL grants Users (`0`) and was denied the file that grants only the user (`5`).
- `CreateProcessAsUserW` returned 0. The process exit code was `3221225506` (`0xC0000022`, `STATUS_ACCESS_DENIED`). The child did not write its report. That is not a successful sandboxed worker.
- A duplicated low-integrity token read a medium file (`0`) and failed the write (`5`). After `RevertToSelf`, the medium user wrote the same file. Low integrity is not a sandbox against this user.

## Evaluation

| Question | A | B | C, as measured | D, not built | E, not built |
| --- | --- | --- | --- | --- | --- |
| Stops a model from calling an unregistered tool | Yes, in process | Same checks if the worker validates | Same, if the worker starts | Same | Same |
| Stops a same-user process | No | No | No against a medium process | Would, for files the other user cannot open | Would, if the VM does not share the user |
| Protects the proposal store from this user | No | No | Not shown. Impersonation still runs as this user | Only if the store ACL excludes the interactive user | Only if the store is not shared into the VM |
| Protects recovery evidence from this user | No | No. Overwrite succeeded | Not shown | Same condition as the store | Same condition as the VM share |
| Workspace access | Full user rights | Full user rights | Impersonation split one file. The process did not start | Broker must pass each granted file | Share must be explicit |
| Publication races | Unchanged | Unchanged. Pin still matters | Not a fix for hard links | Not a fix for a race inside the principal that writes | A race inside the VM remains |
| Hard link out of the workspace | Succeeds for this user | Succeeded | Not retried under the token that could not start | Depends on cross-user link rights | Depends on the share |
| IPC | In process | Pipe token stops a process that lacks the handles. It does not stop this user from reading the child | Would need a broker | Broker is the security boundary | Host broker |
| Performance and operations | Lowest cost | Extra process | Token and ACL work, plus a broker | Account, ACL, and broker | Highest cost |
| Later command execution | Runs as this user | Runs as this user | Not demonstrated. `0xC0000022` stopped startup | Possible only under the other principal | Possible inside the VM |

## Decision

Keep variant A for the current read, prepare, and human-approved apply path. Do not describe it as isolation from TM-C.

Do not adopt variant B as a security boundary. A second process is useful for crashes and for validating messages. It is the same user.

Do not adopt the measured restricted token or low integrity as the sandbox. The impersonation split is real and narrow. The process did not run. The interactive user still writes.

Variant D is the smallest isolation that would make DPAPI and the store ACL mean something against other processes of the interactive user. It needs a broker: the other user must not be able to open the proposal store, the evidence files, or an arbitrary path, and the interactive user must still approve writes. That design is not implemented here.

Variant E is stronger and was not tested. It is not required to keep the current tools on the human-approved path. It is in scope again if command execution needs a boundary the Windows principal cannot provide.

Command execution stays disabled until one of D or E is implemented and measured. An allowlist is not that measurement ([LCA-ARCH-25](LCA-ARCH-25.md)).
