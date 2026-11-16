# LCA-ARCH-15: Durable proposal state and recovery

- Status: Accepted
- Decision: The existing nine states stay. A sealed preimage and phase record are written before the target changes. Recovery classifies bytes and file id. It does not write the target and it does not reuse an approval.
- Milestone: LCA-01I

## Context

LCA-01H already stores `Applying` before `apply_ntfs` and reconciles `Applying` and `Unclear` by hash plus file id. That record did not contain the original bytes, so a torn file could be recognized only as "neither hash". There was no separate process kill, so a fault that returned inside the same process still ran the failure writer.

## States

No new state byte was required. The contract version stays 1. Unknown state bytes still fail closed.

| State | Recovery |
| --- | --- |
| `Prepared`, `Approved` | Expire when the TTL has passed. Otherwise unchanged. |
| `Applying` | `Applied` when the proposed hash and the same file id are present. `Failed` when the original hash and the same file id are present. Otherwise `Unclear`. |
| `Unclear` | Same two evidence rules. A different file id stays `Unclear`. |
| `Applied`, `Failed`, `Rejected`, `Expired`, `Conflict` | Not rewritten. |

`Failed` means the approved bytes were not published. It is not an invitation to try the same approval again. `approve` rejects every state other than `Prepared` and `Approved`.

## Order

1. The proposal digest, workspace id, path, file id, and approval line are checked.
2. `Approved` is stored with `sync_all`, then renamed into place.
3. `Applying` is stored the same way, and `apply_started` is appended and flushed.
4. The open handle's bytes are hashed. On a match, the original bytes, both hashes, the file id, and a new attempt id are sealed as evidence and synced before any target `WriteFile`.
5. The staged image is written, flushed, and read back.
6. `mutation_started` is recorded, and the exclusive handle is written.
7. After `FlushFileBuffers`, `mutation_published` is recorded and the handle is read back.
8. `verified` is recorded only when that read-back matches. `Applied` is stored after that.

A kill after step 4 and before step 6 leaves the original bytes. Reconciliation stores `Failed`. A kill inside step 6 can leave a mixture. Reconciliation stores `Unclear` and does not copy the sealed bytes back. A kill after the new bytes are flushed and before `Applied` is stored reconciles to `Applied` with audit event `recovered`, not `apply_succeeded`.

`sync_all` forces the evidence file and the proposal file through the process and the system file cache as far as `FlushFileBuffers` does for those handles. It does not fsync the parent directory. Power loss can still drop a rename that the kill tests already observed as durable across `TerminateProcess`. That difference is explicit: the kill tests are process-crash evidence, not power-loss evidence.

The audit sequence file is now `sync_all`'d as well. The log line is flushed before the sequence is advanced.

## Recovery

`status` and `recover` run the rules above. `inspect` does not. None of them write the workspace file.

`lca patch inspect <id>` prints the stored state, the three hashes, both file ids, the evidence phase, and a next step. The next step for a torn file says the preimage is sealed and that a new proposal plus a new approval are required. The old confirmation line is not accepted again.

`lca patch recover <id>` applies the state rules and records the recovery tag on the evidence. It does not call `WriteFile` on the target.

Automatic rollback was rejected. Writing the sealed original back would be a second mutation under the spent approval, and a crash in that write would be a second torn file.
