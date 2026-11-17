# LCA-ARCH-18: Verified restoration and recovery evidence

- Status: Accepted
- Decision: Restoration writes through the existing exclusive-handle publisher. Recovery classifies bytes and file id. It does not write, and it does not reuse the restoration approval.
- Milestone: LCA-01J

## Publisher

`apply_image_controlled` checks the restoration image marker, the grant, privacy, the timestamp identity, and then calls `apply_ntfs`. That is the publisher LCA-01H and LCA-01I already use: exclusive handle, file id check, hardlink refusal, reparse refusal, staged read-back, `WriteFile`, `SetEndOfFile`, `FlushFileBuffers`, and a handle read-back. There is no second write implementation and no rename fallback.

The image's "original" hash is the hash captured at restoration prepare. The image's new bytes are the sealed preimage. A unified diff is not replayed. A torn file is not required to be a valid patch context.

Before `Restoring` is stored, the evidence, workspace, file id, current hash, privacy rule, link count, and reparse state are checked again. `apply_ntfs` checks the handle again immediately before `WriteFile`. A mismatch fails closed.

## Attempt record

`.lcae` stays the publication preimage. Restoration does not rewrite it. The attempt record is `{restoration-id}.lrae`, label `LCA-01J-ATTEMPT-V1`. It is sealed and `sync_all`'d before the target `WriteFile`, and it holds the bytes that were current at that moment. Phase flags live there. They are not part of the restoration digest.

## Recovery

`status` and `recover` read the target. They do not call `WriteFile`.

| Observed bytes and file id | Next state |
| --- | --- |
| Restored hash, same file id | `Restored` |
| Hash captured at prepare, same file id | `Failed` |
| Anything else, including a different file id or an unreadable target | `Unclear` |

`Failed` means this approval did not publish. It is not permission to run it again. `Unclear` stays until a later read matches one of the two hashes. A new restoration id is a new decision. `Prepared`, `Approved`, and `Restoring` block a second prepare. `Unclear` does not, because the old approval still cannot write.

## Evidence boundary

`.lcae` and `.lcar` are DPAPI blobs in a directory whose ACL is restricted to the current user. SHA-256 detects a torn or partially edited record. It does not stop the same Windows user, who can unprotect, edit, and protect again. This milestone does not claim a same-user boundary. A debugger on this process is outside the claim as well.

Publication evidence is not deleted. `publication_evidence_may_be_deleted` returns false for every state. There is no cleanup command.

## What is not claimed

- Atomic visibility. The publisher is still the in-place write from LCA-ARCH-14.
- Power-loss durability. The kill tests use `taskkill /F`. `FlushFileBuffers` and `sync_all` are not a power-loss proof, and the parent directory is not flushed.
- That a same-length `WriteFile` is split by the `DuringPublish` hook. The hook runs after the first successful transfer. A transfer that already wrote every new byte is complete before `SetEndOfFile`. The partial case in the kill test is a longer target, so the tail is still the old bytes when the hook runs.
