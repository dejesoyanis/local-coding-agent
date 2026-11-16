# LCA-ARCH-13: Failure atomicity, recovery, and fault injection

- Status: Accepted
- Decision: A mutation that may have started becomes `Unclear` until the target bytes and file id reconstruct one of two evidence states. Recovery never writes the file.
- Milestone: LCA-01H

## Context

LCA-01G mapped a failed read-back to `Conflict` and left the new bytes in place. The name `verify_failed` could be read as "the write was undone". It was not. There was no way to force that branch in a test.

## Decision

`State::Unclear` is byte 9. The contract version stays 1. An unknown state byte still fails closed. New transitions are `Applying → Unclear`, `Unclear → Applied`, and `Unclear → Failed`. `Failed`, `Conflict`, `Applied`, `Approved`, and `Prepared` are not rewritten by recovery.

`ApplyFault` is an internal enum. `ProposalStore::approve` always passes `ApplyFault::None`. The CLI has no flag and no environment variable that arms a fault. Tests call `approve_with`.

The points, in order, are:

| Point | Mutation | Stored state if the fault is the result |
| --- | --- | --- |
| `AfterValidation` | not started | stays `Prepared` |
| `AfterApproval` | not started | stays `Approved` |
| `AfterTempCreate` | not started | `Failed` |
| `AfterWrite` | not started | `Failed` |
| `BeforeRename` | not started; this is the last point before the verified handle changes | `Failed` |
| `AfterRename` | published; the name is historical, the operation is the in-place flush | `Unclear` |
| `BeforeReadback` | published | `Unclear` |
| `DuringReadback` | published; returned as `verify_failed` | `Unclear` |
| `AfterVerification` | published and the read-back matched | stays `Applying` until reconciliation |
| `BeforeAudit` | published and recorded `Applied` | `Applied`, without `apply_succeeded` |

`published` is the platform flag. It is true only after `publish_handle` has been entered. A later verification failure does not clear it and does not restore the previous bytes.

## Recovery evidence

`status`, `show`, and `approve` reconcile `Applying` and `Unclear` by opening the target again:

- Reparse, directory, `link_count != 1`, a zero file id, or a read error stays `Unclear`.
- Proposed SHA-256 and the same volume and file id become `Applied`.
- Original SHA-256 and the same volume and file id become `Failed`.
- Any other bytes, or the same hash on a different file id, stay `Unclear`.

A reconstructed `Applied` writes the audit event `recovered`. It does not write `apply_succeeded`. It does not write the file. A second approve is rejected. If the original bytes are still there, the process does not reuse the approval; the state is `Failed` and apply is not attempted again. Unknown bytes stay `Unclear` or, when the failure happened before publication and the identity check failed, `Conflict`.

## Audit

New events, none of which contain file bytes: `mutation_started`, `mutation_published`, `verified`, `verification_failed`, `state_unclear`, `recovered`. Existing events stay: `created`, `shown`, `approved`, `rejected`, `apply_started`, `apply_succeeded`, `apply_failed`, `conflict`, `expired`.

A successful apply records `apply_started`, `mutation_started`, `mutation_published`, `verified`, then `apply_succeeded`. `mutation_published` means the handle was flushed. It does not mean a rename occurred. `verified` is not written when the read-back failed.

## Rollback

No automatic rollback is implemented. Writing the original bytes back would be a second unchecked mutation, and a crash in that write would be a second torn state. When the bytes are unknown, the state stays `Unclear` for a person to resolve.
