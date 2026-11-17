# LCA-ARCH-17: Independent restoration authorization

- Status: Accepted
- Decision: Restoring a sealed preimage is a new contract, a new id, and a new confirmation line. The proposal approval is not accepted.
- Milestone: LCA-01J

## Context

LCA-01I can recognize a torn file and can show that the preimage is sealed. It does not write that preimage back. Writing it back under the original approval would be a second mutation with a spent grant. A crash during that write would be a second torn file.

## Contract

The record label is `LCA-01J-RESTORATION-V1`. Contract version is `1`. Any other version fails closed. The digest is SHA-256 of the canonical body. The state byte sits outside the digest, as it does for a proposal, so a state transition does not retarget the confirmation line.

The body binds:

- `restoration_id`, which is not the proposal id and not the proposal action id
- `source_proposal_id` and the source proposal digest
- workspace volume, file id, and path
- relative target path
- target volume and file id
- the timestamp identity captured at prepare
- `current_sha256` and the current bytes
- `restored_sha256` and the restored bytes
- `original_evidence_sha256`, the hash of the immutable evidence preimage
- the publication-evidence attempt id
- creation and expiry

The confirmation line is `restore {restoration_id} {first 16 hex chars of the digest}`. A line that starts with `approve` is rejected. There is no `--yes`, `--force`, or `--auto-approve`. The `lca` binary reads the line only from an interactive console.

## Source

A restoration is prepared only from `Unclear` or `Failed`, and only when publication evidence decrypts, its digest matches, and its original bytes match the proposal's original hash. The open file id must be the recorded target. The current hash must be neither the original nor the proposed hash.

`Applied` is not treated as damaged. `Conflict` is not a source: the target diverged before publication, and overwriting it would discard bytes this program refused to patch. `Prepared`, `Approved`, `Applying`, `Rejected`, and `Expired` are not sources. A missing or undecryptable `.lcae` is not replaced with a guess.

`Failed` whose current bytes still match the sealed original is refused. There is nothing to restore.

## Single use

`approve` accepts only `Prepared`. Accepting the line stores `Approved` and then moves to `Restoring` in that same call. A second call is rejected. A crash after `Approved` is stored, and before `Restoring`, leaves `Approved`. Status does not continue the write. The operator rejects that restoration and prepares a new one.

Terminal states `Restored`, `Rejected`, `Expired`, `Conflict`, and `Failed` do not mutate. `Unclear` can be reclassified from the bytes. It cannot be approved again.
