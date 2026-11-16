# LCA-ARCH-08: Persistent verified patch proposals

- Status: Accepted
- Decision: Store the exact proposed bytes outside the workspace, bound to a live workspace identity
- Milestone: LCA-01G

## Context

LCA-01D keeps `PreparedPatch` in memory. The approval ledger dies with the process, so a later CLI invocation cannot apply the same reviewed bytes. A diff alone is not enough: applying it again can mean something else if the file changed.

A SHA-256 digest names bytes. It does not prove that the file on disk is the file the operator reviewed, and it does not authenticate the proposal against someone who can edit the proposal directory.

## Decision

One proposal record, contract version 1, is the persistent form of `PreparedPatch`. It stores the patch text and the exact proposed bytes. On apply, the patch is replayed and must equal those bytes. The diff is what the operator reads. The bytes are what get written.

The record also stores:

- proposal UUID and contract version
- workspace volume serial, 128-bit file id, and canonical root path
- relative target path
- created and expiry timestamps (24 hours)
- original, proposed, and patch SHA-256
- original and proposed sizes
- target volume serial and file id captured at prepare
- lifecycle state
- proposal digest

The digest is SHA-256 over the canonical body, excluding the state byte, so a legal state change does not retarget an approval. The stored file is `canonical body || state || digest`. A load recomputes the digest and rejects a mismatch.

Workspace identity is recomputed from the live root directory: volume serial, file id, and canonical path. It is not a string from the model and not a UUID stored inside the workspace. The store key is the hex SHA-256 of `LCA-01G-WORKSPACE-V1`, the volume, the file id, and the path.

- A copy has a new file id and a new path. Its proposals are not visible.
- A move that keeps the file id still changes the path component, so the record does not match.
- A restore normally gets a new file id.
- A proposal from workspace A is not applied in workspace B. The operator prepares it again.

The store lives in `%LOCALAPPDATA%\lca`, or in `LCA_STATE_DIR` when that variable is set. The variable only moves the same store. It is not an approval. Proposal files are not workspace files, so model tools cannot read them through the sandbox. The directory ACL is owner plus LocalSystem, protected, and checked again before use. The bytes are DPAPI ciphertext with the entropy label `LCA-01G-PROPOSAL-V1` and `CRYPTPROTECT_UI_FORBIDDEN`. Proposal files are still parsed as untrusted input: bad labels, versions, sizes, and digests fail closed.

An HMAC key in the same directory would be readable by the same user who can already call DPAPI. That is not a stronger boundary. The trust boundary is the Windows user. A process running as that user can forge a ciphertext. The model tool surface cannot reach this directory. If DPAPI or the ACL cannot be established, `save` and `approve` fail closed. Non-Windows builds have no verified store and fail closed.

States: `Prepared`, `Approved`, `Applying`, `Applied`, `Rejected`, `Expired`, `Conflict`, `Failed`.

Allowed edges:

```text
Prepared -> Approved | Rejected | Expired
Approved -> Applying | Rejected | Expired | Conflict
Applying -> Applied | Failed | Conflict
```

`Applied`, `Rejected`, `Expired`, `Conflict`, and `Failed` have no apply edge. A consumed approval is not reused. A failed apply is not retried by calling approve again.

## Consequences

- The same `PreparedPatch` engine prepares and applies. There is no second patch engine.
- The digest binds the human confirmation to the reviewed body. It is not a MAC against the current user.
- Full proposed bytes are stored. They can contain source code, so the ciphertext and the ACL are the protection. Audit lines do not contain file bytes.
