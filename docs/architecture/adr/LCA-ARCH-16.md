# LCA-ARCH-16: Publication evidence

- Status: Accepted
- Decision: Each apply attempt seals one DPAPI evidence file beside the proposal. The approval digest does not change when the evidence phase changes. A hash match without the approved file id is not success.
- Milestone: LCA-01I

## Context

The proposal digest binds the human approval to the workspace, the path, the file id, and the original and proposed hashes. Putting changing phase flags inside that digest would either invalidate the approval during the attempt or let a status write pretend the reviewer had signed the phase. The phase therefore lives in a second file, `{proposal-id}.lcae`.

## Record

The plaintext, before DPAPI, is length-prefixed and ends with the SHA-256 of the body. The label is `LCA-01I-EVIDENCE-V1`. The strategy byte is `1` (`pinned_in_place`). Any other strategy fails closed. The body carries:

- proposal id and proposal digest
- attempt id, generated for this attempt
- target volume and file id before the write
- file id after the write, or zeros until verification
- original and proposed SHA-256
- the original bytes themselves
- phase: `intent`, `staged`, `mutation_started`, `published`, `verified`
- flags for stage completion, mutation start, and publication completion
- verification: `unknown`, `match`, `mismatch`
- recovery: `none`, `applied`, `failed`, `unclear`
- sealed and updated timestamps

`inspect` prints the names and the hashes. It does not print the sealed bytes.

## Invariants

- One approval starts at most one attempt. A second `approve` is rejected after the state leaves `Prepared`.
- `AfterIntent` and every later kill point in `killed_child_is_recovered_without_a_rewrite` find `apply_started` once. Recovery does not add another.
- `verified` is written only after the handle read-back matches the proposed bytes. A hash of some other file is not that check. `classify_target` also requires the same volume and file id.
- A torn read, where the hash is neither original nor proposed, stays `Unclear`. The evidence phase is not promoted to `verified`.
- Missing evidence stays `absent`. A digest or DPAPI failure stays `invalid`. Neither value is replaced with a success flag.
- The attempt id in the evidence is not an approval. `recover` does not read it as permission to write.
