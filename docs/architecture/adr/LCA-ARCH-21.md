# LCA-ARCH-21: Concurrent namespace mutation

- Status: Accepted
- Decision: The threat model for publication is another process of the same Windows user who can create, rename, replace, link, and reparse inside the workspace between two of our calls. A hash is not an identity. An unclear result is not retried. An approval is not reused.
- Milestone: LCA-01K

## Attacker

The attacker is not a different Windows user and not a kernel caller. It is a second process that already has the rights of this user, including write access in the workspace. A debugger attached to this process is outside the model, as is a same-user rewrite of DPAPI evidence. Those limits are unchanged from LCA-01J.

The operations in scope are:

| Action | What it tries to change |
| --- | --- |
| Rename of the target | The directory entry that readers open |
| Replace of that entry | Which object the name denotes |
| Rename of a parent directory | The path walk, not the open file object |
| Delete and recreate | A new file id at the same name |
| Hard link | Another name for the same file id, including a name outside the workspace |
| Junction or file symlink | A reparse point where a path walk would leave the workspace |
| Change or removal after validation | The object or the name between the check and the write |

## Classes

- **Target identity.** The file id and volume of the handle that was checked.
- **Namespace binding.** The directory entry a later open of the path returns.
- **Content integrity.** Whether a reader can observe a prefix of the new bytes and a tail of the old bytes.
- **Workspace boundary.** A write that becomes visible through a hard link or a reparse point outside the workspace.
- **Recovery evidence.** The sealed preimage, the one-shot approval, and the rule that an unclear file is not rewritten.

## Invariants

**INV-01.** No publish onto a target the approval did not name. The production open is still the relative walk from the workspace root. A failed open does not fall back to a path replace.

**INV-02.** No silent substitution of the checked object. If the name no longer denotes that file id, the publication is a violation even when the staged bytes are well formed.

**INV-03.** No publication of a partial image as success. Strategy A can leave a torn file. That result stays `Unclear` until a person authorizes restoration. It is not reported as atomic.

**INV-04.** No unobserved mutation outside the workspace. A hard link created during `BeforeRename` is visible to this model: the outside name received the new bytes. The milestone records it and does not weaken the link-count check.

**INV-05.** No automatic retry after an unclear result. The kill parent reads the file twice and does not write it. `taskkill /F` is not repaired by the harness.

**INV-06.** No reuse of an approval. The harness token stays `single-use`. The production ledger is unchanged and still rejects a second approve.

**INV-07.** No weakening of the privacy policy. The experimental module is `cfg(test)` and is not on the apply path. Reserved names, streams, and `..` still fail the production open.

**INV-08.** A hash does not prove which object was written. The swap tests keep the original hash on the moved file id while the name shows either a decoy or the staged bytes.

**INV-09.** No production strategy change without a new accepted architecture decision. This decision does not authorize one.

## What the measurements add

While the production handle omits `FILE_SHARE_DELETE`, a second process's `MoveFileExW` of that name returns `32`. `DeleteFileW` returns `32`. A parent rename and a replace onto the name return `5`. Eight of eight renames against that pin failed. Eight of eight renames against `FILE_SHARE_READ | FILE_SHARE_DELETE` succeeded. An exclusive byte-range lock did not stop the second case. The fresh read of the moved file returned `33` until the locking handle was closed.

Those are observations on this NTFS volume. They are not a proof about every future filter driver.
