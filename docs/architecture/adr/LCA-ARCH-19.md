# LCA-ARCH-19: Publication strategy review

- Status: Accepted
- Decision: Keep pinned in-place publication. Atomic publication is the long-term preference only after a new measurement shows the checked object is still the object that readers open. This milestone does not add a rename or `ReplaceFileW` path.
- Milestone: LCA-01J

## The two goals

**Model A, object identity first.** The file id captured before the write is the file id after the write. The mutation is `WriteFile` on that handle. Readers can observe a torn file. Crash recovery and a separate restoration are required.

**Model B, atomic publication first.** The new bytes are prepared in full. A later open of the name sees either the old file or the new file. The file id of the name may change. The publisher has to prove it replaced the intended directory entry and did not follow a reparse point or a swapped name.

## What LCA-01I already measured

These results are on this machine. They are recorded in LCA-ARCH-14.

| Question | Model A, as implemented | Model B, as measured |
| --- | --- | --- |
| Wrong target | The exclusive handle's file id is checked before the write. Share-delete is not granted, so another rename cannot move the name first. | POSIX replace and `std::fs::rename` succeed while `FILE_SHARE_DELETE` is open. An exclusive byte-range lock did not stop that rename. |
| Torn bytes | A kill after the first `WriteFile` and before `SetEndOfFile` left a mixed file. Restoration now writes the sealed preimage back under a new approval. | A completed rename shows the staged file or the old file to a later open. The rename itself was not power-loss tested. |
| Crash | `taskkill /F` results are in LCA-01I and LCA-01J. Power loss was not produced. | Not measured as a killed publisher. `REPLACEFILE_WRITE_THROUGH` is documented as unsupported. |
| NTFS name swap | Not used. | POSIX replace keeps the old handle's id and bytes and gives the name the staged id. `ReplaceFileW` gives the name the replacement's id. |
| Reparse points | Rejected on the relative open. | A replace that opens the name again can be pointed at a different object if the pin was released. |
| Hard links | `link_count != 1` is refused. The check is not a history of names that were unlinked earlier. | A name swap does not by itself collapse every existing hard link. |
| Open handles | The exclusive handle blocks a sharing writer. A publisher that needs share-delete gives that up. | `ReplaceFileW` fails while the exclusive handle is held. Its documented failures can drop or rename the original. |
| Git, rustc, editors | They open the path. The file id stays. A torn file is visible to them until restoration. | A new file id is normal for tools that replace by rename. Some watchers treat that as delete plus create. |
| ACLs and metadata | The same file object keeps them. | A replacement file keeps the replacement's id and can keep different metadata unless the publisher copies them. That copy was not implemented or measured. |
| User expectation | A crash can leave a mixed file. `inspect` says so. Restoration is an explicit second decision. | Users of editors often expect the name to show either the old or the new document. |
| Implementation | The publisher exists and the kill tests exist. | The safe version does not exist. The unsafe version was rejected because it loses the checked object. |

## Decision

The implemented strategy remains Model A.

Model B is the better long-term shape if, and only if, a later milestone measures a publication where:

1. the name that readers open is still the checked object at the moment of the swap
2. a concurrent rename cannot win
3. a crash leaves either the old bytes or the new bytes, not a third file
4. reparse points and hard links are still refused
5. the result is demonstrated with `taskkill /F`, not only with a successful call

None of those five were demonstrated for a rename or for `ReplaceFileW` while the exclusive handle stayed held. Theoretical atomic visibility does not justify switching. LCA-01J therefore adds restoration for the torn in-place write. It does not add a second publisher.

## Still required before a switch

- A design that pins the directory entry without `FILE_SHARE_DELETE`, or a measured proof that some other pin closes the hole the byte-range lock left open.
- Kill tests around the swap, including a kill between the documented intermediate names of `ReplaceFileW`.
- A rule for ACLs, timestamps, and alternate data streams. They were not part of the Model B measurement.
- An explicit product decision that tools may observe a new file id.
