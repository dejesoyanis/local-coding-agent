# LCA-01G: Verified patch approval and execution boundary

LCA-01G lets an agent prepare a change that a person reviews in a later CLI process. The agent cannot approve its own change. The grant covers one proposal, one workspace, one path, one original content, one proposed content, and one apply attempt.

Decisions: [LCA-ARCH-08](adr/LCA-ARCH-08.md), [LCA-ARCH-09](adr/LCA-ARCH-09.md), [LCA-ARCH-10](adr/LCA-ARCH-10.md).

## What LCA-01D actually guaranteed

Before this milestone the patch engine was in-memory:

- `PreparedPatch` held the replayed bytes and the diff.
- `ApprovalLedger` was process-local. A grant could not be reused, and it died with the process.
- The confirmation line had to match `approve {action_id} {binding prefix}` exactly. Model text did not match.
- Apply re-resolved the path, re-hashed the file, replayed the hunks, wrote a temp file with create-new and nofollow, renamed it, and hashed the read-back.
- A verify failure after the rename did not restore the old bytes.
- Windows identity was creation time, last write, and length. Stable Rust did not expose the NTFS file index.
- The component walk rejected reparse points, then the final open used `FILE_FLAG_OPEN_REPARSE_POINT`. An intermediate junction could still be followed by the operating system between the check and the open.
- Hardlinks were not a separate patch class. A read of a hardlink alias of a protected file was allowed.

This milestone does not mark those read races as solved.

## Threat model

| Boundary | What it stops | What it does not stop |
| --- | --- | --- |
| Model tool surface | Reading the proposal store through the workspace sandbox; approving via text, JSON, or a tool call | A process that already runs as the user |
| DPAPI + owner ACL | Other users reading or editing proposal ciphertext | The same user, who can unprotect and reprotect |
| Proposal digest | Applying a body other than the one just shown | Forgery by that same user |
| Workspace file id + path | Applying a proposal in a copy, a moved tree, or another workspace | Two directories that are the same object and the same path |
| NTFS file id + link count | Writing through a junction, a symlink, or a hardlink target | Reading a protected file through a second hardlink name |
| Interactive console | `--yes`, a pipe, and a captured stdin | A person who types the line without reading the diff |

No shell is added. No network grant is added. Eval never calls `approve`.

## Proposal contract

Contract version 1. The body is length-prefixed and labeled `LCA-01G-PROPOSAL-V1`. The on-disk file is that body, then the state byte, then the 32-byte digest. The digest excludes the state. Proposed bytes are stored in full. Replay must reproduce them. The unified diff is display only.

TTL is 24 hours from creation. Expiry of `Prepared` or `Approved` becomes `Expired` and is audited.

## Approval workflow

`lca agent execute` persists the proposal and stops. `lca patch show` prints the path, hashes, file id, digest, target status, diff, and the confirmation line. `lca patch approve` repeats that view on a terminal, reads one line, reloads the digest, and only then calls `apply_granted`.

The line is `approve {uuid} {first 16 hex chars of the full digest}`. The library also requires the full digest the command just printed. A model document cannot supply either value to this command, because this command does not call a model.

## Windows identity

Prepare records `FileIdInfo` for the workspace root and for the target. Apply opens the root and walks with `NtCreateFile` relative to the parent, refusing reparse points and `link_count != 1`. The temp file is created in that parent. The target handle is closed, the name is replaced, and the written handle is read back.

After the handle is closed and before the rename, another writer can still change the directory entry. That window is open. A mismatch on the read-back is `verify_failed`, the proposal becomes `Conflict`, and the old bytes stay replaced. There is no rollback.

## Crash recovery

No path writes the workspace file merely because a previous process died.

| Crash | Next `status`, `show`, or `approve` |
| --- | --- |
| Before approval | Stays `Prepared`. Nothing was written. |
| After `Approved`, before `Applying` | Stays `Approved`. A new interactive line is required. Nothing is written by itself. |
| During `Applying`, target already has the proposed hash | Becomes `Applied`. No second write. |
| During `Applying`, target still has the original hash and the same file id | Becomes `Failed`. No second write. |
| During `Applying`, bytes or file id differ | Becomes `Conflict`. No write. |
| After the rename, before the audit line | The same reconciliation. The audit line is written when the state is resolved. |

`Failed`, `Conflict`, `Applied`, `Rejected`, and `Expired` do not apply again.

## Audit

`%LOCALAPPDATA%\lca\audit\{workspace key}\events.log` is JSON lines with a monotonic `seq`. Events: `created`, `shown`, `approved`, `rejected`, `apply_started`, `apply_succeeded`, `apply_failed`, `conflict`, `expired`. Fields are the sequence, event, proposal id, digest, state, relative path, and time. File contents are not logged.

## Tests

Automated on this Windows machine, without Ollama:

- Proposal round-trip, model text rejected, tampered ciphertext rejected, workspace copy rejected, changed target conflicts, single-use approval, `Applying` with the proposed bytes reconciles to `Applied` without a second write.
- Platform file ids are stable and distinct. Hardlinks share an id and have `link_count > 1`. Junctions are reparse points and the relative open refuses them. DPAPI flips fail. The owner ACL can be set and rechecked. Replace swaps bytes and changes the file id.
- `prepare` on a hardlink target returns `hardlink_denied` and leaves both names unchanged.
- Existing filesystem tests, including CRLF, junctions, and the in-process grant, still pass through the Windows apply path.
- `lca agent execute` still prepares without printing `approve ` and without changing the source file. The proposal is stored.
- `lca patch approve --yes`, `--force`, and `--auto-approve` are rejected. A piped `lca patch approve` is rejected before apply.
- Offline `lca eval agent` covers the eight run classes and records `patches_applied: 0`.
- A pseudoconsole child sees `IsTerminal` on stdin and stdout.

Live, cross-process, on a temporary workspace, not on the project tree:

1. Prepare and store a proposal.
2. `lca patch show` in a second process prints the diff and `matches_original`.
3. `lca patch approve` on a pseudoconsole, with the shown line, writes `beta`.
4. A second approve is refused and the file stays `beta`.
5. A flipped proposal ciphertext is refused.
6. A proposal whose target was edited after prepare is refused and the edited bytes stay.

Not demonstrated:

- A fault injection that makes the post-rename hash mismatch on purpose. The code returns `verify_failed` and does not restore; no test forces that branch.
- Linux and macOS. Those builds fail closed by construction and were not executed here.
- A live model evaluation. `lca eval agent --live` stays fail-closed even when `LCA_EVAL_LIVE=1`.

## Known limits

- Same-user DPAPI forgery.
- The close-then-rename window on the directory entry.
- No rollback after a bad read-back.
- Hardlink reads of protected bytes under another name.
- Read paths still use the LCA-01D check-then-open walk.
- `lca agent run` still prints the process-local confirmation line. That line cannot approve the stored proposal.
