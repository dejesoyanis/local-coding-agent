# LCA-01J: Controlled restoration and recovery authorization

Decisions: [LCA-ARCH-17](adr/LCA-ARCH-17.md), [LCA-ARCH-18](adr/LCA-ARCH-18.md), [LCA-ARCH-19](adr/LCA-ARCH-19.md).

## Threat model

The writer we defend against can create, rename, and replace files in the workspace between two of our calls. The same Windows user can decrypt DPAPI and rewrite both the evidence file and its hash. That user is not a boundary. A debugger attached to this process is not a boundary.

The new failure we handle is a torn in-place publication. Restoration is a second, separately authorized write. It can itself tear. Power loss was not produced.

## Trust boundaries before this milestone

| Material | Where it lives | What was already true |
| --- | --- | --- |
| Sealed original bytes | `{proposal-id}.lcae` | DPAPI, owner-only ACL, bound to the proposal id, digest, file id, and original hash. Not a same-user seal. |
| Current target bytes | The workspace file | Read from the checked handle. A torn file matches neither hash. |
| Proposed patch bytes | `{proposal-id}.lcap` | Bound into the proposal digest. |
| Persisted metadata | The proposal record | State, path, file id, expiry. The digest does not include the state byte. |
| Human approval | The `approve` line | Bound to the proposal digest. Single use. Not accepted from a model, a flag, or a pipe. |
| Filesystem identity | NTFS file id on the exclusive handle | Preserved by the in-place write. Not preserved by the rejected rename and `ReplaceFileW` measurements. |

LCA-01I stops at recognition. `recover` does not write. This milestone adds the write, under a new contract.

## Restoration contract

Label `LCA-01J-RESTORATION-V1`, version 1. The id is new. The confirmation line is `restore {id} {digest-prefix}`. The proposal line is rejected. The restored bytes and the current bytes are inside the DPAPI record and inside the digest.

Prepare accepts `Unclear` and `Failed` only when evidence checks pass and the live hash is neither the original nor the proposed hash. `Applied` is not treated as damaged. `Conflict` is not a source. A missing, undecryptable, or mis-bound `.lcae` fails closed.

Commands:

```text
lca patch inspect <proposal-id>
lca patch restoration prepare <proposal-id>
lca patch restoration show <restoration-id>
lca patch restoration approve <restoration-id>
lca patch restoration reject <restoration-id>
lca patch restoration status <restoration-id>
lca patch restoration recover <restoration-id>
```

`approve` reads one line from an interactive console. `dispatch` does not approve. There is no automatic yes.

## Verified restoration

The write calls `apply_ntfs`, the same exclusive-handle publisher as a normal patch. Checks before `Restoring` is stored, and again on the handle: evidence, workspace, file id, current hash, privacy, reparse, link count, TTL, state, and the new confirmation line. `.lcae` is not rewritten. The attempt record is `{id}.lrae` and is synced before the target write.

Recovery does not write. The restored hash on the same file id becomes `Restored`. The hash captured at prepare becomes `Failed`. Anything else stays `Unclear`. The spent line is not reused. Publication evidence is never deleted.

## Crash tests

`killed_restoration_is_not_retried` uses `taskkill /F` on a child that was still running. The library does not read `LCA_RESTORE_KILL_SPEC`. The `lca` binary does not construct `KillHold`.

The torn file is the LCA-01I shape, `beta\n\n` for `alpha\n` replaced by `beta\n`, except the `during_publish` row. That row appends `TAIL` so the target is longer than the sealed original. A same-length `WriteFile` finishes before the `DuringPublish` hook; the longer file still has a tail when the hook runs.

| Hold | Bytes after the kill | State after `recover` |
| --- | --- | --- |
| `after_validation` | unchanged torn bytes | `prepared` |
| `after_approval` | unchanged torn bytes | `approved` |
| `after_intent` | unchanged torn bytes | `failed` |
| `during_publish` | neither the bound bytes nor `alpha\n` | `unclear` |
| `before_flush`, `after_rename`, `before_readback`, `after_verification`, `before_audit` | `alpha\n` | `restored` |

Every row kept the file id, kept `.lcae` byte-for-byte, and did not add another `restoration_started` during recovery. Rows whose approval had been stored rejected a second approve. These rows are process-kill evidence. They are not a power-loss proof.

`before_flush` is after `SetEndOfFile` and before `FlushFileBuffers`. On this kill, the bytes were already `alpha\n`. That does not show what a disk cache would contain after power loss.

## Publication strategy

Model A, identity first, stays. Model B, atomic publication, is not implemented. The measurements in LCA-ARCH-14 still show that a name swap needs share-delete and then changes the file id. LCA-ARCH-19 records that a switch waits for a new measurement, not for a theoretical advantage.

## Acceptance

| ID | Result | Evidence |
| --- | --- | --- |
| AC-01 | PASS | `an_unknown_contract_version_is_rejected`. Label `LCA-01J-RESTORATION-V1`. |
| AC-02 | PASS | New UUID. The proposal confirmation line is rejected in `a_torn_file_is_restored_once_and_the_old_approval_is_rejected`. |
| AC-03 | PASS for the mechanism | The line starts with `restore`. The binary refuses a non-interactive stdin and rejects `--yes`, `--force`, and `--auto-approve`. A human did not type the line in the live run. |
| AC-04 | PASS | A second `approve_restoration` returns `approval_consumed`. `Approved` is not accepted on a later call. |
| AC-05 | PASS | Missing, garbage, and swapped `.lcae` files are rejected. A clean copy of the original evidence prepares. |
| AC-06 | PASS | Another workspace cannot show the restoration. A recreated file with the same bytes and a new file id is refused. |
| AC-07 | PASS | The successful restore read back `alpha\n` on the captured file id. The attempt phase is `verified`. |
| AC-08 | PASS | `recover_restoration` left the partial bytes in place. A second approve failed. |
| AC-09 | PASS | `taskkill /F` in `killed_restoration_is_not_retried`. The child was alive when it was killed. |
| AC-10 | PASS | A flipped plaintext byte, reprotected, fails the digest check. |
| AC-11 | PASS | A sandbox that excludes `notes.txt` cannot prepare. The file bytes stayed torn. |
| AC-12 | PASS for hardlink and junction | Hardlink approve returns `hardlink_denied`. A junction at the target path is refused and the outside sentinel stays. File-symlink creation in that test is accepted only as a refused symlink or as OS error 1314 or 5. |
| AC-13 | PASS | The audit log contains the restoration events and does not contain `alpha` or `beta`. |
| AC-14 | PASS | `.lcae` bytes are unchanged after restore and after the kill. No delete path exists. |
| AC-15 | PASS | The comparison in LCA-ARCH-19. |
| AC-16 | PASS | `docs/architecture/adr/LCA-ARCH-19.md`. |
| AC-17 | PARTIAL | `live_restoration_stops_before_human_approval`. Inspect, prepare, and show ran. Approve stopped because stdin was not a terminal. The torn bytes stayed. |
| AC-18 | PASS | `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, and `cargo clippy --workspace --all-targets -- -D warnings` on the commit that contains this file. The pre-existing `live_ollama_smoke` test stayed ignored and is not counted. |
| AC-19 | PASS | No rename fallback. Failed evidence, identity, privacy, hardlink, and reparse checks do not write. |
| AC-20 | PASS | This file, the three ADRs, and the cursor prompt. |

## Live run

Isolated temp workspace, `LCA_STATE_DIR` pointed at a temp store. `notes.txt` started as `alpha\n`. An in-process `DuringPublish` fault left a torn file and sealed `.lcae`. The `lca` binary then ran `patch inspect`, `patch restoration prepare`, and `patch restoration show`. The shown line started with `restore`. `patch restoration approve` exited because stdin was not a console. The file was still the torn bytes.

## Known limitations

- In-place publication can tear. Restoration can tear too. `Unclear` is not a second write.
- `FlushFileBuffers` and `sync_all` are not a power-loss proof. The parent directory is not flushed.
- DPAPI and the store ACL do not stop this user.
- `link_count == 1` can be true after a protected name was unlinked.
- A same-length restoration write is not split by `DuringPublish`.
- Non-Windows verified apply stays unsupported.
- The live human approval was not entered.
