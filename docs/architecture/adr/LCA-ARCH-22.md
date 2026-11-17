# LCA-ARCH-22: Publication evidence standard

- Status: Accepted
- Decision: Publication experiments run only from the Windows unit-test module `publication_probe`. A result may claim what that run recorded. Silence is not atomicity. A privilege failure is skipped. Stress is not a proof. Power loss is a separate claim and was not produced.
- Milestone: LCA-01K

## Where the harness lives

`crates/lca-platform/src/publication_probe.rs` is compiled with `cfg(all(test, windows))`. The agent binary links the library without `cfg(test)`, so it cannot call the module. `apply_ntfs` does not reference it. Strategies B, C, D, and E are not functions on `OpenedTarget`.

Each case uses a new directory under the process temp directory and removes it when the test value drops. The repository tree is not the workspace. No test asks for an elevated token.

## What a line records

The lines under `target/lca-01k/` are local evidence, not product logs. They carry the strategy, the Windows version, the filesystem name, the API, the flags, the share mask, the return code, a file-id hex, a SHA-256, a content class, and `power_loss=unproven`. They do not carry file bytes. Classes used here are `original`, `proposed`, `decoy`, `torn`, `mixed`, `missing`, and `other`.

## What a result may say

| Observation | Allowed claim |
| --- | --- |
| Hook samples of strategy A were a new prefix and an old tail | Torn visibility was observed for that publisher, on that size |
| A 4 KiB equal-length write was already the full new file at `DuringPublish` | No mixed sample. Not a proof that the write is atomic |
| Strategy D: the old handle read the old pattern and a new open read the new pattern, spinner mixed count 0 | Handle split was observed. Not a proof that every reader is limited to those two images, and not a power-loss result |
| `taskkill /F` after the child had reached the ready file | Process-kill evidence for that point. Not a power-loss result |
| Mid-syscall kill of `MoveFileExW`, `ReplaceFileW`, or `FileRenameInfoEx` | Not instrumentable in this harness |
| Eight renames | A bounded stress count. The line says `formal_proof=false` |
| `CreateSymbolicLinkW` returned `1314` | Skipped. Not a pass of symlink refusal |
| `ReplaceFileW` with flags `1` returned success | The flag was accepted by the call. Durability was not measured |

A test that cannot create the object it meant to attack does not count as a pass of the control. Junction creation succeeded in this run, so the junction refusal is a real open failure. The file symlink did not.

## Crash procedure

The parent starts this test binary again with `--exact publication_probe::publication_probe_child` and `LCA_01K_KILL`. The child writes a one-shot token and an evidence file, signals readiness, and parks. The parent checks that the child is still running, then runs `taskkill /F`. It reads the target, reads it again, and does not write. Recovery in the production store is not invoked by this harness. The two reads must match.

## Separation from the product contract

The production evidence file remains `LCA-01I-EVIDENCE-V1` with strategy byte `1` (`pinned_in_place`). Restoration remains `LCA-01J-RESTORATION-V1` and still calls `apply_ntfs`. The harness token is not that approval and cannot satisfy it.
