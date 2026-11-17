# LCA-ARCH-25: Filesystem mutation policy

- Status: Accepted
- Decision: Three mutation modes are loaded from trusted configuration and enforced before a prepare or a write. A missing `tools.mutation_mode` is `read_only`. An unknown name is a configuration error and the file is not loaded. `write_enabled` does not raise the mode. The model cannot set it. The NTFS publisher is unchanged.
- Milestone: LCA-01L

## Modes

| Mode | Reads | Prepare and review | Apply and restoration |
| --- | --- | --- | --- |
| `read_only` | Yes, when reads are enabled | No | No |
| `prepare_only` | Yes, when reads are enabled | Yes, when `write_enabled` is set | No |
| `human_approved` | Yes, when reads are enabled | Yes, when `write_enabled` is set | Only after the existing human confirmation for that action or restoration |

Privacy rules and the workspace root apply in every mode. There is no automatic mutation and no mode that skips approval.

## Where it is enforced

`lca-config` parses the string. The CLI copies it onto `FsLimits`. `allows_prepare` gates `prepare_patch` and whether `apply_patch` is advertised. `allows_human_mutation` gates proposal approval and restoration approval. A prepared patch records the mode. `apply_granted_controlled` and `apply_image_controlled` refuse a patch that is not `human_approved` before they call `apply_ntfs`. A proposal reloaded from disk starts as `read_only` until the approval path, after the limits check, marks it authorized.

`FsLimits::try_new` still defaults an in-memory limit set to `human_approved` when writes are enabled, so existing tests keep the publisher they already call. That default is not the configuration default. Configuration that omits the key is `read_only`, including when `write_enabled` remains true.

`read_only()` forces `read_only` even if the caller then asks for `human_approved` while writes are disabled. `lca eval tools` still uses `read_only()`.

This is an enforcement layer on the existing calls. It is not a new publisher and not a same-user boundary.

## Command execution

No shell is added. A later command runner is out of scope until [LCA-ARCH-24](LCA-ARCH-24.md) is satisfied. The requirements, none of which are implemented here:

- An explicit allowlist of executables, not a shell string.
- Fixed arguments, a workspace working directory, and a scrubbed environment.
- Process creation under a job, with a timeout, output caps, and no inherited handles except the ones the broker meant to pass.
- stdout and stderr treated as untrusted data.
- No shell metacharacters and no `cmd.exe` wrapping.
- The child tree killed with the job.
- Network and secret-bearing environment variables denied by default.
- `cargo test`, `build.rs`, procedural macros, compiler plugins, and dependency scripts are not made safe by naming `cargo` in an allowlist. They run arbitrary code as the process that starts them.

An allowlist for `cargo test` is not a sandbox. Command execution stays off while the process still has this user's rights.
