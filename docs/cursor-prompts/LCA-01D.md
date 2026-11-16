# LCA-01D prompt

The milestone was implemented from the brief below. The resulting contracts are recorded in [LCA-01D](../architecture/LCA-01D.md) and [LCA-ARCH-04](../architecture/adr/LCA-ARCH-04.md).

# LCA-01D: Secure Filesystem Tools & Workspace Sandbox

**Milestone:** LCA-01D
**Architecture decision:** LCA-ARCH-04, variant C, capability-based workspace sandbox
**Repository:** `C:\Users\mifur\dev\cursor\local-coding-agent`
**Branch:** `lca-development`
**Commit title:** `LCA-01D: Secure Filesystem Tools`

Inspect LCA-01A, LCA-01B, and LCA-01C first. Keep their contracts. Do not rebuild a working boundary.

Known LCA-01C live probes: native tool calling passed, structured JSON passed, auto selected native, and `diagnostic_echo` was validated and not executed.

## Tools

Implement `list_directory`, `read_file`, `search_files`, and `apply_patch`.

The first three may run inside the workspace after validation. `apply_patch` prepares a change, validates it, and shows a diff. The write happens only after an explicit, action-bound user confirmation. The model cannot mint that confirmation.

No shell. No autonomous agent loop. No unsupervised write. `lca ask` must not start executing tools.

## Sandbox

One immutable canonical workspace root per sandbox value. Model paths are untrusted. Allow relative workspace paths only. Reject absolute paths, `..`, drive prefixes, UNC paths, device paths, alternate data streams, NUL, paths outside the workspace, unexpected reparse points, and symlink or junction traversal. Check components. A `starts_with` on an uncanonicalized string is not enough.

Fail closed when a path cannot be verified. Do not claim that a check-then-open race is prevented when the code only checks paths before opening them. Prefer handle-based opens. This workspace forbids `unsafe`.

## Read tools

`list_directory` is non-recursive, capped, and sorted. Hidden names may appear. A bad entry is not reported as a safe file. Symlinks are not followed.

`read_file` reads UTF-8 text, at most 1 MiB by default, and returns at most 256 KiB. A partial response is marked truncated. No binary files, no encoding conversion, no directories.

`search_files` is literal search. No regular expressions. Deterministic order, relative paths, line numbers. Default caps: 100 matches, 1000 files, 1 MiB per file, 32 MiB total. Skip `target`, `.git`, and `node_modules`. Do not follow symlinks or junctions.

## Patch and approval

Prepare validates the patch, checks paths, reads the current bytes, hashes them, applies the patch in memory, validates the result, and builds a unified diff and an approval request. Prepare must not change a file.

The confirmation is bound to the action id, workspace identity, target path, original hash, exact patch, and expected new hash. A blanket approval is not allowed. A used grant is not reused. Model text is not approval.

Apply checks the grant, resolves the path again, compares hashes, and aborts on conflict. One existing text file only. No create, delete, rename, or multi-file patch. No silent newline or encoding change. No writes under `.git`. Use a temporary file in the target directory and an atomic replace, and document the Windows limits. If a safe apply cannot be guaranteed, return a typed error.

Read tools need no interactive approval inside policy. Writes always do. `require_write_approval` cannot be set to false. Missing `[tools]` uses conservative defaults. Invalid limits are configuration errors. The workspace root cannot be changed by model output. Existing `lca.toml` files stay compatible.

The CLI is:

```text
lca tools list
lca tools read Cargo.toml
lca tools search ModelRuntime --path crates
lca tools patch prepare <patch-file>
```

`prepare` prints the target, the diff, the action id, and the approval state, then asks for confirmation in the same process. Do not add a model-controlled approve flag. Keep the existing probe commands on the diagnostic registry.

## Tests and gates

Use temporary directories. Do not modify the user's real files from tests. Cover path validation, limits, patch conflicts, approval binding, and Windows junctions. If symlink creation is not permitted, record that instead of skipping the assertion that an existing symlink must not be followed.

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Do not push. If a guarantee cannot be enforced, stop that function, document it, and mark the acceptance criterion failed. Do not describe the sandbox as a complete security boundary.
