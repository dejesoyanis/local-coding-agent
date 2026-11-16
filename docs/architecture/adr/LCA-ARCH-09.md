# LCA-ARCH-09: Human approval and verified apply boundary

- Status: Accepted
- Decision: A later interactive console confirms one stored proposal; the agent never approves
- Milestone: LCA-01G

## Context

LCA-01D can apply a patch only in the process that prepared it, and only after that process reads the exact confirmation line. `lca agent execute` deliberately does not offer that line, because the binding dies with the process and a model reply must not become a grant.

The operator needs to inspect the change in a second invocation and approve it there. Argument flags, model text, tool calls, and JSON documents are not a person at the console.

## Decision

Commands:

```text
lca agent execute "<task>"
lca patch list
lca patch show <proposal-id>
lca patch approve <proposal-id>
lca patch reject <proposal-id>
lca patch status <proposal-id>
```

`lca agent execute` prepares a patch, stores the proposal, prints `proposal_id` and `proposal_state: prepared`, and stops. It prints `approval: unavailable` and `applied: false`. It does not print a confirmation line and does not contain `approve `. It does not call `approve`. The workspace source file is unchanged.

`lca patch approve` does not call the model. It is deterministic:

1. Load the proposal from the protected store and check the digest, the filename, and the live workspace identity.
2. Print the path, both hashes, the file id, the full digest, the current target status, and the diff.
3. Require `stdin` to be a terminal. A pipe, including `Command` output capture, is refused before apply.
4. Read one line. The only accepted line is `approve {proposal-id} {first 16 hex chars of the digest that was just printed}`.
5. Reload the record. If the digest changed since the print, refuse.
6. Move `Prepared` or `Approved` to `Applying`, then call the existing `apply_granted` with a fresh in-memory grant for those same bytes.
7. Re-check the workspace, the target file id, the link count, the reparse bit, the original hash, and the proposal digest inside that apply.
8. Record `Applied`, or `Conflict` / `Failed`. Do not try again.

There is no `--yes`, `--force`, or `--auto-approve`. The words `approve` in model text, a tool call, or a model JSON document do not grant. `lca tools patch prepare` keeps the older same-process confirmation. That path is not the cross-process grant.

One approval authorizes one proposal, one workspace, one relative path, one original content, one proposed content, and one apply attempt. It does not authorize another file, another tool, or a shell.

`lca agent run` still prints the process-local confirmation line and does not apply. It also stores a proposal when prepare succeeds, so the operator can use `lca patch` afterwards. The process-local line does not survive the process and is not accepted by `lca patch approve`.

## Consequences

- The displayed diff and the confirmed digest are the same value the apply path reloads. A change to the proposal file between the print and the line is `approval_mismatch`.
- A change to the target file is `conflict` or `identity_changed`. The proposed bytes are not written.
- A second approve of an applied proposal is `approval_consumed`.
- If no interactive console is attached, apply does not run.
