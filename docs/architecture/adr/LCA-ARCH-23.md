# LCA-ARCH-23: Workspace trust boundaries

- Status: Accepted
- Decision: Seven trust boundaries and three threat models are the security model for the next milestones. The model has no authority. A Rust check is not an operating-system boundary. Same-user processes are inside TM-C and are not stopped by the current process.
- Milestone: LCA-01L

## Boundaries

| Id | Area | What it may do | What this repository actually enforces |
| --- | --- | --- | --- |
| TB-01 | Human / host | Highest authority over the workspace, approvals, and the operating system | The confirmation line is read by the CLI. The host user is not sandboxed from the agent. |
| TB-02 | Agent controller | Call the model, validate actions, enforce budgets | `SingleTurnAgentController` and `BoundedAgentController` do not call `commit_prepared`. Budgets come from configuration. |
| TB-03 | Tool executor | Run an allowed capability | `execute_validated` runs read tools and prepares a patch. `RejectingToolExecutor` still refuses the LCA-01A request type. There is no shell tool. |
| TB-04 | Model runtime | Return text and tool-call proposals | `lca-ollama` speaks HTTP to loopback. It does not receive file handles, approval grants, or configuration mutation. |
| TB-05 | Workspace filesystem | Data, not instructions | Paths are resolved from the canonical root. Privacy rules apply. File bytes are not treated as authority. |
| TB-06 | Proposal and evidence store | Persist review state and recovery records | DPAPI and an owner ACL. Both were measured again: this user can unprotect and overwrite them. |
| TB-07 | External processes | Editors, git, compilers, and other processes of this user | Not a trusted peer. Publication still uses the exclusive handle from LCA-01H. |

## Authority the model does not have

The model cannot approve a write, approve a restoration, change security policy, widen the workspace, raise an operating-system privilege, hold a filesystem handle, rewrite recovery evidence, or start a tool executor outside the controller. Tool arguments are schema-checked. `mutation_mode` is not a field of `apply_patch`. A missing configuration mode is `read_only` ([LCA-ARCH-25](LCA-ARCH-25.md)).

Prompt text that says the model cannot approve is an instruction to the model. It is not the enforcement. The enforcement is the absence of an approval API on the model path and the grant check in `apply_granted_controlled`.

## Threat models

**TM-A, untrusted model.** Invalid calls, harmful proposals, repository-influenced output, prompt injection, protected paths, and constructed paths are in scope. The model has no operating-system rights of its own. Guarantees that exist today: schema and policy rejection, workspace and privacy checks, no shell, no write without a human grant, and the mutation mode from configuration. Accepted risk: the model can still ask for a dangerous patch, and a person can approve it. Attacks that need the model's host privileges are out of scope because the model has none.

**TM-B, concurrent trusted development tools.** Editors, git, and compilers may write, rename, and hold files. They are not treated as malicious. Races remain in scope. The exclusive handle without `FILE_SHARE_DELETE` denied the measured rename (`32`) and parent rename (`5`) in LCA-01K and again in this milestone. A torn in-place write remains possible. That risk stays accepted. Hard links created in the window after the link-count check are not prevented by "the other process is a compiler."

**TM-C, malicious same-user process.** In scope: changing workspace files, creating hard links, swapping directory entries, opening handles, starting processes, and reading or rewriting proposal and evidence data. DPAPI for the current user is not a boundary against that user. This run unprotects a sealed blob from a second process and overwrites the evidence file. A separate process with the same token does not move an attack out of TM-C. Stopping TM-C needs a different security principal or a VM ([LCA-ARCH-24](LCA-ARCH-24.md)). Until that exists, command execution stays disabled, and workspace mutation stays on the human-approved path with the known publication limits.

## What is not claimed

- That the host user is confined by the agent.
- That a debugger on this process is in scope. It is not.
- That Rust privacy checks stop a process that already has the user's rights.
- That an unclear or torn file is prevented. Recovery classifies it. Restoration is a second human decision.
