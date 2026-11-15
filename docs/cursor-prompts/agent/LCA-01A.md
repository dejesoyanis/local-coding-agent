Implement LCA-01A: Rust Agent Foundation.

PROJECT
Root: C:\Users\mifur\dev\cursor\local-coding-agent
Existing test project: C:\Users\mifur\dev\cursor\local-coding-agent\lca-test
Platform: Windows, PowerShell 5.1
Language: Rust stable, edition 2024.

OBJECTIVE
Create a production-oriented foundation for a fully local coding agent. This milestone must not implement autonomous file editing, shell execution, or an agent loop.

WORKSPACE
Create a Cargo workspace containing:
- apps/lca-cli
- crates/lca-core
- crates/lca-config
- crates/lca-ollama
- crates/lca-tools

Keep lca-test as a separate benchmark project, excluded from the workspace. Preserve all existing files, including opencode.json, Modelfiles, backups, and test files. Never create Git worktrees or move the project.

ARCHITECTURE
lca-core:
- Agent lifecycle types: Idle, Initializing, Ready, Running, WaitingForTool, Completed, Failed, Halted.
- Typed AgentError and AgentResult.
- AgentTask with UUID, prompt, timestamps, and status.
- No Ollama, filesystem, or CLI dependencies in the core domain.
- Explicit, tested lifecycle transitions. Invalid transitions must return errors.

lca-config:
- Typed configuration with serde.
- Workspace root path.
- Ollama endpoint, model name, context window, generation limit.
- Max agent steps and timeout settings.
- Default endpoint: http://127.0.0.1:11434
- Default model: lca-30b-agent
- No secrets in logs.
- Validate workspace root existence and canonicalize it.
- Reject a nonexistent or invalid workspace root.
- Load from a TOML configuration file with documented defaults.

lca-ollama:
- Define an OllamaClient abstraction and request/response DTOs.
- Provide a minimal HTTP health/model-availability check using Ollama's local API.
- Use timeouts and structured error handling.
- No tool calling or agent loop yet.
- Unit tests must not require Ollama to be running.

lca-tools:
- Define ToolName, ToolRequest, ToolResult, ToolError.
- Define a ToolExecutor trait.
- No filesystem modification or process execution in this milestone.
- Explicitly model workspace-scoped tool authorization.

lca-cli:
- Commands: lca status, lca config validate, lca workspace info.
- Display model, endpoint, workspace root and readiness.
- Status should report Ollama unavailable without panicking.
- No interactive agent yet.

ENGINEERING RULES
- Rust 2024, stable.
- No unwrap/expect in production paths where errors are recoverable.
- No unsafe Rust.
- Use thiserror for typed errors and tracing for diagnostics.
- Avoid unnecessary dependencies.
- Do not modify lca-test.
- Do not modify opencode.json.
- Do not create worktrees.
- Do not use && in PowerShell 5.1 commands.
- Prefer direct cargo commands with --manifest-path when appropriate.
- Do not claim a check passed unless it was actually executed.

TESTING
Run:
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

If a command fails, fix the issue and rerun it.

DOCUMENTATION
Create docs/architecture/LCA-01A.md containing:
- Architecture and dependency direction
- Crate responsibilities
- Configuration example
- CLI usage
- Lifecycle transitions
- Security boundaries
- Explicitly deferred capabilities

Create docs/cursor-prompts/agent/LCA-01A.md containing this complete prompt.

REPORT
Provide:
- Files created/changed
- Architectural decisions
- Tests executed with actual results
- Known limitations
- Acceptance criteria PASS/FAIL
- Git commit hash

ACCEPTANCE CRITERIA
1. Workspace builds.
2. All unit tests pass.
3. Clippy passes with -D warnings.
4. CLI status works even if Ollama is offline.
5. Invalid workspace roots are rejected.
6. Invalid lifecycle transitions are rejected.
7. Existing benchmark project is unchanged.
8. No autonomous tool execution exists yet.

COMMIT
After successful implementation and verification, create one Git commit:
LCA-01A: Rust Agent Foundation

Do not commit unrelated existing changes. If Git is unavailable or the repository is not initialized, report that instead of initializing or changing repository structure without approval.
