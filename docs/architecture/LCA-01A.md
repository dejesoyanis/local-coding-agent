# LCA-01A: Rust Agent Foundation

This milestone is the local coding agent's library and command-line foundation. It loads configuration, models the agent lifecycle, checks a local Ollama server, and defines workspace-scoped tool authorization. It does not edit files, start processes, call tools, or run an agent loop.

`lca-test` stays an independent benchmark. The workspace excludes it. `opencode.json` stays at the repository root, where OpenCode reads it. Ollama Modelfiles live under `models/ollama/` and are not read at runtime.

## Workspace layout

```
Cargo.toml
apps/lca-cli
crates/lca-core
crates/lca-config
crates/lca-ollama
crates/lca-tools
docs/architecture/LCA-01A.md
models/ollama/     Ollama Modelfiles, not read by this foundation
lca-test/          excluded benchmark, not a workspace member
```

The workspace uses Cargo resolver 3 and Rust edition 2024. Every crate forbids `unsafe` code.

## Dependency direction

```
lca-cli
  -> lca-core
  -> lca-config
  -> lca-ollama

lca-core        domain only
lca-config      TOML, validation, canonical workspace root
lca-ollama      native Ollama HTTP checks
lca-tools       tool model and authorization
```

`lca-core` does not depend on Ollama, the filesystem, or the CLI. `lca-config`, `lca-ollama`, and `lca-tools` do not depend on each other. `lca-cli` is the composition root and does not depend on `lca-tools`, so the binary cannot execute a tool. A later milestone can add that dependency when an executor is allowed to succeed.

External libraries are limited to `thiserror`, `tracing`, `uuid`, `serde`, `toml`, `url`, `ureq`, `clap`, and `tracing-subscriber`.

## Crate responsibilities

### lca-core

- `AgentStatus`: `idle`, `initializing`, `ready`, `running`, `waiting_for_tool`, `completed`, `failed`, `halted`.
- `AgentLifecycle`: in-place state machine. Invalid edges return `AgentError::InvalidTransition` and leave the current status unchanged.
- `AgentTask`: UUID, trimmed prompt, caller-supplied timestamps, and the same lifecycle rules.
- `AgentResult<T>`: alias of `Result<T, AgentError>`.

Timestamps are passed in by the caller so the domain does not read the clock. Task identity uses UUID v4.

### lca-config

Loads one TOML file, applies defaults, and returns an `AgentConfig` whose workspace root is a canonical directory. Relative `workspace_root` values are resolved against the configuration file's directory, not the process working directory.

Validation rejects:

- a missing, empty, nonexistent, or non-directory workspace root
- endpoint schemes other than `http` and `https`
- endpoints with a username, password, path, query, or fragment
- an empty model name, whitespace inside a model name, or a model name longer than 256 characters
- a context window outside `1..=1_048_576`
- a generation limit outside `1..=context_window`
- `max_steps` outside `1..=10_000`
- `timeout_secs` outside `1..=86400`
- `request_timeout_secs` outside `1..=3600`
- configuration files larger than 64 KiB
- unknown fields

The default generation limit is 2048, so a custom context window below 2048 must set `generation_limit` as well.

Logs record field names and the error classification. They do not record the raw file. Credential rejection uses a static message and does not echo the URL.

### lca-ollama

`OllamaClient` exposes `check_model`. `HttpOllamaClient` calls the native endpoints `GET /api/version` and `GET /api/tags`. It does not call `/api/chat` and it does not send tool definitions.

A model is present when a tag equals the requested name or equals `name:tag` with that name as the base. `lca-30b-agent` therefore matches `lca-30b-agent:latest`.

The client applies the configured timeout to connect, read, and write, disables redirects, and stops reading a response after 1 MiB. Offline servers, HTTP errors, invalid JSON, and oversized bodies become `OllamaAvailability::Unavailable`. The status text does not include response bodies. Unit tests use an in-process TCP stub or no network. They do not start Ollama.

### lca-tools

`ToolName`, `ToolRequest`, `ToolResult`, and `ToolError` describe future tools. `WorkspaceScope` canonicalizes the workspace and judges each request:

- path tools must stay inside the workspace after lexical normalization and after canonicalizing the nearest existing ancestor, so `..` escapes and directory junctions that leave the workspace are denied
- `write_file`, `edit_file`, and `execute_command` are denied even when the path is inside the workspace
- read-shaped requests that stay inside the workspace are marked in-workspace

`RejectingToolExecutor` implements `ToolExecutor`. In-workspace reads return `ToolError::NotImplemented`. Denied requests return `ToolError::Unauthorized`. The executor never returns `Ok`, never reads file contents, and never starts a process. Command text is not copied into the error.

### lca-cli

| Command | Behavior |
| --- | --- |
| `lca status` | Prints the idle lifecycle, config, model, endpoint, workspace, and Ollama readiness. Exit 0 only when the config is valid and the model is advertised. |
| `lca config validate` | Validates the file. It does not contact Ollama. |
| `lca workspace info` | Prints the canonical workspace root. |

`--config PATH` selects the file. When it is omitted, the command reads `lca.toml` from the working directory. A missing Ollama server is `ollama: unavailable` and exit code 1. An invalid configuration is `ollama: not_checked`; status does not contact the network in that case. Neither path panics.

## Configuration example

```toml
workspace_root = "C:/path/to/workspace"

[ollama]
endpoint = "http://127.0.0.1:11434"   # native origin, not the /v1 URL
model = "lca-30b-agent"
context_window = 8192
generation_limit = 2048
request_timeout_secs = 5

[limits]
max_steps = 32
timeout_secs = 300
```

Defaults when a field is omitted:

| Field | Default |
| --- | --- |
| `ollama.endpoint` | `http://127.0.0.1:11434` |
| `ollama.model` | `lca-30b-agent` |
| `ollama.context_window` | `8192` |
| `ollama.generation_limit` | `2048` |
| `ollama.request_timeout_secs` | `5` |
| `limits.max_steps` | `32` |
| `limits.timeout_secs` | `300` |

`workspace_root` has no default. The endpoint above is the Ollama native API. The OpenAI-compatible base used by other local tools ends in `/v1` and is rejected here because `/api/version` and `/api/tags` live on the origin.

`limits.timeout_secs` and `limits.max_steps` are stored for a later loop. This milestone does not enforce them. `lca status` uses `ollama.request_timeout_secs` for the health check.

## CLI usage

```text
lca status --config C:\path\to\lca.toml
lca config validate --config C:\path\to\lca.toml
lca workspace info --config C:\path\to\lca.toml
```

A valid configuration whose Ollama server is down prints a report shaped like this and exits 1:

```text
agent_status: idle
config: valid
config_file: C:\path\to\lca.toml
model: lca-30b-agent
endpoint: http://127.0.0.1:11434
workspace_root: C:\path\to\workspace
context_window: 8192
generation_limit: 2048
max_steps: 32
timeout_secs: 300
request_timeout_secs: 5
ollama: unavailable
ollama_detail: request to http://127.0.0.1:11434/api/version failed: ...
readiness: not_ready
```

`ollama` is `ready`, `model_missing`, or `unavailable` after a real probe. `readiness` is `ready` only when the config loaded and the model is advertised.

## Lifecycle transitions

| From | Allowed next statuses |
| --- | --- |
| `idle` | `initializing` |
| `initializing` | `ready`, `failed`, `halted` |
| `ready` | `running`, `halted` |
| `running` | `waiting_for_tool`, `completed`, `failed`, `halted` |
| `waiting_for_tool` | `running`, `failed`, `halted` |
| `completed` | none |
| `failed` | none |
| `halted` | none |

Any other pair, including a transition to the current status, returns `AgentError::InvalidTransition`. `completed`, `failed`, and `halted` are terminal. A task also rejects a timestamp earlier than its last accepted update and leaves the task unchanged.

`lca status` constructs a new lifecycle and prints `idle`. It does not move the state.

## Security boundaries

- No `unsafe` code.
- Recoverable failures use `Result`. Library and binary paths do not call `unwrap` or `expect`.
- The workspace root must exist and is stored in canonical form. Tool paths must remain inside that root after `..` removal and after following an existing prefix, including a directory junction.
- Mutating tools and process execution are hard-denied. The only executor returns an error.
- The CLI does not depend on the tool crate and does not interpret model output as a command.
- Ollama endpoints cannot carry a username, password, path, query, or fragment. Redirects are disabled. Response bodies are capped and are not copied into status text.
- A non-loopback endpoint is accepted and a warning is logged. The operator chooses the host. The default is loopback.
- Configuration files are not a secret store. This schema has no secret fields. Tracing records the error kind and the safe summary (workspace root, endpoint, model, numeric limits). It does not record raw TOML. Credential errors use a fixed sentence.
- The agent timeout and step budget are not enforced because there is no loop yet. The HTTP timeout is enforced on the health check.

## Explicitly deferred capabilities

- Autonomous file reading, writing, and editing
- Process or shell execution
- An agent loop, planning, or multi-step runs
- Model generation, chat, streaming, and tool-calling protocols
- An interactive REPL
- Enforcement of `max_steps` and `limits.timeout_secs`
- Secret storage or credential brokers
- Editing `lca-test` or treating it as part of the agent workspace

## Verification

From the workspace root:

```text
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
