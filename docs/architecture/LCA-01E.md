# LCA-01E: Controlled single-turn model-to-tool dispatch

This milestone connects the local model runtime to the workspace tool registry and the dispatcher. The architecture decision is [LCA-ARCH-05](adr/LCA-ARCH-05.md) (option C).

One `lca agent run` starts one non-streaming generation. The response may be text, one tool call, a batch, or an error. It is never followed by another generation.

## Module boundaries

| Crate | Responsibility |
| --- | --- |
| `lca-core` | `SingleTurnAgentController`. It selects the protocol, calls `generate` once, and dispatches a validated batch. It does not open a socket and it does not write |
| `lca-model-runtime` | Unchanged. `select_protocol`, `GenerationRequest`, and `GenerationResponse` |
| `lca-ollama` | Unchanged. One HTTP attempt per generation. No retry after a dropped connection |
| `lca-tools` | Unchanged. `ToolRegistry::workspace`, `parse_action_document`, `validate_batch`, `execute_validated` |
| `lca-config` | Unchanged. `max_steps` is the configured action budget for this turn |
| `lca-cli` | `agent run`. Loads configuration, builds the runtime and the sandbox, prints the result |

`lca-core` now depends on `lca-model-runtime`. It does not depend on `lca-ollama`. The runtime crate does not depend on `lca-core`.

`lca ask` still streams text, sends no tools, and does not parse the answer. `lca tools probe` still uses `ToolRegistry::diagnostic` and still prints `execution: disabled`.

## Single-turn invariant

`SingleTurnAgentController::run` accepts the prompt, then:

1. Looks up capabilities (`POST /api/show` through the Ollama adapter). This is not a generation.
2. Selects the protocol once. LCA-01F keeps this controller at one generation and routes that selection through `resolve_protocol_profile` and `select_protocol_with_profile`. `lca tools probe` still calls `select_protocol` and does not apply the profile.
3. Calls `ModelRuntime::generate` once, with `stream` false.
4. Interprets that response with the protocol that was selected.
5. Validates the whole batch, then dispatches it, or returns the error.

An empty prompt returns before step 1 and does not consume the turn. Every other call consumes it. A protocol failure, a model failure, a bad document, or a tool failure does not start another `generate`. A second `run` on the same controller returns `second_model_turn` and does not contact the runtime again.

The controller does not call `generate_stream`. The Ollama chat helper still sends one HTTP request and returns the transport error. A dropped connection is not tried again, because the server may already have started sampling.

The controller does not enter `waiting_for_tool`. Leaving that state for more work would be another agent step.

## What the model is shown

The CLI passes `ToolRegistry::workspace`. The controller advertises tools from that registry whose policy decision is allowed and whose class is still enabled:

| Tool | Advertised when |
| --- | --- |
| `list_directory`, `read_file`, `search_files` | `read_enabled` |
| `apply_patch` | `write_enabled` |
| `diagnostic_echo` | never |

`diagnostic_echo` stays registered. A model that emits it anyway is validated and then reported as `not_executed`. Names and JSON schemas sent to the model are `RegisteredTool::name`, `description`, and `schema`. The controller does not keep a second copy of those schemas.

Native mode puts those definitions on `GenerationOptions::tools` and leaves the response format as text. JSON mode sends no `tools` array. The system text includes one JSON catalog built from the same registry fields, and `protocol_version` 1. `format: "json"` is set only when JSON mode was `Confirmed`, matching LCA-01C.

## How a response becomes a batch

| Selected protocol | Source of calls | Ignored |
| --- | --- | --- |
| Native | `GenerationResponse::tool_calls`, in order | Assistant text, including a JSON document or a `<tool_call>` marker |
| JSON | `parse_action_document` on the whole assistant text | Native `tool_calls` on the same response |

`parse_action_document` is the only JSON parser. Markdown fences, a wrong `protocol_version`, a document above 64 KiB, and invalid JSON are errors. The bytes are not repaired and a JSON object is not extracted from prose.

The configured budget is `min(max_steps, MAX_ACTIONS)`. `MAX_ACTIONS` is 8. A larger `max_steps` does not raise it. A proposal list above the effective limit is rejected before `validate_batch` and before any tool runs.

`validate_batch` still rejects the whole batch on the first unknown tool, invalid argument, missing field, or policy denial. No action from a rejected batch is dispatched.

## Dispatch

Accepted actions run through `dispatch_validated` in order. That function is unchanged:

- read tools run inside the sandbox
- `apply_patch` prepares a diff in memory
- `diagnostic_echo` returns `NotExecuted`

The controller has no call to `commit_prepared`. Model text that contains `approve` is not a confirmation. `agent run` does not read stdin. The CLI prints `applied: false` and the confirmation line for a prepared patch. Applying the patch remains `lca tools patch prepare`.

A tool error stops the batch. Earlier results are printed and the process exits 1. Later actions do not run, and the model is not asked to recover.

A response with no calls is a successful text turn. `model_calls` is 1.

## CLI

```text
lca agent run "Lies Cargo.toml"
lca agent run --protocol native "Lies Cargo.toml"
lca agent run --protocol json "Lies Cargo.toml"
lca agent run --protocol auto "Lies Cargo.toml"
```

The default protocol is `auto`. Any other value is a clap error and exits 2.

A successful turn prints `protocol`, `model_calls`, `actions`, and one block per action (`result` is `read`, `listed`, `searched`, `prepared`, or `not_executed`). Non-empty assistant text follows the blocks. Failures go to stderr as `lca: ...` and exit 1. Validation errors do not include argument values.

## Errors

| Kind | When |
| --- | --- |
| `empty_prompt` | The task is empty after trimming. The runtime is not contacted |
| `native_unconfirmed`, `json_fallback_disabled`, `no_protocol` | Selection failed. `generate` was not called |
| `invalid_request`, `connection`, `timeout`, `backend_failure`, `protocol_violation` | The runtime failed. It is not called again |
| `markdown`, `invalid_json`, `unsupported_version`, `too_large` | The JSON document was rejected by the existing parser |
| `unknown_tool`, `invalid_arguments`, `policy_denied`, `too_many_actions` | `validate_batch` rejected the batch. Nothing ran |
| `action_limit` | The proposal list is larger than `min(max_steps, 8)`. Nothing ran |
| `not_found`, `tool_disabled`, and the other `FsError` kinds | A validated action failed. Earlier actions are kept. The rest are not started |
| `second_model_turn` | `run` was entered again after a turn had already been claimed |

## Tests

Controller tests use a fake `ModelRuntime`. They count `generate`, `capabilities`, and `generate_stream`. CLI tests use a local HTTP stub and assert two requests for a turn (`/api/show`, then one `/api/chat`), `stream: false`, registry tool names on the native request, a read of a workspace file, a patch that does not change the file, a JSON document that is not overridden by a native call, a textual tool call that is not executed, an unknown tool, a `max_steps` of 1, and a HTTP 500 that is not followed by another chat.

`cargo test --workspace` does not call a live model unless `LCA_OLLAMA_SMOKE=1`.
