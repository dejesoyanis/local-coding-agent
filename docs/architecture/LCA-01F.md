# LCA-01F: Controlled multi-turn agent loop

This milestone lets one user task drive several model turns inside fixed budgets. The architecture decisions are [LCA-ARCH-06](adr/LCA-ARCH-06.md) and [LCA-ARCH-07](adr/LCA-ARCH-07.md).

`lca agent run` stays one generation. `lca agent execute` is the bounded loop. Neither command runs a shell, and neither applies a patch.

## Module boundaries

| Crate | Responsibility |
| --- | --- |
| `lca-model-runtime` | `ModelProtocolProfile`, `resolve_protocol_profile`, `select_protocol_with_profile`. `select_protocol` stays capability-only. `Message` can carry a tool result and echoed tool calls |
| `lca-tools` | The same JSON decoder. `parse_action_document` still accepts only protocol version 1. `parse_agent_document` accepts version 1 and version 2 |
| `lca-core` | `BoundedAgentController`, the state machine, budgets, and the conversation. `SingleTurnAgentController` remains the one-turn path and now selects through the profile |
| `lca-ollama` | Chat messages can include `tool_name`, `tool_call_id`, and `tool_calls`. A non-empty tool-call id is preserved. The function index is still dropped |
| `lca-config` | New `[agent]` table. `limits.max_steps` is unchanged |
| `lca-cli` | `agent execute`. Builds the runtime, the sandbox, and `ToolRegistry::workspace`, then renders the report |

`lca-core` still does not depend on `lca-ollama` or `lca-config`. The CLI is the composition root.

`lca ask` still streams text and sends no tools. `lca tools probe` still uses `select_protocol` and `ToolRegistry::diagnostic`. `lca eval tools` is unchanged.

## Model profiles

`resolve_protocol_profile` is the only model-name comparison.

| Identifier | Preferred protocol | `fallback_eligible` | Version | Digest |
| --- | --- | --- | --- | --- |
| `lca-30b-agent` | JSON | false | 1 | unset |
| anything else, including `lca-30b-agent:latest` | capability rules | true | 0 | unset |

`fallback_eligible` is a selection-time flag. It is not permission to retry after an error. The digest field exists so a later milestone can pin a model. LCA-01F does not check it.

## Protocol selection

Explicit `--protocol native` and `--protocol json` ignore the profile and call `select_protocol`.

`auto` uses the profile:

- registered model: JSON first, even when `/api/show` confirms tools. If JSON is not available, selection fails with the JSON error. Native is not tried.
- unregistered model: the LCA-01E rule. Native when tools are confirmed, otherwise JSON.

The chosen protocol is stored on the run and reused for every generation. A protocol error ends the run. There is no second selection.

`lca agent run` uses the same selection, then still performs one generation. For `lca-30b-agent`, default `auto` is now JSON. Native single-turn calls pass `--protocol native`. The probe does not use the profile, so a probe of the same model can still report native when tools are confirmed.

Loop prompt version is `lca-01f-h1.1`. The eval prompt version stays `lca-01e-h1.1`. The single-turn prompt is unchanged.

## State machine

`AgentLoopState` documents the legal edges. `can_transition` is the check. Terminal states are `Completed`, `Failed`, and `BudgetExhausted`. A transition out of a terminal state is rejected and becomes `state_error` only when the machine was not already terminal.

```text
Initialized
  -> ModelRequested          one turn is reserved here, before generate
  -> ModelResponded
       -> Completed          final answer
       -> ValidatingActions
            -> ExecutingTools
                 -> Completed          prepared patch
                 -> PreparingNextTurn
                      -> ModelRequested
```

Any non-terminal state may also enter `Failed` or `BudgetExhausted`.

A capability lookup is not a model turn. The turn counter increments only inside `ModelRequested`, and only when a turn remains. If the counter is already at the limit, the run stops with `turn_budget` and does not call `generate`.

A transport error is a runtime failure. It does not reserve another turn. A rejected batch never enters `ExecutingTools`. A prepared patch never enters `PreparingNextTurn`. A policy denial and a tool error enter `Failed` and stop.

`RunStatus::Cancelled` is reported when the cancel flag is set. The state used for that stop is `Failed`, because cancel is a terminal failure of the run rather than a fourth state.

## Conversation contract

The runtime `Message` is the only message model. Roles are system, user, assistant, and tool. An assistant message may have empty content only when it carries tool calls. A tool message needs a valid tool name and non-empty content.

The system prompt is built once from the selected protocol and the advertised registry tools. `diagnostic_echo` is not advertised. Reads are advertised when `read_enabled` is set. `apply_patch` is advertised when `write_enabled` is set. The catalog is the registry name, description, and schema. The controller does not keep a second schema list.

### Native

A native tool turn appends:

1. An assistant message with the response text and the echoed `RawToolCall` values, including a call id when the runtime supplied one.
2. One tool-role message per result. The body is contract `lca.tool_result`, `contract_version` 1, `trust` `untrusted_data`.
3. One user message, contract `lca.controller_budget`, `trust` `controller`, with the remaining budget.

The next native request sends those messages and the same tool definitions. The tool-call id on the tool message is the id from the assistant call.

### JSON

JSON mode has no native tool role. A tool turn appends:

1. An assistant message whose content is the raw document.
2. One user message, contract `lca.tool_result`, `contract_version` 1, `trust` `untrusted_data`. The body contains the decision, the result objects, `error: null`, and the remaining budget.

Result objects are JSON values. File text is a string field inside that object. It is not parsed as a system instruction.

### Protocol version 2

Version 1 is `protocol_version` and `actions` only. `parse_action_document` still rejects every other version, so `lca agent run` and the LCA-01C tests keep that contract.

`parse_agent_document` is the same decoder with version 2 enabled. Version 2 may include `final_answer`. The string is required when `actions` is empty and forbidden when `actions` is not empty. A blank or whitespace-only string is `empty_final_answer`. The decoder does not repair JSON, strip a markdown fence, or drop unknown fields. A version-1 document with actions is still a tool turn. A version-1 document with an empty `actions` array has no `final_answer`, so the loop treats it as a protocol error (`missing_final_answer`) and stops. It is not a successful empty turn, and it does not switch to native.

The loop prompt states that contract without a contradictory “do not add fields” line. `protocol_version` is always 2. `actions` is always present. `final_answer` is absent when `actions` is not empty, and it is a non-empty string when `actions` is empty. The only allowed fields are those three. The model response is one JSON object, with no markdown fence and no text outside the object. The prompt includes one tool-call example and one final-answer example, and both parse with `parse_agent_document`. The examples are not introduced with a `Final answer:` label. That label was copied into a field name `final_answer:`, which the parser rejects as an unknown field.

```json
{"protocol_version": 2, "actions": [], "final_answer": "..."}
```

### JSON output request

`json_mode_confirmed` is true only when `/api/show` lists `json` or `json_mode`. Requesting JSON output does not set the flag.

`BoundedAgentController` sends `ResponseFormat::Json` on every JSON run, including when the capability is unconfirmed. `lca-ollama` maps that to the Ollama field `format` with the string `json`. That mode asks for syntactic JSON. The request does not include a JSON Schema. The controller still validates the document.

`SingleTurnAgentController` is unchanged. It sends `ResponseFormat::Json` only when JSON mode is confirmed, and `ResponseFormat::Text` otherwise. It still accepts only protocol version 1.

If Ollama rejects `format: "json"`, the adapter returns the HTTP failure. A 400 is `invalid_request` and the run stops as `model_error`. A 200 whose body is not JSON is `invalid_http_json` and the run stops as `protocol_error`. Neither path switches to native, and neither sends another generation.

### Diagnostics

A rejected assistant document records a code, the response length, the protocol version when that JSON number can be read, whether `actions` and `final_answer` are present, and the finish reason. The detail and the debug log do not include the assistant text or a file body.

| Code | Meaning |
| --- | --- |
| `invalid_json` | Assistant content is not one JSON value |
| `invalid_http_json` | The Ollama HTTP body is not JSON. `RuntimeError::kind` stays `protocol_violation` |
| `missing_final_answer` | Version 2 has an empty `actions` array and no `final_answer` |
| `empty_final_answer` | `final_answer` is empty or only whitespace |
| `missing_version`, `invalid_version`, `unsupported_version` | The protocol version is missing, not an integer, or not supported |
| `markdown`, `unknown_field`, `not_an_object`, `invalid_action`, `final_answer_conflict`, and the other parser kinds | The document structure was rejected |
| `truncated_response` | The finish reason is `length` and the assistant content is not valid JSON |

A finish reason of `length` on a document that already parsed is not reported as truncation.

## Tool results

Tools come from `ToolRegistry::workspace`: `list_directory`, `read_file`, `search_files`, and `apply_patch`. The registry does not advertise a shell, a process tool, or a network tool.

The whole batch is validated with `validate_batch` before `dispatch_validated`. One invalid action rejects the batch. Nothing in it runs.

A tool error records the actions that already returned, skips the rest of the batch, and stops the run. The failed action is not recorded as executed. The model is not asked to recover.

Successful results are counted against the result-byte budget before they are appended. The byte count is the serialized result object. If the next object would exceed the budget, the action is recorded, the result is not appended, and the run stops with `result_budget`. No further generation follows.

A prepared patch is not appended and is not sent back. The run completes with `prepared_patch`.

## Budget enforcement

`[agent]` holds the execute budgets. CLI flags override two of them for one process: `--max-turns` and `--max-actions` (per run, not per turn).

```toml
[agent]
max_turns = 5
max_actions_per_turn = 8
max_actions_per_run = 20
max_tool_result_bytes = 524288
max_history_bytes = 1048576
timeout_secs = 180
```

`limits.max_steps` still feeds `lca agent run` and is clamped to 8. A value of 32 does not become 32 model turns. `limits.timeout_secs` is not the execute timeout. The execute timeout field is `agent.timeout_secs`.

The controller checks cancel and timeout before selection, before each reservation, and between actions. History bytes are the system text plus message content, tool names, tool-call ids, and tool-call arguments. They are not the HTTP body size. If the next message does not fit, the run stops with `history_budget` and does not call `generate`. A history overflow after a tool turn can leave the assistant message in the in-memory history without its result. That history is not sent, because the run has already stopped.

The model sees a budget snapshot. Rust still enforces the caps. The model cannot raise them.

## Termination

| Stop | Status | Another model request |
| --- | --- | --- |
| Final text, or JSON version 2 with an empty `actions` array and `final_answer` | `completed` / `final_answer` | no |
| Prepared patch | `completed` / `prepared_patch` | no |
| Tool error | `failed` / `tool_error` | no |
| Rejected batch | `failed` / `validation_error` | no |
| Parser or selected-protocol failure | `failed` / `protocol_error` | no |
| Runtime error whose kind is `protocol_violation` | `failed` / `protocol_error` | no |
| Other runtime error | `failed` / `model_error` | no |
| Turn, action, result, history, or time budget | `budget_exhausted` and the matching reason | no |
| Cancel flag | `cancelled` / `cancelled` | no |

`completed` exits 0. Every other status exits 1. A budget stop does not synthesize a final answer. `final_answer` is empty.

## CLI

```text
lca agent execute --protocol auto|json|native --max-turns N --max-actions N --output text|json "<prompt>"
```

Text output is a stable `key: value` report: `protocol`, `model`, `profile_version`, `preferred_protocol`, `status`, `stop_reason`, `model_turns`, `tool_actions`, then one block per turn. Reads include the file body after `---`. Lists and searches print their entries. A prepared patch prints `applied: false`, `approval: unavailable`, and the diff. It does not print a confirmation line.

`--output json` prints one object with the same status fields and per-turn tool names. It does not include file bodies.

Stderr on failure is `lca: ` plus the detail, or the stop reason when there is no detail. Logs do not include secrets. Protected file bodies are not part of a denial.

## Security invariants

- The binding check stays in Rust. Prompt text and file text do not grant tools, raise budgets, or approve a write.
- Protected paths stay protected on every turn. They are not read, searched, or patched. Listings omit protected names. A denial does not echo the file body.
- `execute_command` is not a registered workspace tool. A batch that names it is rejected before any action runs.
- `apply_patch` prepares a diff in memory. The controller does not call `commit_prepared`. The string `approve` in model text is not a grant.
- `ApprovalLedger` and the confirmation line are valid only in the process that prepared the patch. `agent execute` does not print that line and does not suggest a later grant.
- Conversation history and tool-result bytes have hard caps. The loop cannot grow them by continuing.

## Tests

Deterministic tests live in `crates/lca-core/src/bounded.rs` and use a scripted `ModelRuntime`. They cover one final answer, a read then a final answer, search then read then an answer, a multi-tool batch, a rejected batch, a tool error, a model error, a JSON protocol error that does not fall back, a native protocol error, a prepared patch that does not write, turn, action, result, and history budgets, timeout, cancel, native tool-call association, JSON-first `auto` with explicit native still available, privacy across turns, a file that tells the model to run a shell, and an empty prompt.

State-machine tests lock the terminal edges, count one reservation per generation, and assert that a transport error, a policy denial, a prepared patch, a rejected batch, and a spent budget do not cause another generation.

CLI tests stub Ollama. `agent run` cases that need native calls pass `--protocol native`. New execute cases cover JSON `auto`, a read followed by a final answer, `--max-turns 1` with `limits.max_steps = 32`, a prepared patch with `approval: unavailable`, a protected `lca.toml`, and `--output json`.

Live Ollama checks are not part of `cargo test`. They run only when someone invokes `lca agent execute` against a local daemon on purpose. `LCA_OLLAMA_SMOKE=1` remains the existing live gate and is not set by the unit suite.

## Known limitations

- The approval binding does not survive the process. A prepared patch from `agent execute` cannot be applied later by resending the diff. Apply stays `lca tools patch prepare` in a process that still holds the binding.
- The profile digest is not verified. A renamed or retagged model does not match `lca-30b-agent` and stays on the capability rules.
- `lca tools probe` does not apply the profile.
- Version-1 empty action documents are a protocol error inside the loop. Single-turn JSON still accepts them as an empty batch.
- History accounting is the controller's message bytes, not the size of the HTTP request.
- The loop does not stream. Each turn is one non-streaming `generate`.
- There is still no shell and no automatic write.

## Outlook for LCA-01G

LCA-01G should not add a shell, should not persist an approval that outlives the file bytes it was bound to, and should not turn a protocol error into a retry.

The open work is the gap this milestone left on purpose:

- Verify a model digest before trusting a JSON-first profile, or keep unknown identifiers on the capability rules.
- Decide whether a prepared patch can be granted across a real boundary without treating model text as the grant. The grant has to be checked again against the prepared bytes.
- Keep the probe and the agent selection visibly different, or teach the probe to print the profile without changing its capability report.
