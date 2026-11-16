# LCA-ARCH-05: Controlled single-turn dispatch

- Status: Accepted
- Decision: C
- Milestone: LCA-01E

## Context

LCA-01C can receive a native tool call or a versioned JSON action document and validate the batch. It does not execute the batch. LCA-01D can execute a validated read and can prepare `apply_patch`, and it writes only after a confirmation line typed in that same process. `lca ask` still streams text and does not see the workspace tools.

The next step is to let one user task drive one model call and then hand a validated batch to the existing dispatcher. A second model call, a retry, or a protocol switch after a bad payload would start the agent loop this milestone does not have.

## Decision

Use a controlled single-turn dispatch.

1. `SingleTurnAgentController` in `lca-core` owns the turn. `lca-cli` loads configuration, builds the Ollama runtime, the workspace sandbox, and `ToolRegistry::workspace`, then calls the controller once.
2. The controller selects the protocol once from the existing capability report, then calls `ModelRuntime::generate` once. It does not call `generate_stream`. A second `run` on the same controller is refused before another capability lookup or generation.
3. Native calls come only from `GenerationResponse::tool_calls`. JSON calls come only from `parse_action_document`. Text that looks like a call is not a call. A rejected payload does not select the other protocol and does not repair the JSON.
4. `validate_batch` runs on the whole proposal list before any dispatch. `dispatch_validated` then runs the accepted actions in order. A tool error stops the rest of the batch. The controller does not call `commit_prepared`, so `apply_patch` stays a prepare.
5. The model is shown the registry schemas of the tools the current limits still allow, except `diagnostic_echo`. Definitions are copied from `RegisteredTool`. They are not rewritten for the prompt.

```text
lca agent run
  -> capabilities          POST /api/show, not a generation
  -> select_protocol       once
  -> ModelRuntime::generate
       -> one POST /api/chat, stream false, no HTTP retry
  -> propose_actions
  -> validate_batch
  -> dispatch_validated    read, or prepare
  -> stop
```

`lca ask` and `lca tools probe` stay on their existing paths. The probe still uses `ToolRegistry::diagnostic` and still does not execute.

## Consequences

- `lca-core` depends on `lca-model-runtime` as well as `lca-tools`. It does not depend on `lca-ollama` or `lca-config`. `lca-model-runtime` does not depend on `lca-core`, so the edge is not a cycle. The CLI remains the only place that constructs `OllamaModelRuntime`.
- The controller does not enter `waiting_for_tool`. The only way back from that state is `running`, and that edge is the loop this milestone refuses.
- `capabilities` is a separate `/api/show` request. It is not a model turn. The Ollama adapter already performs one attempt per generation and does not retry after a dropped connection. The controller does not issue a second `generate` when that attempt fails.
- The effective action limit is the smaller of `limits.max_steps` and `MAX_ACTIONS` (8). A configured budget cannot raise the protocol limit.
- Reads that finished before a later tool error are reported and are not rolled back. They do not change files. The process exits with an error and does not ask the model what to do next.
- `diagnostic_echo` remains in the workspace registry. It is not advertised. If a model emits it anyway, dispatch reports it as not executed.

## Alternatives not taken

- Feeding tool results back to the model. That is a second turn.
- Parsing a tool call out of assistant text when the native `tool_calls` array is empty, or parsing native calls when JSON mode was selected.
- Retrying a model error, repairing JSON, or switching protocol after the response.
- Letting `agent run` read the approval line and write the prepared file.
- Building a second tool list or a second JSON parser beside the LCA-01C registry and `parse_action_document`.
