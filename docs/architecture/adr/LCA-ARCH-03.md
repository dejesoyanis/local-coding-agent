# LCA-ARCH-03: Hybrid structured tool calling

- Status: Accepted
- Decision: C
- Milestone: LCA-01C

## Context

The agent will eventually call tools. The first backend is local Ollama. A later backend may be llama.cpp. Model output is not trusted: a tool name in text is not permission to read a file, write a file, or start a process.

LCA-01B already reports `tools` and `json_mode` as `Confirmed`, `NotReported`, or `Unknown`. It does not treat an unknown capability as support. This milestone needs a way to receive structured calls without executing them and without tying the agent core to Ollama's JSON.

## Decision

Use hybrid structured tool calling.

1. The controller selects one protocol before the model is called: `native`, `json`, or `auto`.
2. Native is selected only when the backend reported tool calling as `Confirmed`.
3. `auto` prefers that confirmed native protocol. Otherwise it uses the JSON action document, and only because the composition root explicitly allows that fallback. The fallback is strict validation of one JSON document. It is not a promise that the model will emit JSON.
4. Both protocols become the same unvalidated `AgentAction` values. `validate_batch` is the only constructor of `ValidatedAction`. One invalid action rejects the whole batch.
5. The Ollama adapter transports native `tool_calls` on non-streaming `POST /api/chat`. It does not execute them and it does not read tool calls out of prose. `generate_stream` stays a text stream. A request that advertises tools or JSON format is rejected before a stream is opened.
6. The only registered tool in this milestone is `diagnostic_echo`. Validation does not run it.

```text
lca tools probe
  -> select_protocol(capabilities)
  -> ModelRuntime::generate
       -> OllamaModelRuntime
  -> propose_actions
  -> validate_batch
  -> print the proposal
```

`lca ask` does not enter this path. It still streams text and sends no `tools` field.

## Consequences

- `GenerationRequest` gained optional `tools` and `response_format`. Both default to the LCA-01B text request, so existing `generate` and `generate_stream` callers keep their behavior.
- `GenerationResponse` carries raw tool calls and is no longer `Eq`, because JSON values are not `Eq`. `complete` still builds a response with an empty call list.
- `lca-tools` does not depend on `lca-model-runtime`. The CLI maps raw calls and JSON actions into proposals. `lca_tools::ToolArguments` remains the LCA-01A path, search, and command enum. JSON arguments live in `lca_tools::action::ToolArguments`.
- Ollama 0.40.16 was probed locally. `qwen3:8b` returned a complete `tool_calls` array with object arguments, including a model-supplied `id` that the adapter drops. The same model, when streamed, put that complete array on one non-terminal NDJSON frame. `qwen2.5-coder:7b` advertised `tools` and still returned a JSON-looking string in `content`, with no `tool_calls` field. The probe treats that as "no tool call". It does not scrape the string.
- `format: "json"` is sent only when JSON mode is `Confirmed`. `lca-30b-agent` reports `capabilities: ["completion", "tools"]` from `POST /api/show`, so auto mode selects native and does not send `format`.
- A validated action is still not executed. `RejectingToolExecutor` is unchanged and is not called by the validator.

## Alternatives not taken

- Native tool calling only. Models that advertise `tools` still sometimes answer in text, and a future backend may not have a native tool channel.
- JSON documents only. That would ignore a confirmed native `tool_calls` array and would invite scraping JSON out of prose.
- Parsing `<tool_call>` or `<function=...>` markers. Those strings are untrusted text. The adapter and the JSON parser both leave them alone.
- Aggregating tool calls inside `generate_stream` in this milestone. One observed stream shape is a complete call on a non-terminal frame. Another observed shape is the call split across text tokens. Non-streaming `generate` is the reliable aggregation point, and a structured stream request fails before I/O instead of dropping the call.
- Switching protocol after a bad payload. Selection happens once.
