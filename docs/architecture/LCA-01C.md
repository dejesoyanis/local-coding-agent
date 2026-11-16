# LCA-01C: Hybrid Structured Tool Calling

This milestone receives structured tool calls, normalizes them, and validates them. It does not execute a tool, write a project file, start a process, or run an agent loop.

The architecture decision is [LCA-ARCH-03](adr/LCA-ARCH-03.md) (option C).

## Data flow

```text
lca tools probe
   |
   v
capabilities + select_protocol
   |
   +-- native, only if tools == Confirmed
   |      POST /api/chat  stream:false  tools:[diagnostic_echo]
   |
   +-- json, when native is not confirmed and the fallback is allowed
          POST /api/chat  stream:false
          format:"json" only if json_mode == Confirmed
   |
   v
raw tool calls, or one JSON action document
   |
   v
propose_actions          controller ActionId, source native|json
   |
   v
validate_batch           registry, schema, size, policy
   |
   v
ToolCallBatch            every action valid, or the batch is an error
```

`ValidatedAction` has no public constructor and no deserializer. `AgentAction::status` is always `unvalidated`. A validated batch is still not executed: the probe prints `execution: disabled`.

`lca ask` is unchanged. It streams text, sends no tools, and does not parse the answer.

## Canonical action model

The types live in `lca-tools` under `action`.

| Type | Role |
| --- | --- |
| `ActionId` | `u64` from `ActionIdFactory`, starting at 1 for that factory |
| `AgentAction` | One proposal: id, tool name, JSON arguments, source, status `unvalidated` |
| `action::ToolArguments` | `serde_json::Value`, not the LCA-01A path/search/command enum |
| `ToolCall` | Name plus those JSON arguments |
| `ActionSource` | `native` or `json` |
| `ValidatedAction` | Built only inside `validate_batch` |
| `ToolCallBatch` | The ordered list of validated actions, or nothing |
| `ActionValidationError` | The first reason the batch was rejected |

A new factory restarts at 1 so tests stay deterministic. Identities from one factory are unique. The model cannot supply one: the JSON document rejects an `id` field, and the Ollama adapter drops `tool_calls[].id`.

`lca_tools::ToolArguments` at the crate root is still the LCA-01A enum. The JSON newtype is `lca_tools::action::ToolArguments`. They are not interchangeable.

## Registry and schema

`ToolRegistry::diagnostic` registers one tool.

| Field | `diagnostic_echo` |
| --- | --- |
| Name | `diagnostic_echo`, compared with `==` |
| Effect | read-only |
| Permission | `diagnostic` |
| Argument limit | 8192 bytes |
| Schema | object, `additionalProperties: false`, required string `message`, at most 1024 characters |

`Diagnostic_Echo`, `diagnostic_echo `, and `execute_command` are unknown. Unknown names are rejected before schema checks.

The schema checker accepts `type` (`object`, `string`, `integer`, `number`, `boolean`), `properties`, `required`, boolean `additionalProperties`, `minLength`, `maxLength`, and a string `description`. Any other keyword, including `pattern`, is rejected when the tool is registered. Omitted `additionalProperties` follows JSON Schema and allows extra fields. The diagnostic schema does not omit it.

A controller can insert another tool. Insertion is not authorization. `authorize_proposal` denies a mutating effect and denies every permission other than `diagnostic`. Schema failure is reported before that policy decision, so a mutating tool with a bad argument fails as `invalid_arguments`, and the same tool with a valid argument fails as `policy_denied`.

## Native tool calling

`GenerationOptions::tools` and `response_format` default to an empty list and ordinary text. `GenerationRequest::try_new` and `validate` reject duplicate names, names that are not an ASCII letter followed by letters, digits, or underscore, and parameters that are not a JSON object.

The Ollama payload adds `tools` only when the list is non-empty:

```json
{
  "type": "function",
  "function": {
    "name": "diagnostic_echo",
    "description": "...",
    "parameters": { "type": "object" }
  }
}
```

A non-streaming response reads `message.tool_calls` in order. Each entry must be an object with `function.name` and, when present, `function.arguments` as a JSON object. Missing arguments become `{}` and then fail schema validation if `message` is required. A JSON string in `arguments` is a protocol error and is not parsed again. More than 8 calls is a protocol error. Model `id` and function `index` are ignored.

This shape was captured from Ollama 0.40.16 and `qwen3:8b`:

```json
{
  "message": {
    "role": "assistant",
    "content": "",
    "tool_calls": [
      {
        "id": "call_yqfuarki",
        "function": {
          "index": 0,
          "name": "diagnostic_echo",
          "arguments": { "message": "hello" }
        }
      }
    ]
  },
  "done": true,
  "done_reason": "stop"
}
```

Text such as `<tool_call>` or `<function=diagnostic_echo>` stays in `content`. It does not become a call.

## JSON fallback

The document is the whole assistant text. The parser does not trim a fence, does not extract an object from prose, and does not repair commas or quotes.

```json
{
  "protocol_version": 1,
  "actions": [
    {
      "tool": "diagnostic_echo",
      "arguments": { "message": "hello" }
    }
  ]
}
```

Limits: 64 KiB for the document, at most 8 actions, and only the fields shown above. `protocol_version` must be the integer token `1`. A missing version, a string version, a fractional version, and any other integer are distinct errors. A leading markdown fence is `markdown` and the interior is not parsed.

The fallback runs only after `select_protocol` has chosen JSON. A native probe does not parse a JSON body, even when that body is a valid action document.

Ollama's `format: "json"` asks the server to constrain the text to JSON. It does not constrain the text to this document. The probe sends `format` only when `json_mode` is `Confirmed`. When it is `Unknown` or `NotReported`, the probe still accepts the fallback if the controller allowed it, and it still rejects anything that is not the document. A successful parse is not evidence that the model emits the document reliably.

`lca-30b-agent` on the local Ollama 0.40.16 server lists `completion` and `tools` only. Auto mode therefore selects native and does not send `format`.

## Protocol selection

| Preference | Result |
| --- | --- |
| `native` | Native if `tools` is `Confirmed`, otherwise `native_unconfirmed` |
| `json` | JSON if the runtime allows the fallback, otherwise `json_fallback_disabled` |
| `auto` | Native when `tools` is `Confirmed`, otherwise the allowed JSON fallback, otherwise `no_protocol` |

`Unknown` and `NotReported` are not confirmations. Unrecognized names such as `function_calling` are not confirmations. The CLI sets the JSON fallback to allowed because this milestone implements the strict parser. A backend that does not opt in gets `no_protocol` from auto mode.

There is no second attempt. An empty native `tool_calls` array plus a JSON body is a failed native probe.

The LCA-01B mapping is unchanged: if a capability list contains neither `json` nor `json_mode`, `json_mode` stays `Unknown` rather than `NotReported`. Selection still requires `Confirmed` before it sends `format`.

## Validation boundary

`validate_batch` checks, in order:

1. The batch has at most 8 actions.
2. Controller identities are unique.
3. The tool name is in the registry.
4. The encoded argument JSON is within the tool's byte limit.
5. The value matches the schema, including required fields, types, and unknown fields.
6. `authorize_proposal` allows the registered tool.

The first failure is the result. Actions that were checked earlier are not returned. Running the function twice on the same proposals yields the same error. The function does not take a `ToolExecutor`. It does not open files or start a process.

An empty proposal list validates as an empty batch. `lca tools probe` treats that empty batch as failure: `model produced no tool call`. A probe with no action is not a passing tool-calling test.

## Batch semantics

Fail-closed for the whole batch. A response may contain several calls, and their order is kept when every call passes. If call 0 is valid and call 1 is unknown, the result is an error at index 1. There is no partial `ToolCallBatch` and no mode that skips the bad call.

The same limit of 8 is enforced at three layers: the JSON parser, the native response parser, and `validate_batch`.

## CLI

```text
lca tools probe
lca tools probe --protocol native
lca tools probe --protocol json
lca tools probe --protocol auto
```

The default is `auto`. Any other protocol value is a clap error and exits 2.

A passing probe prints one protocol line and one block per validated action:

```text
protocol: native
tool: diagnostic_echo
validation: passed
execution: disabled
```

Failures go to stderr as `lca: ...` and exit 1. The lines do not include argument values. `lca ask` remains a streaming text command.

## Errors

| Kind | When |
| --- | --- |
| `native_unconfirmed` | Native was requested and `tools` is not `Confirmed` |
| `json_fallback_disabled` | JSON was requested and this runtime did not allow it |
| `no_protocol` | Auto found neither confirmed native calling nor an allowed fallback |
| `protocol_violation` | The Ollama body is not a chat response or `tool_calls` is malformed |
| `invalid_json`, `markdown`, `missing_version`, `unsupported_version` | The JSON document was rejected |
| `unknown_tool`, `invalid_arguments`, `too_large`, `policy_denied` | The batch was rejected |
| `model produced no tool call` | Validation succeeded and the batch was empty |

Runtime failures use the existing `RuntimeError` report. Prompt text and argument values are not copied into these messages.

## Security invariants

- Model output is untrusted. Deserialization does not authorize it.
- The validator and the Ollama adapter do not execute tools.
- No file is written, no process is started, and no worktree is created by this path.
- Unknown tools are rejected. Mutating tools are not implicitly allowed.
- `<tool_call>` and `<function=...>` are text.
- A confirmed capability is an explicit backend report. It is not inferred.
- The probe cannot change protocol after it sees the payload.

## Tests and the optional live call

Unit and integration tests use in-memory runtimes or a local HTTP stub. They do not need Ollama.

```text
$env:LCA_OLLAMA_SMOKE = "1"
cargo test -p lca-cli --test live_probe -- --nocapture
```

`apps/lca-cli/tests/live_probe.rs` returns immediately when `LCA_OLLAMA_SMOKE` is not `1`. When it is `1`, `lca tools probe --protocol auto` must print a validated `diagnostic_echo` and must not leave files in the temporary workspace. A model that returns prose fails that test. The existing `lca-ollama` smoke test stays `#[ignore]` and is not started by a normal `cargo test --workspace`.

## Known limitations

- Tool calls are not aggregated from a stream. On Ollama 0.40.16, `qwen3:8b` placed one complete `tool_calls` array on a non-terminal frame, and `qwen2.5-coder:7b` streamed a JSON-looking string in `content` with no `tool_calls` field. `generate_stream` rejects a request that sets tools or JSON format before it opens a socket. Text streaming still ignores a `tool_calls` field if a frame contains one.
- A `tools` capability means the server accepted the feature in its capability list. `qwen2.5-coder:7b` has that capability and still answered with text. The probe then fails closed.
- The schema subset cannot express `pattern`, `enum`, or `$ref`. Those schemas are refused at registration.
- JSON mode on this server is not a guarantee of the action document. For `lca-30b-agent` it is not even reported.
- Action identities are unique per factory, not a durable global counter.
- Nothing in this milestone runs `diagnostic_echo`.

## Later tool execution

A later milestone can execute only a `ValidatedAction`, and only after a separate authorization step. The existing `RejectingToolExecutor` remains the refusal path for workspace and process tools. The first executed tools should be read-only and workspace-scoped. The probe should stay a non-executing diagnostic. An agent loop that sends tool results back to the model comes after that, and it should keep the same fail-closed batch rule.
