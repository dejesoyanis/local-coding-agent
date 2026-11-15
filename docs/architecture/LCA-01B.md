# LCA-01B: Local Model Runtime and Ollama Adapter

This milestone adds a local, backend-neutral generation runtime and the Ollama adapter. `lca ask` streams one answer to stdout. It does not run tools, write project files, download models, or start an agent loop.

The architecture decision is [LCA-ARCH-02](adr/LCA-ARCH-02.md) (option B).

## Runtime architecture

```text
lca ask
   |
   v
lca-cli composition root
   |
   v
ModelRuntime                         crates/lca-model-runtime
   |
   +---- OllamaModelRuntime          crates/lca-ollama
   |
   +---- future llama.cpp adapter
```

`lca-model-runtime` depends on `async-trait`, `futures-util`, and `thiserror`. It does not depend on HTTP, Ollama, or a model file format. `lca-ollama` depends on the runtime crate. `lca-core`, `lca-config`, and `lca-tools` do not. `lca-cli` constructs the adapter and then streams through the trait, so the write loop does not mention Ollama types.

The LCA-01A health client stays. `HttpOllamaClient` still uses `ureq` for `GET /api/version` and `GET /api/tags`. Generation uses a separate `reqwest` client. That split keeps the health-check tests and timeouts intact.

## Public contracts

`ModelRuntime` is `Send + Sync` and object-safe:

- `generate` returns one `GenerationResponse`
- `generate_stream` returns a `GenerationStream`
- `capabilities` returns a `ModelCapabilities` report

`GenerationRequest` carries a model name, at least one message, optional system instructions, sampling parameters, an optional token limit, an optional context window, and an optional deadline. `MessageRole` is `System`, `User`, or `Assistant`. Tool messages and multimodal content are not part of the contract.

Validation runs before any I/O. Limits:

| Field | Bound |
| --- | --- |
| Model name | 1..=256 characters, no whitespace or control characters |
| Messages | 1..=256 |
| Message or system text | non-empty, at most 1 MiB of characters |
| `max_tokens` | >= 1, and not above `context_tokens` when both are set |
| `context_tokens` | 1..=1_048_576 |
| Timeout | 1 ms through 3600 s |
| `temperature` | finite, 0 through 2 |
| `top_p` | finite, 0 through 1 |
| `top_k` | 1..=10_000 |
| `repeat_penalty` | finite, 0 through 4 |

Validation errors do not echo prompt text.

`GenerationResponse` and `GenerationMetadata` carry the model, text or finish metadata, an optional finish reason, optional token counts, and optional timing. A count or duration that the backend omitted stays absent. Zero is not invented.

`GenerationEvent` is `TextDelta(String)` or `Completed(GenerationMetadata)`. A successful stream is zero or more deltas followed by exactly one completion. Dropping `GenerationStream` cancels the operation.

`CapabilityStatus` is `Confirmed`, `NotReported`, or `Unknown`. `ModelCapabilities::from_parts` drops blank labels, drops a zero context length, and sorts unrecognized names. It does not mark tools or JSON mode as confirmed by itself.

The reusable harness is `lca_model_runtime::contract::exercise` (feature `contract`). It is the suite a llama.cpp adapter must pass. The model names and expected outcomes are documented on that module.

## Ollama adapter

`OllamaModelRuntime::connect` checks the origin and the timeouts, then builds one `reqwest` client. The client disables the system proxy, disables redirects (`Policy::none()`), uses HTTP/1.1, and sends `user-agent: lca/0.1`. Construction does not open a socket.

| Call | HTTP |
| --- | --- |
| `generate` | `POST /api/chat` with `stream: false` |
| `generate_stream` | `POST /api/chat` with `stream: true` and `Accept: application/x-ndjson` |
| `capabilities` | `POST /api/show` with `{ "model": ... }` |

Roles map to the Ollama strings `system`, `user`, and `assistant`. Optional system text is a leading system message. Sampling fields are sent only when set: `temperature`, `top_p`, `top_k`, `seed`, `repeat_penalty`, `num_predict` (`max_tokens`), and `num_ctx` (`context_tokens`). The payload does not contain a `tools` field.

Each generation is one HTTP attempt. There is no retry.

A success body is capped at 8 MiB. An error body is capped at 8 KiB. Only a JSON `error` string is kept, with control characters replaced by spaces and a 512-character cap. A non-JSON body is discarded.

## Streaming protocol

The parser reads the response body as it arrives. It does not buffer the whole response.

- A frame is one NDJSON line.
- A TCP chunk may contain several lines, or end in the middle of a line. The partial tail stays buffered until the rest of the line arrives.
- A single frame may not exceed `MAX_STREAM_FRAME_BYTES` (1 MiB). A larger frame is a protocol error. The buffer is not allowed to grow past that limit.
- A non-empty `message.content` becomes `TextDelta`.
- `"done": true` becomes `Completed`. That is the only successful terminal event.
- End of stream without `done` is `StreamInterrupted`.
- End of stream inside an unfinished line is a protocol error.
- A JSON `error` field is a runtime error, not a completion.
- A transport error while reading the body is `Timeout` or `StreamInterrupted`. It is never turned into `Completed`.
- Dropping the stream drops the HTTP body, which cancels the read.

## Error semantics

| Variant | When |
| --- | --- |
| `InvalidRequest` | The request fails validation, or the backend returns HTTP 400 or 422. Not retried. |
| `Connection` | The socket cannot be established or is reset before a response. |
| `Timeout` | The connect or request deadline elapses, or the backend returns HTTP 408 or 504. |
| `ModelNotFound` | HTTP 404, or a sanitized backend message that contains `not found`. |
| `BackendFailure` | HTTP 5xx, or another unsuccessful status that is not one of the cases above. |
| `ProtocolViolation` | Empty, truncated, or non-JSON success payloads, and oversized or malformed frames. |
| `StreamInterrupted` | The stream ends without `done`, or the body read fails for a non-timeout reason. |

`kind()` is a stable label. `report()` appends up to four source errors. Response bodies are not stored on the error. Logs record the endpoint, the model name, and `error_kind`. They do not record the prompt or a response body.

## Configuration

Generation reads the existing `[ollama]` table. No second table was added.

```toml
[ollama]
endpoint = "http://127.0.0.1:11434"
model = "lca-30b-agent"
context_window = 8192
generation_limit = 2048
connect_timeout_secs = 5
request_timeout_secs = 120
```

`connect_timeout_secs` defaults to 5. `request_timeout_secs` still defaults to 5, which is the LCA-01A health-check default. A long generation needs a larger `request_timeout_secs`. Both must be from 1 through 3600 seconds. Missing required config still fails at load time. There is no cloud model and no credential field.

`lca ask` sends `generation_limit` as `max_tokens`, `context_window` as `context_tokens`, and `request_timeout_secs` as the request deadline.

## Security boundaries

- Generation accepts only loopback origins: `127.0.0.0/8`, `::1`, and `localhost`, with `http` or `https`, and with no user, password, path, query, or fragment.
- Redirects are not followed, including a redirect to another host.
- The system proxy is not used.
- `lca status` can still contact a non-loopback endpoint that the loader accepted. That is the LCA-01A probe. `lca ask` refuses the same endpoint before it connects.
- The answer is written to stdout and is not executed, parsed as a tool call, or written into the workspace.
- No `unsafe` code.

## CLI

```text
lca ask "Erkläre mir Rust Ownership"
lca ask --model lca-agent "Was ist ein Rust Trait?"
lca ask --config C:\path\to\lca.toml "prompt"
```

The binary loads the config, rejects an empty prompt before connecting, builds the runtime, and writes each text delta to stdout with a flush. Diagnostics go to stderr as `lca: ...`. A successful answer that does not already end in a newline gets one trailing newline. That newline is a presentation choice in the CLI, not part of the runtime contract.

Exit codes: `0` on a terminal completion, `1` on a usage or runtime failure, `130` on Ctrl+C. Cancellation drops the stream and prints `lca: interrupted` on stderr. The library `dispatch` path refuses `ask`, because that path would have to buffer the answer.

## Test strategy

Tests do not need a model or a running Ollama.

- Unit tests cover request validation, roles, payload mapping, response mapping, HTTP error mapping, capability mapping, config validation, and NDJSON frame parsing (split lines, several frames per chunk, a missing `done`, a partial trailing frame, and the frame limit).
- `crates/lca-ollama/tests/runtime.rs` runs the adapter against an in-process mock: successful chat, the shared contract, HTTP 400/404/500 with a single attempt, redirect without following `Location`, empty and broken JSON, an early close, split and packed NDJSON, a missing `done`, an oversized frame, request timeout, connection reset, a closed port, stream cancellation, and an invalid request that never connects.
- `contract::exercise` is the shared contract. The Ollama mock implements it, and `ScriptedRuntime` implements it inside the runtime crate.
- `tests/smoke.rs` is `#[ignore]`. It runs only when `LCA_OLLAMA_SMOKE=1`. Optional `LCA_OLLAMA_MODEL` and `LCA_OLLAMA_ENDPOINT` override the defaults `lca-30b-agent` and `http://127.0.0.1:11434`.

On this Windows host, a closed TCP port drops the SYN instead of sending RST, so that case is a connect timeout. An accepted socket closed with linger 0 is the connection-failure case. Other operating systems may report a closed port as `connection`. The closed-port test accepts either failure kind and rejects success.

## Known limitations

- `request_timeout_secs` defaults to 5 seconds. Long answers need a higher value.
- `lca status` is not limited to loopback. Only generation is.
- The runtime does not download models, call tools, keep conversation memory, or schedule a GPU.
- Capability lookup trusts only fields Ollama returned. JSON mode stays `Unknown` unless the capability list contains `json` or `json_mode`, even when other capabilities are listed. Absence is not treated as proof that JSON mode is missing.
- A llama.cpp adapter is not implemented.

## llama.cpp extension

Add an adapter crate that depends on `lca-model-runtime` and implements `ModelRuntime`. Map that backend's chat, stream, and model-info calls onto the existing request, event, error, and capability types. Do not add Ollama fields to the trait. Select the adapter in `lca-cli` from configuration, and run `contract::exercise` against it. `lca-core` stays unaware of both backends.
