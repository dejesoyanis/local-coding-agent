# LCA-ARCH-02: Local model runtime shape

- Status: Accepted
- Decision: B
- Milestone: LCA-01B

## Context

The agent needs to generate text from a local model. The first backend is a local Ollama server. A later milestone may add llama.cpp. Agent core, the application flow, and the CLI must not be rewritten when that backend arrives.

LCA-01A already has a blocking Ollama health client (`HttpOllamaClient` via `ureq`) and an `[ollama]` configuration table. That client only calls `/api/version` and `/api/tags`.

## Decision

Generation goes through a backend-neutral `ModelRuntime` trait in `lca-model-runtime`. The Ollama chat, stream, and capability adapter lives in `lca-ollama` and is the only type that knows the Ollama HTTP schema. `lca-cli` is the composition root: `lca ask` depends on the trait for streaming and constructs `OllamaModelRuntime` in one place.

```text
lca ask
  -> ModelRuntime
       -> OllamaModelRuntime
       -> future llama.cpp runtime
```

The trait is object-safe through `async_trait`. A successful stream is zero or more `TextDelta` events and exactly one `Completed`. Dropping the stream cancels the request. Missing a terminal frame is an error.

## Consequences

- Runtime contracts contain no Ollama types, URLs, or JSON field names.
- Generation uses one `reqwest` client per runtime. Redirects are disabled, the system proxy is disabled, and a generation is not retried.
- `OllamaModelRuntime::connect` accepts only loopback origins (`127.0.0.0/8`, `::1`, `localhost`). The config loader still accepts other hosts so `lca status` keeps the LCA-01A behavior. Status can still probe a configured remote host. Ask cannot.
- Configuration stays in `[ollama]`. `connect_timeout_secs` was added (default 5). `request_timeout_secs` stays at its existing default of 5 seconds. There is no `[model_runtime]` table and no cloud fallback.
- The health client is not the generation client. Replacing it would have changed LCA-01A timeout and body-limit behavior for no gain.
- A llama.cpp adapter implements the same trait and the same `contract::exercise` cases. The CLI selects it from configuration. The trait, request, response, and error types stay.

## Alternatives not taken

- Putting Ollama JSON types in the runtime crate. That would force every backend to speak Ollama's schema.
- A new application crate for one command. The CLI already is the composition root, and `ask` is the only caller.
- Automatic retries after a dropped connection. The server may already have started the generation.
- Inferring tool calling or JSON mode when the backend did not list them.
