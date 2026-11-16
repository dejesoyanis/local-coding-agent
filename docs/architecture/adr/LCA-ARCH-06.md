# LCA-ARCH-06: Model-aware protocol selection, JSON-first

- Status: Accepted
- Decision: JSON-first profile, chosen once
- Milestone: LCA-01F

## Context

LCA-01C kept two tool protocols: native tool calls, and a versioned JSON action document. LCA-01E selected between them once per single turn with `select_protocol`. That function looks only at capabilities. When the backend confirms tools, `auto` selects native.

Live samples of the local model `lca-30b-agent` on Ollama 0.40.16, with prompt version `lca-01e-h1.1`, scored JSON 100/100 and native 77/100 on the same read, search, listing, knowledge, and privacy cases. Those numbers are observations of that model. They are not a claim about every model.

A hidden retry (JSON, then native, then JSON again) would spend extra model turns and would hide which protocol the run actually used.

## Decision

Resolve a typed `ModelProtocolProfile` in one place, then choose the protocol once and keep it for the whole run.

1. `resolve_protocol_profile` is the only model-name comparison. The registered identifier is exactly `lca-30b-agent`. Its profile prefers structured JSON, sets `fallback_eligible` to false, and uses profile version 1. The digest is unset. LCA-01F does not verify a digest.
2. Every other identifier, including `lca-30b-agent:latest`, gets the unregistered profile: prefer the existing capability rules, `fallback_eligible` true, version 0.
3. `select_protocol` is unchanged and remains the capability-only function. `lca tools probe` still calls it. `lca agent run` and `lca agent execute` call `select_protocol_with_profile`.
4. An explicit `native` or `json` preference ignores the profile and uses `select_protocol`.
5. `auto` uses `ModelProtocolProfile::preferred`. For the registered model that is JSON, even when native tools are confirmed. If that preference cannot be selected and `fallback_eligible` is false, selection returns the preference's error. It does not switch protocol.
6. `fallback_eligible` applies only during that one selection, before the first generation. A parser error, a transport error, or an empty native `tool_calls` array does not select the other protocol and does not call the model again for a retry.

## Consequences

- `lca agent run` stays one model turn, but its default `auto` for `lca-30b-agent` is now JSON. Callers that need native pass `--protocol native`.
- The probe output for the same model can still say native when tools are confirmed. That is intentional. The probe reports capabilities. The agent applies the profile.
- A registered model whose JSON fallback is disabled fails selection. It is not silently moved to native.
- Adding another model profile means extending `resolve_protocol_profile`. Controllers do not grow new name comparisons.

## Alternatives not taken

- Trying JSON and, on failure, trying native inside the same run.
- Matching model tags, digests, or name prefixes.
- Changing `select_protocol` so the probe starts applying the profile.
- Pinning a model digest in this milestone. The field exists and stays empty.
