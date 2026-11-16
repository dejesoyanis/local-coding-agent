# LCA-ARCH-05-H1: Reliability and privacy hardening

- Status: Accepted
- Decision: Keep single-turn dispatch. Add a diagnostic response class and a name-based privacy boundary. Do not parse text into tool calls.
- Milestone: LCA-01E-H1
- Extends: [LCA-ARCH-05](LCA-ARCH-05.md)

## Context

LCA-01E already connects one local model turn to the workspace registry and the dispatcher. Live probes of `lca-30b-agent` on Ollama 0.40.16 showed two separate problems.

The native search prompt sometimes came back as XML-shaped text in `message.content`, with an empty `tool_calls` array. The controller correctly executed nothing. A general-knowledge prompt sometimes called `list_directory` anyway, and that listing included `lca.toml` and `opencode.json`.

An agent loop, an automatic write, or a shell is still out of scope. Parsing the leaked XML on the client would hide a parser bug and would execute text the protocol does not treat as a call.

## Decision

1. Native calls stay exclusively in `GenerationResponse::tool_calls`. JSON calls stay exclusively in `parse_action_document`. XML, Markdown, and JSON text in native mode stay text. A bad response does not retry and does not switch protocol.
2. `classify_response` labels a successful turn `native_tool_call`, `plain_text`, `pseudo_tool_call_text`, or `invalid_native_response`. The label is diagnostic. A pseudo label still means zero actions.
3. The single-turn system prompt tells the model to use the attached tool interface, to answer general knowledge in text, and not to emit calls as XML, Markdown, or pseudocode. The prompt is not a security control. Prompt version `lca-01e-h1.1` is metadata for evaluation.
4. `PrivacyPolicy` lives on `WorkspaceSandbox`. The baseline names are mandatory. `[tools] privacy_excludes` can only add patterns. An invalid pattern fails configuration. `deny_overrides` returns the first denial, so a later allow cannot cancel privacy, the sandbox, a disabled tool, or the approval boundary.
5. `list_directory`, `read_file`, `search_files`, and `apply_patch` consult the policy before content access. Listings omit protected names and do not report how many were omitted. Search skips protected files and directories. Explicit access returns `privacy_denied` with the fixed text `access to a protected workspace path was denied`.
6. `lca eval tools` repeats the fixed read-only cases. It forces `write_enabled = false`, does not call `commit_prepared`, and writes a JSON report. The default path is `target/lca-eval/tool-selection.json`. Mock and live runs are labeled by the caller. A sample is a new turn, not a retry.

## Consequences

- A registered, in-workspace, schema-valid `read_file` of `lca.toml` is still denied.
- `.env.example`, `.env.sample`, `.env.template`, and `.env.dist` are readable unless a protected parent covers them. Other `.env.*` names are protected.
- Name matching is not file identity. A hard link under another name remains readable. Check-then-open races, incomplete handle-based Windows checks, missing NTFS file identity, and a verify failure after rename without rollback stay open from LCA-01D. This milestone does not claim to have closed them.
- The qwen3-coder parser in Ollama 0.40.16 only starts a tool call on a literal `<tool_call>`. A bare `<function=...>` block is content. This client does not repair that. Upgrading Ollama, or lowering the model temperature, is an LCA-01F option, not a parser change here.
- One successful live sample is not a reliability rate. `lca eval tools --runs 20` was not executed for this milestone.

## Alternatives not taken

- Client-side parsing of `<function=` / `<tool_call>` text into executable calls.
- Falling back from native mode to the JSON document when `tool_calls` is empty.
- A second `generate` when the text looks like a call.
- Changing `models/ollama/Modelfile-30b-agent` or sending a temperature in the HTTP request.
- Disabling the baseline through configuration.
- Treating hardlink aliases as solved without a file-identity check.
