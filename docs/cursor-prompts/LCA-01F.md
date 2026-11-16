# LCA-01F prompt

The milestone was implemented from the brief below. The resulting contracts are recorded in [LCA-01F](../architecture/LCA-01F.md), [LCA-ARCH-06](../architecture/adr/LCA-ARCH-06.md), and [LCA-ARCH-07](../architecture/adr/LCA-ARCH-07.md).

# LCA-01F: Controlled Multi-Turn Agent Loop + JSON-First Protocol Profiles

**Milestone:** LCA-01F
**Architecture Decisions:** LCA-ARCH-06, LCA-ARCH-07
**Branch:** `lca-development`
**Commit-Titel:** `LCA-01F: Controlled Multi-Turn Agent Loop`

## Ziel

Der Agent führt mehrere kontrollierte Modellturns aus.

```text
lca agent execute "<prompt>"
```

Ablauf: Auftrag annehmen, Profil und Protokoll einmal festlegen, Modell aufrufen, Aktionen validieren, zulässige Werkzeuge ausführen, Ergebnisse begrenzt zurückgeben, weitere Turns nur innerhalb des Budgets, bei finaler Antwort oder Fehler oder Budget kontrolliert stoppen.

Keine Shell. Keine automatische Schreibfreigabe. Keine unbegrenzte Autonomie.

## Protokoll

`native`, `json`, und `auto`. `auto` benutzt `ModelProtocolProfile`. Die einzige Namensprüfung ist `resolve_protocol_profile`.

`lca-30b-agent` ist JSON-first, `fallback_eligible = false`, Profilversion 1, Digest leer. Jeder andere Name, auch `lca-30b-agent:latest`, behält die Capability-Regeln.

Das Protokoll gilt für den ganzen Run. Ein Fehler wechselt das Protokoll nicht. `select_protocol` bleibt für `lca tools probe`. `lca agent run` und `lca agent execute` benutzen `select_protocol_with_profile`. `agent run` bleibt ein Modellturn.

## Loop

`BoundedAgentController` bleibt neben `SingleTurnAgentController`. Zustände: `Initialized`, `ModelRequested`, `ModelResponded`, `ValidatingActions`, `ExecutingTools`, `PreparingNextTurn`, `Completed`, `Failed`, `BudgetExhausted`. Terminale Zustände haben keine ausgehende Kante. Jeder Modellrequest reserviert den Turn davor.

Getrennte Budgets, Defaults: 5 Turns, 8 Aktionen pro Turn, 20 Aktionen pro Run, 512 KiB Tool-Result, 1 MiB History, 180 Sekunden. `limits.max_steps` bleibt das Single-Turn-Aktionslimit und wird nicht zum Turn-Budget.

## Conversation

Ein Nachrichtenmodell: System, User, Assistant, Tool Result. JSON-Ergebnisse nutzen den versionierten Contract `lca.tool_result` / `lca.controller_budget`, `contract_version` 1. Dateitext ist `untrusted_data`.

`parse_action_document` akzeptiert weiter nur Protokollversion 1. Der Loop nutzt `parse_agent_document`. Version 2 verlangt `final_answer`, wenn `actions` leer ist, und verbietet es sonst.

## Werkzeuge und Abschluss

Nur `ToolRegistry::workspace`: `list_directory`, `read_file`, `search_files`, `apply_patch` prepare-only. Der ganze Batch wird vor der ersten Ausführung validiert. Ein Tool-Fehler behält frühere Aktionen und stoppt ohne Modell-Recovery. Privacy aus LCA-01E-H1 gilt in jedem Turn.

Ein Prepared Patch beendet den Run. `approve` im Modelltext ist keine Freigabe. Die Approval-Bindung ist prozesslokal. `agent execute` druckt keine Confirmation-Line und keine später einlösbare Freigabe.

Ein erschöpftes Budget erfindet keine finale Antwort.

## CLI

```text
lca agent execute --protocol auto|json|native --max-turns N --max-actions N --output text|json "<prompt>"
```

## Tests und Grenzen

Deterministische Controller-, Zustands- und Sicherheitstests mit einem Fake-`ModelRuntime`. Live-Ollama-Läufe gehören nicht in `cargo test`.

Quality Gates: `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`.
