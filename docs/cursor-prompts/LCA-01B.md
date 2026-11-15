# LCA-01B: Local Model Runtime & Ollama Adapter

**Projekt:** Local Coding Agent (LCA)
**Architekturentscheidung:** LCA-ARCH-02 = B
**Status:** APPROVED FOR IMPLEMENTATION
**Technologie:** Rust, Tokio, Ollama HTTP API
**Implementierungsstrategie:** Contract-first, test-driven, incremental

---

## 1. Mission

Implementiere eine robuste, vollständig lokale Model Runtime für den bestehenden Rust-basierten Local Coding Agent.

Die Runtime muss verschiedene Inference-Backends über eine gemeinsame Abstraktion unterstützen können.

Implementiere in diesem Milestone ausschliesslich den Ollama-Adapter. Die Architektur muss eine spätere Integration von llama.cpp ermöglichen, ohne dass Agent Core, Application Layer oder CLI grundlegend verändert werden müssen.

**Wichtig:** Arbeite auf dem bestehenden Repository. Untersuche vor jeder Änderung die vorhandene Architektur, Cargo-Workspace-Struktur, Konfigurationsmechanismen, Fehlerbehandlung und Tests.

Bestehende Contracts sind zu respektieren. Vermeide parallele Implementierungen bereits vorhandener Funktionalität.

## 2. Scope

### In Scope

- Backend-unabhängige Runtime-Abstraktion
- Typisierte Request-/Response-Contracts
- Asynchrone Ollama-HTTP-Kommunikation
- Chat-Completions
- Token-Streaming
- Modellidentifikation und Capability-Abfragen
- Konfigurierbare Timeouts
- Strukturierte Fehlerbehandlung
- Cancellation und Ressourcenfreigabe
- CLI-Integration für `lca ask`
- Unit-, Integration- und Contract-Tests
- Dokumentation

### Out of Scope

- Autonome Agent Loops
- Shell- oder Dateisystem-Tool-Ausführung
- Automatisches Modelltraining
- Modell-Downloads oder Modellinstallation
- llama.cpp-Implementierung
- Multi-Agent-Orchestrierung
- Persistente Conversation Memory
- GPU-Scheduling
- Remote-Cloud-Modelle
- Automatisches Ausführen von generiertem Code

Keine dieser Funktionen darf als versteckte Abhängigkeit eingeführt werden.

## 3. Architecture

Verwende eine hexagonale Architektur mit klarer Trennung zwischen Contracts, Application Layer und konkreten Runtime-Adaptern.

Logische Struktur:

```text
LCA CLI
   |
   v
Application Layer
   |
   v
Model Runtime Contract
   |
   +---- Ollama Adapter
   |
   +---- Future llama.cpp Adapter
```

### 3.1 Repository Integration

Analysiere die vorhandenen Crates und integriere die Funktionalität möglichst in die bestehenden Modulgrenzen.

Neue Crates dürfen nur eingeführt werden, wenn dadurch eine tatsächliche architektonische Verbesserung entsteht.

Falls neue Crates erforderlich sind, bevorzuge:

- `lca-model-runtime`: Contracts und Runtime-Datentypen
- `lca-ollama`: Ollama-spezifischer Adapter

Die Namen sind Vorschläge und müssen mit den vorhandenen Workspace-Konventionen abgeglichen werden.

Keine unnötige Umstrukturierung von LCA-01A.

### 3.2 Dependency Direction

Die Runtime-Contracts dürfen keine Ollama-spezifischen Typen enthalten.

Der Ollama-Adapter hängt von den Runtime-Contracts ab.

Der Application Layer hängt ausschliesslich von der Runtime-Abstraktion ab.

Die CLI verwendet den Application Layer beziehungsweise eine vorhandene Composition Root.

Vermeide zyklische Abhängigkeiten.

## 4. Runtime Contract

Definiere eine objekt-sichere, asynchrone Runtime-Schnittstelle.

Verwende bei Bedarf `async_trait` oder eine gleichwertige, technisch begründete Lösung.

Orientiere dich an folgendem konzeptionellen Contract:

```rust
#[async_trait]
pub trait ModelRuntime: Send + Sync {
    async fn generate(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResponse, RuntimeError>;

    async fn generate_stream(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationStream, RuntimeError>;

    async fn capabilities(
        &self,
        model: &str,
    ) -> Result<ModelCapabilities, RuntimeError>;
}
```

Das Beispiel definiert die beabsichtigte Semantik, nicht zwingend die endgültige Rust-Signatur.

### 4.1 Request Contract

`GenerationRequest` soll mindestens enthalten:

- Model Identifier
- Messages
- Optional System Instructions
- Sampling Parameters
- Optional Token Limit
- Optional Request Timeout

Definiere eine typisierte Nachrichtenstruktur:

```rust
pub enum MessageRole {
    System,
    User,
    Assistant,
}
```

Nachrichten besitzen eine Rolle und einen Textinhalt.

Tool Messages und multimodale Inhalte werden noch nicht implementiert.

Berücksichtige Erweiterbarkeit, ohne bereits komplexe Tool-Calling-Contracts einzuführen.

### 4.2 Response Contract

`GenerationResponse` enthält:

- Model Identifier
- Generierten Text
- Optionalen Finish Reason
- Optionales Token Usage
- Optionales Timing Metadata

Optional verfügbare Backend-Metadaten dürfen nicht durch erfundene Werte ersetzt werden.

### 4.3 Runtime Errors

Implementiere eine strukturierte Fehler-Taxonomie.

Mindestens:

```rust
pub enum RuntimeError {
    Connection { /* ... */ },
    Timeout { /* ... */ },
    ModelNotFound { /* ... */ },
    InvalidRequest { /* ... */ },
    BackendFailure { /* ... */ },
    ProtocolViolation { /* ... */ },
    StreamInterrupted { /* ... */ },
}
```

Ergänze weitere Varianten nur bei konkretem Bedarf.

Anforderungen:

- Keine Panics bei erwartbaren Runtime-Fehlern
- Aussagekräftige Fehlerketten
- Keine sensiblen Daten in Logs
- Keine Vermischung von Transport- und Domain-Fehlern
- Kein automatischer Retry für semantisch ungültige Requests

## 5. Ollama Adapter

Implementiere einen HTTP-basierten Adapter für einen lokal laufenden Ollama-Server.

Standard-Endpunkt:

`http://127.0.0.1:11434`

Verwende eine wiederverwendbare HTTP-Client-Instanz, beispielsweise mit `reqwest`.

### 5.1 Generation

Implementiere die Chat-Generierung über die Ollama-API.

Anforderungen:

- Korrekte Request-Serialisierung
- Typisierte Response-Deserialisierung
- Unterstützung mehrerer Nachrichten
- Mapping zwischen Runtime-Rollen und Ollama-Rollen
- Konfigurierbare Sampling-Parameter
- Erkennung fehlender Modelle
- Behandlung nicht erfolgreicher HTTP-Statuscodes
- Begrenzung von Fehlerantwortgrössen

Keine Ollama-spezifischen Felder in den öffentlichen Runtime-Contracts.

### 5.2 Streaming

Implementiere inkrementelles Streaming.

Anforderungen:

1. HTTP-Streaming ohne vollständiges Puffern der Antwort
2. Inkrementelles Parsen von NDJSON
3. Korrekte Behandlung von Chunks, die mitten in einer JSON-Zeile enden
4. Unterstützung mehrerer JSON-Objekte innerhalb eines Transport-Chunks
5. Definierte maximale Grösse eines einzelnen Stream-Frames
6. Erkennung des terminalen `done`-Signals
7. Strukturierte Behandlung fehlerhafter Frames
8. Cancellation durch Drop des Streams
9. Keine unbounded Buffers
10. Keine stillschweigende Umwandlung von Transportfehlern in erfolgreiche Completion

Definiere typisierte Stream-Events, beispielsweise:

```rust
pub enum GenerationEvent {
    TextDelta(String),
    Completed(GenerationMetadata),
}
```

Ein erfolgreicher Stream muss einen eindeutigen terminalen Abschluss besitzen.

Bei vorzeitigem Verbindungsabbruch darf kein erfolgreicher Abschluss gemeldet werden.

### 5.3 Model Capabilities

Implementiere die Abfrage verfügbarer Modellinformationen anhand der tatsächlich unterstützten Ollama-Endpunkte.

Unterscheide zwischen:

- Explizit vom Backend bestätigten Capabilities
- Nicht verfügbaren Informationen
- Unbekannten Capabilities

Erfinde keine Unterstützung für Tool Calling, JSON Mode oder andere Funktionen.

Ein späterer llama.cpp-Adapter muss dieselbe Semantik verwenden können.

### 5.4 Retry Policy

Implementiere keine pauschalen automatischen Retries für Generation Requests.

Begründung: Nach einem Verbindungsabbruch kann unklar sein, ob die Generierung bereits begonnen hat.

Falls bestehende Infrastruktur Retries vorsieht, müssen sie für Generation Requests standardmässig deaktiviert sein.

## 6. Configuration

Integriere die Runtime-Konfiguration in das vorhandene Konfigurationssystem.

Vorgeschlagene logische Konfiguration:

```toml
[model_runtime]
backend = "ollama"
model = "lca-agent"
endpoint = "http://127.0.0.1:11434"
connect_timeout_seconds = 5
request_timeout_seconds = 120
```

Diese Konfiguration ist beispielhaft. Verwende das bestehende Konfigurationsformat und die vorhandenen Namenskonventionen.

Anforderungen:

- Validierung beim Start
- Klare Fehler bei fehlenden Pflichtwerten
- Kein impliziter Cloud-Fallback
- Keine Zugangsdaten in Logs
- Backend-Auswahl über eine zentrale Composition Root
- Kein unnötiges Hardcoding von Modellnamen

### 6.1 Local-Only Security

Standardmässig sind nur lokale Loopback-Endpunkte zulässig.

Externe Endpunkte dürfen nicht unbeabsichtigt durch Konfigurationsänderungen aktiviert werden.

Vermeide automatische Weiterleitungen auf externe Hosts.

Eine spätere explizite Remote-Unterstützung ist nicht Teil dieses Milestones.

## 7. CLI Integration

Implementiere oder erweitere die bestehende CLI um:

```powershell
lca ask "Erkläre mir Rust Ownership"
```

Erwartetes Verhalten:

1. Konfiguration laden
2. Runtime initialisieren
3. Request validieren
4. Ollama aufrufen
5. Textantwort streamen
6. Fehler verständlich ausgeben
7. Korrekten Exit-Code zurückgeben

Optional:

```powershell
lca ask --model lca-agent "Was ist ein Rust Trait?"
```

CLI-Anforderungen:

- Keine unnötige vollständige Antwortpufferung
- Streaming direkt nach stdout
- Diagnostik über stderr
- Keine Debug-Ausgaben im Antworttext
- Definiertes Verhalten bei Ctrl+C
- Kein automatisches Ausführen generierter Befehle
- Keine Schreibzugriffe auf Projektdateien

Falls die bestehende CLI andere Namenskonventionen verwendet, integriere den Befehl konsistent statt eine zweite CLI zu schaffen.

## 8. Testing Strategy

Verwende deterministische Tests ohne Abhängigkeit von einem tatsächlich installierten Sprachmodell.

### 8.1 Unit Tests

Teste mindestens:

- Request-Validierung
- Nachrichten-Rollen
- Parameter-Mapping
- Response-Mapping
- Error-Mapping
- Konfigurationsvalidierung
- Capability-Mapping
- Stream-Frame-Parsing
- Terminale Stream-Zustände

### 8.2 HTTP Integration Tests

Verwende einen lokalen Mock-HTTP-Server.

Teste:

- Erfolgreiche Chat-Generierung
- Fehlendes Modell
- HTTP 400
- HTTP 404
- HTTP 500
- Connection Refused
- Connection Timeout
- Request Timeout
- Fehlerhafte JSON-Response
- Leere Response
- Unterbrochene Streaming-Verbindung
- NDJSON über mehrere Chunks verteilt
- Mehrere Frames pro Chunk
- Fehlendes terminales `done`
- Überschreitung des Frame-Limits

### 8.3 Contract Tests

Erstelle wiederverwendbare Tests gegen die Runtime-Abstraktion.

Mindestens:

- Erfolgreiche Generation
- Korrekte Fehlersemantik
- Korrekte Stream-Reihenfolge
- Terminaler Abschluss
- Cancellation-Verhalten

Diese Tests sollen später auch auf den llama.cpp-Adapter anwendbar sein.

### 8.4 Live Smoke Test

Ein echter Ollama-Smoke-Test darf optional angeboten werden.

Er darf nicht Bestandteil der verpflichtenden CI-Tests sein.

Fehlende Modellgewichte oder ein nicht laufender Ollama-Server dürfen die normalen Tests nicht scheitern lassen.

## 9. Implementation Strategy

Arbeite inkrementell in folgender Reihenfolge.

**Phase A – Repository Reconnaissance**

- Workspace analysieren
- Bestehende Contracts identifizieren
- Bestehende CLI und Konfiguration prüfen
- Integrationspunkte dokumentieren

**Phase B – Runtime Domain**

- Typisierte Requests
- Responses
- Events
- Errors
- Runtime Trait

**Phase C – Ollama Adapter**

- HTTP Client
- Serialisierung
- Fehlerbehandlung
- Non-Streaming Generation
- Streaming Parser
- Capability Mapping

**Phase D – Application Integration**

- Runtime Factory
- Konfiguration
- CLI
- Cancellation

**Phase E – Verification**

- Unit Tests
- Mock HTTP Tests
- Contract Tests
- Clippy
- Formatting
- Dokumentation

Keine Phase überspringen.

Falls eine Architekturabweichung notwendig ist, dokumentiere sie ausdrücklich.

## 10. Acceptance Criteria

| ID | Criterion | Required |
|---|---|---|
| AC-01 | Runtime Contract unabhängig von Ollama | PASS |
| AC-02 | Ollama Adapter implementiert | PASS |
| AC-03 | Non-Streaming Generation funktioniert | PASS |
| AC-04 | Streaming verarbeitet NDJSON korrekt | PASS |
| AC-05 | Stream-Abbruch wird erkannt | PASS |
| AC-06 | Strukturierte Runtime Errors | PASS |
| AC-07 | Timeouts und Cancellation funktionieren | PASS |
| AC-08 | Konfiguration validiert | PASS |
| AC-09 | `lca ask` integriert | PASS |
| AC-10 | Mock-HTTP-Tests bestehen | PASS |
| AC-11 | Runtime Contract Tests bestehen | PASS |
| AC-12 | Keine Cloud-Abhängigkeit erforderlich | PASS |
| AC-13 | Bestehende LCA-01A-Tests bestehen | PASS |
| AC-14 | Dokumentation aktualisiert | PASS |
| AC-15 | Keine autonomen Tools implementiert | PASS |

Zusätzliche Quality Gates:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Alle Befehle müssen mit Exit Code 0 abschliessen.

Keine Warnungen ignorieren oder Tests deaktivieren, um Gates künstlich zu bestehen.

## 11. Documentation

Dokumentiere mindestens:

- Runtime-Architektur
- Öffentliche Contracts
- Ollama-Adapter
- Konfiguration
- Streaming-Protokoll
- Fehlersemantik
- Sicherheitsgrenzen
- CLI-Beispiele
- Teststrategie
- Bekannte Einschränkungen
- Erweiterungspfad für llama.cpp

Erstelle oder aktualisiere eine Architecture Decision Record für `LCA-ARCH-02`.

## 12. Repository & Commit Rules

Vor der Implementierung:

1. Git-Status prüfen.
2. Aktuellen Branch prüfen.
3. Bestehende Änderungen identifizieren.
4. Keine fremden Änderungen überschreiben.

Speichere diesen Prompt als Markdown-Datei im vorhandenen Prompt-Dokumentationsverzeichnis. Falls keines existiert, verwende:

`docs/cursor-prompts/LCA-01B.md`

Nach erfolgreicher Implementierung:

1. Alle Acceptance Criteria verifizieren.
2. Git-Diff prüfen.
3. Keine Secrets oder temporären Artefakte aufnehmen.
4. Nur zu LCA-01B gehörende Änderungen stagen.
5. Einen Commit erstellen:

`LCA-01B: Local Model Runtime and Ollama Adapter`

Keinen Force Push durchführen.

Bei nicht bestandenen Quality Gates keinen erfolgreichen Abschluss behaupten.

## 13. Final Report

Erstelle einen strukturierten Abschlussbericht mit:

1. **Executive Summary**
2. **Implementierte Architektur**
3. **Neue und geänderte Dateien**
4. **Runtime Contract**
5. **Ollama Adapter**
6. **Streaming-Implementierung**
7. **Fehlerbehandlung**
8. **Konfiguration und CLI**
9. **Testergebnisse mit konkreten Zahlen**
10. **Acceptance Criteria (PASS/FAIL/PARTIAL)**
11. **Bekannte Einschränkungen**
12. **Git Commit Hash**
13. **Empfohlener nächster Milestone**

Verwende ausschliesslich tatsächlich gemessene Ergebnisse.

**Completion Rule:** LCA-01B gilt nur als COMPLETE, wenn sämtliche verpflichtenden Acceptance Criteria und Quality Gates bestanden sind. Andernfalls lautet das Urteil PARTIAL oder FAILED mit dokumentierten Ursachen.
