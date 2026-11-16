# LCA-01C prompt

The milestone was implemented from the prompt below.

# LCA-01C: Hybrid Structured Tool Calling

## 1. Projektkontext

**Projektverzeichnis:** `C:\Users\mifur\dev\cursor\local-coding-agent`

**Branch:** `lca-development`

**Ausgangscommit:** `44b1f128fdda5980a7bbfc190618889956d1cb6a`

**Plattform:** Windows, PowerShell 5.1

**Sprache:** Rust, Edition 2024

**Architekturentscheidung:** LCA-ARCH-03, Variante C – Hybrid Structured Tool Calling.

### Bestehende Architektur

- `lca-core`: Agent Domain, Lifecycle und Tasks
- `lca-config`: Konfiguration und Workspace-Validierung
- `lca-model-runtime`: Backendneutraler ModelRuntime-Contract
- `lca-ollama`: Ollama-Adapter und Streaming
- `lca-tools`: Tool-Abstraktionen und RejectingToolExecutor
- `lca-cli`: CLI und Composition Root

LCA-01B implementierte bereits Textgenerierung, NDJSON-Streaming, Capability Discovery und `lca ask`.

**Bestehende APIs und Tests müssen erhalten bleiben.**

## 2. Ziel

Implementiere eine sichere, backendneutrale Architektur zur Generierung, Normalisierung und Validierung strukturierter Werkzeugaufrufe.

Unterstütze zwei Protokolle:

**A. Native Tool Calling**

Ollama liefert native `tool_calls` über `/api/chat`.

**B. Structured JSON Fallback**

Das Modell liefert ein strikt definiertes JSON-Dokument, das anschliessend in dasselbe interne Aktionsmodell überführt wird.

Beide Protokolle müssen dieselbe Rust-Validierungs- und Policy-Grenze durchlaufen.

**Nicht Bestandteil dieses Meilensteins:** tatsächliche Werkzeugausführung, autonome Dateiänderungen, Shell-Kommandos und Agent-Loops.

## 3. Implementierungsstrategie

Arbeite in folgender Reihenfolge:

1. Bestehende Architektur, Runtime-Verträge, Tool-Typen und Tests untersuchen.
2. ADR LCA-ARCH-03 dokumentieren.
3. Kanonisches Aktionsmodell entwerfen.
4. Tool Registry und Schemas implementieren.
5. Native Tool Calling in ModelRuntime und Ollama integrieren.
6. JSON-Fallback implementieren.
7. Protokollauswahl und Capability Handling implementieren.
8. Validierungs- und Policy-Grenze implementieren.
9. CLI-Diagnose integrieren.
10. Tests, Dokumentation und Qualitätsprüfungen ausführen.

Vermeide unnötige API-Brüche. Begründe jede Änderung an bestehenden Contracts.

## 4. Kanonisches Aktionsmodell

Implementiere geeignete Rust-Typen für:

- `AgentAction`
- `ActionId`
- `ToolCall`
- `ToolArguments`
- `ActionSource`
- `ActionValidationError`
- `ValidatedAction`
- `ToolCallBatch`

Die Namen sind Vorschläge. Bestehende gleichwertige Typen sollen bevorzugt wiederverwendet werden.

### Anforderungen

Jede Aktion enthält mindestens:

- Eine vom Controller erzeugte eindeutige Action-ID
- Den kanonischen Tool-Namen
- Typisierte beziehungsweise validierbare Argumente
- Die Herkunft: Native oder JSON
- Den Validierungsstatus

Die Action-ID darf nicht unkontrolliert aus Modelltext übernommen werden.

Eine Modellantwort kann mehrere Aktionen enthalten.

Die Reihenfolge muss erhalten bleiben.

Eine Aktion darf nicht durch blosse Deserialisierung als autorisiert gelten.

`ValidatedAction` darf nur durch den vertrauenswürdigen Validator erzeugt werden.

## 5. Tool Registry

Implementiere eine explizite Registry bekannter Werkzeuge.

Jeder Eintrag enthält:

- Eindeutigen Namen
- Beschreibung
- JSON-Schema der Argumente
- Berechtigungskategorie
- Kennzeichnung für lesende oder mutierende Aktionen
- Optionale Argument- und Grössenlimits

Registriere für diesen Meilenstein ausschliesslich harmlose Diagnosewerkzeuge.

Beispiel:

`diagnostic_echo`

Argumente:

```json
{
  "message": "hello"
}
```

Das Werkzeug wird nicht ausgeführt.

Die Registry dient nur der Definition und Validierung.

Unbekannte Werkzeugnamen werden abgelehnt.

Tool-Namen müssen exakt übereinstimmen.

## 6. Native Ollama Tool Calling

Erweitere `lca-model-runtime` und `lca-ollama` um strukturierte Tool Calls.

### Anforderungen

- Native Tool-Definitionen im Ollama-Request.
- Native `tool_calls` im Ollama-Response.
- Mehrere Tool Calls pro Antwort.
- Erhaltung der Reihenfolge.
- Keine Interpretation von textuellen Pseudo-Tool-Calls.
- Keine Ausführung durch den Adapter.

Die bestehende `generate`-API soll möglichst kompatibel bleiben.

Erweitere Request-/Response-Typen kontrolliert.

Verwende für Argumente `serde_json::Value` oder eine gleichwertige verlustfreie JSON-Repräsentation.

Keine unkontrollierte Umwandlung von JSON-Werten in Strings.

### Streaming

Prüfe, wie die eingesetzte Ollama-Version Tool Calls bei Streaming tatsächlich serialisiert.

Implementiere nur nachweislich unterstützte Streaming-Semantik.

Für den ersten Tool-Calling-Meilenstein ist Non-Streaming zulässig und vorzuziehen, wenn dadurch vollständige Tool-Call-Aggregation zuverlässig möglich ist.

Bestehendes Text-Streaming muss weiterhin funktionieren.

## 7. Structured JSON Fallback

Definiere ein versioniertes JSON-Aktionsprotokoll.

Beispiel:

```json
{
  "protocol_version": 1,
  "actions": [
    {
      "tool": "diagnostic_echo",
      "arguments": {
        "message": "hello"
      }
    }
  ]
}
```

### Anforderungen

- Striktes JSON.
- Explizite Protokollversion.
- Begrenzte maximale Dokumentgrösse.
- Begrenzte Anzahl Aktionen.
- Keine zusätzlichen unbekannten Felder im Protokoll-Envelope.
- Keine Markdown-Codeblöcke.
- Keine Extraktion von JSON aus beliebigem Fliesstext.
- Keine automatische Reparatur fehlerhafter JSON-Dokumente.
- Keine automatische Umdeutung gewöhnlicher Textantworten.

Der Fallback darf ausschliesslich verwendet werden, wenn der Controller den JSON-Modus explizit angefordert hat.

Fehlerhafte JSON-Antworten ergeben einen typisierten Fehler.

## 8. Protokollauswahl

Implementiere einen expliziten Modus:

- `Native`
- `StructuredJson`
- `Auto`

### Native

Nur zulässig, wenn Native Tool Calling vom Backend bestätigt unterstützt wird.

### StructuredJson

Nur zulässig, wenn der Adapter einen verlässlichen strukturierten Ausgabemodus unterstützt oder die Antwort strikt validiert werden kann.

Fehlende garantierte JSON-Unterstützung muss dokumentiert werden. Eine syntaktisch validierte Antwort ist keine Garantie, dass das Modell JSON zuverlässig erzeugt.

### Auto

Bevorzuge bestätigtes Native Tool Calling.

Wenn Native nicht bestätigt ist, wähle einen ausdrücklich zugelassenen JSON-Fallback.

Unbekannte Capabilities dürfen nicht stillschweigend als unterstützt interpretiert werden.

Falls kein zulässiges Protokoll verfügbar ist, gib einen typisierten Fehler zurück.

Kein automatischer Protokollwechsel nach einem fehlerhaften Modelloutput.

## 9. Validierung und Sicherheit

Implementiere eine zentrale Validierungsgrenze.

Prüfe:

1. Tool existiert in der Registry.
2. Argumente sind gültiges JSON.
3. Argumente erfüllen das definierte Schema.
4. Erforderliche Felder sind vorhanden.
5. Datentypen stimmen.
6. Unbekannte Felder werden gemäss Schema abgelehnt.
7. Grössenlimits werden eingehalten.
8. Anzahl der Aktionen ist begrenzt.
9. Policy erlaubt die vorgeschlagene Aktion grundsätzlich.
10. Jede Aktion erhält eine eindeutige Controller-ID.

### Sicherheitsinvarianten

- Modelloutput ist grundsätzlich nicht vertrauenswürdig.
- Keine Werkzeugausführung während der Validierung.
- Keine Dateisystemänderungen.
- Keine Prozessausführung.
- Keine automatischen Worktrees.
- Keine Workspace-Verschiebung.
- Keine impliziten Berechtigungen.
- Keine Freigabe unbekannter Aktionen.
- Keine Interpretation von `<tool_call>`, `<function=...>` oder ähnlichen Textmustern als ausführbare Aktionen.

Validierung und Autorisierung müssen konzeptionell getrennt bleiben.

## 10. Batch-Semantik

Eine Antwort kann mehrere Tool Calls enthalten.

Definiere eine deterministische Batch-Validierung.

Standardverhalten:

**Fail-Closed für den gesamten Batch.**

Wenn eine Aktion ungültig ist, darf der Batch nicht als vollständig validiert gelten.

Keine teilweise Freigabe durch implizites Überspringen fehlerhafter Aktionen.

Dokumentiere die Entscheidung.

## 11. CLI-Diagnose

Erweitere die CLI um:

```text
lca tools probe
```

Der Befehl soll:

1. Die konfigurierte lokale Modellruntime laden.
2. Backend-Capabilities prüfen.
3. Das geeignete Protokoll auswählen.
4. Das Modell zur Verwendung von `diagnostic_echo` auffordern.
5. Die strukturierte Antwort normalisieren.
6. Die Aktion validieren.
7. Das Ergebnis anzeigen.

Beispiel:

```text
protocol: native
tool: diagnostic_echo
validation: passed
execution: disabled
```

Keine Ausführung.

Falls das Modell keine Aktion erzeugt, darf dies nicht als erfolgreicher Tool-Calling-Test gelten.

### CLI-Optionen

Unterstütze nach Möglichkeit:

```text
lca tools probe --protocol native
lca tools probe --protocol json
lca tools probe --protocol auto
```

Ungültige Modi müssen abgelehnt werden.

Die bestehende `lca ask`-Funktion bleibt unverändert nutzbar.

## 12. Tests

Tests müssen ohne laufenden Ollama-Server ausführbar sein.

### Native Tool Calling

- Ein gültiger Tool Call
- Mehrere gültige Tool Calls
- Leere Tool-Call-Liste
- Unbekannter Tool-Name
- Fehlende Argumente
- Falsche Argumenttypen
- Fehlerhafte native Response
- Text mit gefälschtem Tool-Call-Marker

### JSON-Fallback

- Gültiges JSON
- Ungültiges JSON
- Fehlende Protokollversion
- Unbekannte Protokollversion
- Zusätzliche Envelope-Felder
- Markdown-Codeblock statt JSON
- Mehrere Aktionen
- Überschrittene Grössenlimits
- Gewöhnlicher Antworttext statt JSON

### Policy und Validation

- Unbekannte Werkzeuge werden abgelehnt.
- Mutierende Aktionen werden nicht implizit freigegeben.
- Batch-Validierung ist atomar bezüglich des Validierungsresultats.
- Controller-generierte IDs sind eindeutig.
- Validierung ruft keinen ToolExecutor auf.
- Keine Modellantwort kann unmittelbar Dateisystem- oder Shell-Aktionen auslösen.

### Regression

- Bestehende LCA-01A-Tests bestehen.
- Bestehende LCA-01B-Tests bestehen.
- `lca ask` funktioniert weiterhin.
- Bestehendes NDJSON-Streaming funktioniert weiterhin.

### Optionaler Live-Test

Ein echter Ollama-Test darf nur ausdrücklich aktiviert werden.

Beispielsweise:

```powershell
$env:LCA_OLLAMA_SMOKE = "1"
cargo test --workspace
```

Live-Tests dürfen nicht Voraussetzung für normale Unit-Tests sein.

## 13. Dokumentation

Erstelle:

`docs/architecture/LCA-01C.md`

`docs/architecture/adr/LCA-ARCH-03.md`

`docs/cursor-prompts/LCA-01C.md`

Dokumentiere:

- Architektur und Datenfluss
- Native Tool Calling
- JSON-Fallback
- Capability-basierte Protokollauswahl
- Canonical Action Model
- Registry und Schemas
- Validation Boundary
- Batch-Semantik
- Sicherheitsinvarianten
- Fehlerbehandlung
- CLI-Diagnose
- Bekannte Einschränkungen
- Später geplante Werkzeugausführung

Speichere diesen vollständigen Prompt in der Prompt-Dokumentation.

## 14. Qualitätsprüfungen

Führe aus:

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Alle Befehle müssen Exit-Code 0 liefern.

Bei Fehlern: Ursache beheben und erneut prüfen.

Keine erfundenen Testergebnisse.

## 15. Acceptance Criteria

| ID | Kriterium |
|---|---|
| AC-01 | Kanonisches AgentAction-Modell implementiert |
| AC-02 | Native Ollama Tool Calls unterstützt |
| AC-03 | Mehrere Tool Calls korrekt verarbeitet |
| AC-04 | Strikter JSON-Fallback implementiert |
| AC-05 | Explizite Protokollauswahl funktioniert |
| AC-06 | Capability Handling ist Fail-Closed |
| AC-07 | Tool Registry und Schemas funktionieren |
| AC-08 | Ungültige Aktionen werden abgelehnt |
| AC-09 | Batch-Validierung ist deterministisch |
| AC-10 | Keine Werkzeugausführung möglich |
| AC-11 | CLI-Probe funktioniert mit Mock-Backend |
| AC-12 | Bestehende LCA-01A/B-Funktionen bleiben erhalten |
| AC-13 | Tests und Quality Gates bestehen |
| AC-14 | Architektur und ADR dokumentiert |
| AC-15 | Live-Test kann optional ausgeführt werden |

## 16. Abschlussbericht

Liefere:

1. Executive Summary
2. Implementierte Architektur
3. Neue und geänderte Dateien
4. Technische Entscheidungen
5. Native Tool Calling
6. JSON-Fallback
7. Validation und Policy
8. CLI-Verhalten
9. Testergebnisse mit tatsächlichen Exit-Codes
10. Acceptance Criteria mit PASS/FAIL
11. Bekannte Einschränkungen
12. Git-Commit-Hash
13. Empfehlung für den nächsten Meilenstein

## 17. Git

Arbeite auf `lca-development`.

Verändere keine unbeteiligten Dateien.

Insbesondere dürfen `lca-test`, `opencode.json` und vorhandene Modelfiles nicht ungefragt geändert werden.

Erstelle keine Worktrees.

Verwende keine PowerShell-5.1-inkompatiblen `&&`-Befehle.

Nach erfolgreicher Implementierung und bestandenen Qualitätsprüfungen:

**Commit:**

`LCA-01C: Hybrid Structured Tool Calling`

Nicht automatisch pushen.

Falls ein Acceptance Criterion nicht erfüllt ist, melde dies ausdrücklich und behaupte keinen vollständigen Erfolg.
