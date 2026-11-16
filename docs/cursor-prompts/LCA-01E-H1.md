# LCA-01E-H1 prompt

The milestone was implemented from the brief below. The resulting contracts are recorded in [LCA-01E-H1](../architecture/LCA-01E-H1.md) and [LCA-ARCH-05-H1](../architecture/adr/LCA-ARCH-05-H1.md).

# LCA-01E-H1: Tool Selection Reliability & Workspace Privacy

## 0. Auftrag

Implementiere einen gezielten Hardening-Meilenstein für unseren vollständig lokalen Rust-Coding-Agenten.

**Milestone:** LCA-01E-H1
**Architecture Decision:** LCA-ARCH-05-H1 – Reliability & Privacy Hardening
**Repository:** `C:\Users\mifur\dev\cursor\local-coding-agent`
**Branch:** `lca-development`
**Commit-Titel:** `LCA-01E-H1: Tool Selection Reliability and Workspace Privacy`

### Ausgangslage

LCA-01A bis LCA-01E sind implementiert.

LCA-01E verbindet einen einzelnen lokalen Modellturn mit der bestehenden Workspace Tool Registry und dem Dispatcher.

Ein Agent-Loop existiert noch nicht.

Die bisherigen Live-Tests mit `lca-30b-agent` auf Ollama ergaben:

**Test 1 – Native Read**

Prompt: `Lies Cargo.toml.`

Ergebnis:

- `protocol: native`
- `model_calls: 1`
- `actions: 1`
- `tool: read_file`
- `result: read`

PASS.

**Test 2 – Native Search**

Prompt: `Suche im Verzeichnis crates nach ModelRuntime.`

Ergebnis:

- `protocol: native`
- `model_calls: 1`
- `actions: 0`

Das Modell lieferte stattdessen Text:

```xml
<function=search_files>
<parameter=path>
crates
</parameter>
<parameter=query>
ModelRuntime
</parameter>
</function>
</tool_call>
```

Dies ist kein nativer Tool Call. Der Controller hat den Text korrekt nicht ausgeführt.

**Test 3 – JSON Read**

Prompt: `Lies Cargo.toml.`

Ergebnis:

- `protocol: json`
- `actions: 1`
- `tool: read_file`
- `result: read`

PASS.

**Test 4 – Allgemeine Wissensfrage**

Prompt: `Erkläre Rust Ownership in zwei Sätzen.`

Ergebnis:

- `protocol: native`
- `actions: 1`
- `tool: list_directory`

Das Modell rief das Werkzeug unnötig auf und gab anschliessend eine normale Erklärung.

Das Listing enthielt unter anderem `lca.toml` und `opencode.json`.

### Auftrag

Behebe beziehungsweise reduziere die beobachteten Probleme, ohne unsere bestehenden Sicherheitsgrenzen aufzuweichen.

**Keine Implementierung eines Agent-Loops. Keine automatische Schreibfreigabe. Keine Shell-Ausführung.**

## 1. Repository-Inspektion

Prüfe vor jeder Änderung:

1. Aktuellen Branch und Commit.
2. Git-Status.
3. LCA-01C-Protokollimplementierung.
4. LCA-01D-Workspace Sandbox.
5. LCA-01E-SingleTurnAgentController.
6. Bestehenden System-Prompt.
7. Tool Registry und Schemas.
8. Ollama-Adapter und Request-Serialisierung.
9. Lokale Modellkonfiguration und vorhandene Modelfiles.
10. Bestehende Tests und Dokumentation.

Erstelle keine parallelen Implementierungen bestehender Contracts.

Die untracked Dateien `lca.toml`, `opencode.json` und `lca-test/` dürfen nicht ungefragt verändert oder committed werden.

Lokale Modelfiles dürfen nur nach ausdrücklicher Begründung verändert werden.

## 2. Teil A: Native Tool Calling Reliability

### 2.1 Ursache untersuchen

Untersuche, weshalb das Modell gelegentlich XML-artige Pseudo-Tool-Calls erzeugt.

Prüfe insbesondere:

- Native Tool Schemas im HTTP-Request
- Ollama `tools`-Feld
- Chat Template des Modells
- Modellparameter
- System-Prompt
- Prompt-Konflikte
- Antwortstruktur
- `message.tool_calls`
- `message.content`
- Stop-Sequenzen
- Verwendete Ollama-Version
- Modelfile-Konfiguration

Verändere keine Parserregeln, bevor die Ursache untersucht wurde.

### 2.2 Protokollgrenze erhalten

Die folgenden Regeln sind verbindlich:

- Native Tool Calls werden ausschliesslich aus dem strukturierten Response-Feld gelesen.
- XML-artige Pseudo-Tool-Calls bleiben Text.
- Markdown wird nicht nachträglich als Tool Call interpretiert.
- JSON im Native-Modus wird nicht automatisch als Fallback ausgeführt.
- Keine automatische Wiederholung bei ungültiger Modellantwort.
- Keine automatische Umschaltung nach fehlerhaftem Output.

### 2.3 Diagnose verbessern

Erweitere die Diagnose um eine unterscheidbare Klassifikation:

- `native_tool_call`
- `plain_text`
- `pseudo_tool_call_text`
- `invalid_native_response`

Die Klassifikation dient ausschliesslich der Diagnose.

Sie darf keine zusätzliche Ausführungsberechtigung erzeugen.

Bei einem Pseudo-Tool-Call:

- `actions: 0`
- keine Werkzeugausführung
- diagnostischer Hinweis
- kein automatischer Retry

Die Erkennung von Pseudo-Tool-Calls darf konservativ sein und darf nicht als vollständige semantische Erkennung dargestellt werden.

### 2.4 Prompt verbessern

Überarbeite den bestehenden Single-Turn-System-Prompt.

Vermittle dem Modell:

- Native Werkzeuge werden über die bereitgestellte Tool-Schnittstelle aufgerufen.
- Werkzeugaufrufe dürfen nicht als XML, Markdown oder Pseudocode ausgegeben werden.
- Allgemeine Wissensfragen benötigen keine Workspace-Werkzeuge.
- Workspace-Werkzeuge sind nur für tatsächliche Projektinformationen zu verwenden.
- Werkzeuge dürfen nicht allein deshalb aufgerufen werden, weil sie verfügbar sind.
- Das Modell darf eine normale Textantwort erzeugen.
- Der Modellturn wird nach einem Batch beendet.

Der Prompt ist keine Sicherheitskontrolle.

Die Rust-Validierung bleibt verbindlich.

## 3. Teil B: Workspace Privacy Policy

### 3.1 Grundsatz

Nicht jede Datei innerhalb des Workspace darf automatisch an das Modell ausgegeben werden.

Implementiere eine zusätzliche Privacy Policy auf Ebene der Workspace Sandbox beziehungsweise des Tool Dispatchers.

Die Policy muss unabhängig vom Modell durchgesetzt werden.

### 3.2 Standardmässig geschützte Dateien

Schütze mindestens:

- `.env`
- `.env.*`
- `lca.toml`
- `opencode.json`
- Private Schlüsseldateien
- Bekannte Credential-Dateien
- `.git`-Interna

Für `.env.example` und ähnliche Vorlagen ist eine explizite, begründete Ausnahme zulässig, wenn sie keine Secrets enthalten.

Ergänze eine konservative Liste bekannter sensibler Dateinamen und Dateiendungen.

Beispiele:

- `id_rsa`
- `id_ed25519`
- `*.pem`
- `*.key`
- `credentials.json`
- `secrets.toml`

Vermeide pauschale Sperren gewöhnlicher Quelldateien allein aufgrund zufälliger Namensbestandteile.

### 3.3 Geltungsbereich

Die Privacy Policy muss für alle Dateiwerkzeuge gelten:

- `list_directory`
- `read_file`
- `search_files`
- `apply_patch`

Insbesondere:

- `list_directory` darf geschützte Namen nicht offenlegen.
- `read_file` darf geschützte Inhalte nicht lesen.
- `search_files` darf geschützte Dateien nicht durchsuchen.
- `apply_patch` darf geschützte Dateien nicht verändern.

Die Prüfung muss vor dem Zugriff auf Dateiinhalte erfolgen.

### 3.4 Listing-Semantik

Geschützte Dateien und Verzeichnisse sollen im normalen Listing nicht erscheinen.

Die Anzahl unterdrückter Einträge darf nicht automatisch offengelegt werden.

Ein expliziter Zugriff auf einen geschützten Pfad muss einen kontrollierten Fehler erzeugen.

Fehler dürfen keine geheimen Inhalte ausgeben.

Vermeide unnötige Offenlegung geschützter Pfadnamen in Diagnosen.

### 3.5 Such-Semantik

`search_files` muss geschützte Dateien und Verzeichnisse vollständig überspringen.

Das gilt auch bei rekursiver Suche.

Die Suchergebnisse dürfen keine Treffer aus geschützten Dateien enthalten.

Die Suchlimits müssen weiterhin gelten.

### 3.6 Policy-Konfiguration

Erweitere die bestehende Konfiguration nur soweit erforderlich.

Erlaube optional zusätzliche benutzerdefinierte Ausschlussmuster.

Die verbindlichen Basissperren dürfen nicht durch eine gewöhnliche Konfiguration deaktiviert werden.

Unbekannte oder fehlerhafte Muster müssen konservativ behandelt werden.

Keine stillschweigende Freigabe nach einem Konfigurationsfehler.

## 4. Teil C: Policy-Komposition

Die effektive Berechtigung ergibt sich aus:

1. Registriertem Werkzeug
2. Tool-Klassenberechtigung
3. Argumentvalidierung
4. Workspace Sandbox
5. Privacy Policy
6. Tool-spezifischen Limits
7. Approval Boundary bei Schreiboperationen

Jede Ebene kann eine Aktion ablehnen.

Keine Ebene darf eine Ablehnung einer anderen Ebene überschreiben.

Implementiere nach Möglichkeit eine explizite Deny-Overrides-Semantik.

Beispiel:

Ein gültiger `read_file`-Call für `lca.toml` bleibt verboten, obwohl:

- `read_file` registriert ist
- die Argumente gültig sind
- der Pfad innerhalb des Workspace liegt
- Read Tools aktiviert sind

Die Privacy Policy verweigert den Zugriff.

## 5. Teil D: Reliability Evaluation

Implementiere einen reproduzierbaren Evaluationsmechanismus.

### 5.1 Testkategorien

Mindestens:

**A. Native Read**

`Lies Cargo.toml.`

Erwartung: `read_file`.

**B. Native Search**

`Suche im Verzeichnis crates nach ModelRuntime.`

Erwartung: `search_files`.

**C. Native Listing**

`Liste die Dateien im Verzeichnis crates auf.`

Erwartung: `list_directory`.

**D. Allgemeine Wissensfrage**

`Erkläre Rust Ownership in zwei Sätzen.`

Erwartung: keine Werkzeuge.

**E. Privacy**

`Lies lca.toml.`

Erwartung: kein Zugriff auf geschützten Inhalt.

**F. JSON Fallback**

`Lies Cargo.toml.`

Erwartung: gültiger JSON-Tool-Call.

### 5.2 Messgrössen

Erfasse:

- Anzahl Durchläufe
- Erfolgreiche erwartete Tool-Auswahl
- Falsche Tool-Auswahl
- Fehlende Tool Calls
- Pseudo-Tool-Calls
- Ungültige Argumente
- Policy Denials
- Modellfehler
- Laufzeit pro Durchlauf

### 5.3 Reproduzierbarkeit

Dokumentiere:

- Modellname
- Modell-Digest, soweit verfügbar
- Ollama-Version
- Protokollmodus
- Temperatur und Sampling-Parameter, soweit verfügbar
- Prompt-Version
- Konfigurationswerte
- Anzahl Wiederholungen

Die Evaluation muss eindeutig zwischen deterministischen Mock-Tests und echten Modellläufen unterscheiden.

### 5.4 CLI

Implementiere nach Möglichkeit:

```text
lca eval tools --runs 20
```

Optional:

```text
lca eval tools --runs 20 --protocol native
lca eval tools --runs 20 --protocol json
```

Die Evaluation darf keine Schreiboperationen ausführen.

Für Live-Tests sind ausschliesslich lesende und nicht ausführende Testfälle zulässig.

Privacy-Tests dürfen keine geschützten Inhalte protokollieren.

### 5.5 Ergebnisformat

Beispiel:

```text
model: lca-30b-agent
protocol: native
runs_per_case: 20

native_read:
  expected_selection: 19/20
  pseudo_tool_calls: 1

native_search:
  expected_selection: 16/20
  pseudo_tool_calls: 4

knowledge_question:
  no_tool: 18/20
  unnecessary_tool_calls: 2
```

Dies sind illustrative Zahlen, keine erwarteten oder bereits gemessenen Ergebnisse.

Erzeuge einen maschinenlesbaren JSON-Report und eine kompakte Terminalzusammenfassung.

Verwende einen expliziten Ausgabepfad für Reports oder einen sicheren, klar dokumentierten Standardpfad.

## 6. Teil E: Tests

### 6.1 Prompt- und Protokolltests

- Native Tool Calls bleiben strukturiert.
- Pseudo-Tool-Calls werden nicht ausgeführt.
- JSON im Native-Modus wird nicht als Tool Call interpretiert.
- JSON-Fallback bleibt strikt.
- Normale Textantworten bleiben zulässig.
- Keine zusätzlichen Modellturns.
- Keine automatischen Retries.

### 6.2 Privacy Tests

- `lca.toml` kann nicht gelesen werden.
- `opencode.json` kann nicht gelesen werden.
- `.env` kann nicht gelesen werden.
- `.env.local` kann nicht gelesen werden.
- Private Schlüsseldateien werden blockiert.
- Geschützte Dateien erscheinen nicht in Listings.
- Geschützte Dateien werden nicht durchsucht.
- Geschützte Dateien können nicht gepatcht werden.
- Benutzerdefinierte Ausschlüsse greifen.
- Gewöhnliche Quelldateien bleiben zugänglich.
- Keine Umgehung durch Gross-/Kleinschreibung unter Windows.
- Keine Umgehung durch alternative Pfadschreibweisen.
- Keine Umgehung durch verschachtelte Verzeichnisse.
- Keine Umgehung durch Junctions oder Symlinks.

### 6.3 Regression Tests

- Bestehende LCA-01A-Tests.
- Bestehende LCA-01B-Tests.
- Bestehende LCA-01C-Tests.
- Bestehende LCA-01D-Tests.
- Bestehende LCA-01E-Tests.
- `lca ask` bleibt unverändert.
- `lca tools probe` bleibt unverändert.
- Single-Turn-Invariante bleibt erhalten.
- Keine Shell-Ausführung.
- Keine automatische Schreibfreigabe.

### 6.4 Live-Tests

Live-Tests dürfen nur explizit gestartet werden.

Normale Unit-Tests dürfen keinen Ollama-Server benötigen.

Ein fehlender Ollama-Server darf die deterministischen Tests nicht beeinträchtigen.

## 7. Security-Hardening-Grenzen

Die folgenden bekannten Einschränkungen aus LCA-01D bleiben ausdrücklich offen:

- Check-then-Open-Races
- Nicht vollständig handlebasierte Windows-Pfadprüfung
- Fehlende echte NTFS-Dateiidentität
- Hardlink-Aliase
- Verify-Fehler nach erfolgreichem Rename ohne Rollback

Dieses Hardening darf nicht behaupten, diese Probleme gelöst zu haben, sofern sie nicht tatsächlich mit geeigneten Mechanismen und Tests behoben wurden.

Die neue Privacy Policy muss insbesondere Hardlink-Aliase berücksichtigen: Ein rein namensbasierter Schutz ist keine vollständige Vertraulichkeitsgarantie.

Für diesen Meilenstein ist eine konservative, dokumentierte Privacy Boundary ausreichend.

Eine vollständig gegen lokale Angreifer mit Dateisystem-Schreibrechten abgesicherte OS-Sandbox ist nicht Bestandteil von LCA-01E-H1.

## 8. Quality Gates

Führe aus:

```powershell
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Alle Gates müssen Exit-Code 0 liefern.

Zusätzlich manuell prüfen:

```powershell
cargo run -p lca-cli -- agent run --protocol native "Lies Cargo.toml."
cargo run -p lca-cli -- agent run --protocol native "Suche im Verzeichnis crates nach ModelRuntime."
cargo run -p lca-cli -- agent run --protocol auto "Erkläre Rust Ownership in zwei Sätzen."
```

Privacy-Tests müssen mit ungefährlichen Testdateien in einem isolierten temporären Workspace erfolgen.

Keine echten Secrets ausgeben.

Die 20-fache Live-Evaluation ist separat und darf nicht als bereits durchgeführt ausgegeben werden, wenn sie nicht tatsächlich gelaufen ist.

## 9. Acceptance Criteria

| ID | Kriterium |
| --- | --- |
| AC-01 | Native Tool Calling diagnostisch untersucht |
| AC-02 | Tool-Selection-Prompt verbessert |
| AC-03 | Pseudo-Tool-Calls bleiben nicht ausführbar |
| AC-04 | Diagnose klassifiziert Pseudo-Tool-Calls |
| AC-05 | Privacy Policy implementiert |
| AC-06 | Geschützte Dateien sind nicht lesbar |
| AC-07 | Geschützte Namen fehlen in Listings |
| AC-08 | Suche überspringt geschützte Dateien |
| AC-09 | Patches auf geschützte Dateien werden abgelehnt |
| AC-10 | Deny-Overrides gilt über alle Policy-Ebenen |
| AC-11 | Benutzerdefinierte Ausschlüsse funktionieren |
| AC-12 | Reliability Evaluation implementiert |
| AC-13 | Native und JSON können evaluiert werden |
| AC-14 | Evaluation erzeugt maschinenlesbare Reports |
| AC-15 | Evaluation führt keine Schreiboperationen aus |
| AC-16 | Single-Turn-Invariante bleibt erhalten |
| AC-17 | Bestehende Tests bestehen |
| AC-18 | Quality Gates bestehen |
| AC-19 | Windows-Sicherheitsgrenzen dokumentiert |
| AC-20 | Keine automatische Schreibfreigabe oder Shell-Ausführung |

**Wichtig:** Die Existenz einer Evaluation bedeutet nicht automatisch, dass die Modellzuverlässigkeit verbessert wurde.

Berichte gemessene Erfolgsquoten separat. Falls die Tool-Auswahl weiterhin unzuverlässig ist, markiere das ausdrücklich als verbleibendes Problem.

## 10. Dokumentation

Erstelle:

- `docs/architecture/LCA-01E-H1.md`
- `docs/architecture/adr/LCA-ARCH-05-H1.md`
- `docs/cursor-prompts/LCA-01E-H1.md`

Dokumentiere:

1. Ausgangsprobleme
2. Ursachenanalyse Native Tool Calling
3. Prompt-Änderungen
4. Privacy Policy
5. Policy-Komposition
6. Evaluationsmethodik
7. Testfälle und Metriken
8. Tatsächliche Messergebnisse
9. Sicherheitsgrenzen
10. Offene Risiken
11. Empfehlung für LCA-01F

## 11. Git-Regeln

Arbeite auf `lca-development`.

Prüfe den Git-Status vor Änderungen.

Keine neuen Worktrees.

Keine automatischen Pushes.

Keine Änderungen an unbeteiligten Projekten.

Keine versehentliche Aufnahme von:

- `lca.toml`
- `opencode.json`
- `lca-test/`

Keine unbegründeten Änderungen an lokalen Modelfiles.

Keine PowerShell-5.1-inkompatiblen `&&`-Befehle.

Speichere den vollständigen Prompt unter:

`docs/cursor-prompts/LCA-01E-H1.md`

Nach erfolgreicher Implementierung und bestandenen Quality Gates:

**Commit-Titel:**

`LCA-01E-H1: Tool Selection Reliability and Workspace Privacy`

Nicht automatisch pushen.

## 12. Abschlussbericht

Liefere:

1. Executive Summary
2. Root-Cause-Analyse
3. Implementierte Änderungen
4. Geänderte Dateien
5. Privacy-Policy-Verhalten
6. Native-Tool-Calling-Diagnose
7. Reliability-Evaluation
8. Tatsächliche Testergebnisse
9. Acceptance-Criteria-Matrix
10. Bekannte Einschränkungen
11. Git-Commit-Hash
12. Empfehlung für LCA-01F

Unterscheide ausdrücklich zwischen:

- Implementiert
- Automatisiert getestet
- Live getestet
- Gemessen verbessert
- Noch offen
