# LCA-01M prompt

The milestone prototypes a Windows principal boundary and a capability broker. The record is [LCA-01M](../architecture/LCA-01M.md), [LCA-ARCH-26](../architecture/adr/LCA-ARCH-26.md), [LCA-ARCH-27](../architecture/adr/LCA-ARCH-27.md), and [LCA-ARCH-28](../architecture/adr/LCA-ARCH-28.md).

# LCA-01M: Windows Security Principal Isolation

**Milestone:** LCA-01M
**Architecture Decisions:** LCA-ARCH-26, LCA-ARCH-27, LCA-ARCH-28
**Branch:** `lca-development`

## Ziel

Prüfen, ob ein eingeschränkter Windows-Prozess den Proposal Store, Evidence und nicht freigegebene Dateien wirklich nicht öffnen kann, und ob ein Broker nur diesen Prozess bedient.

## Entscheidung

**B. Isolation teilweise nachgewiesen.** Der Restricted-Token-Worker erreichte seinen Testcode. Geschützte Testdateien lieferten `5`, der Hardlink `5`, der fremde Handle `6`, der Elternprozess am Pipe `deny:identity`, `cmd.exe` unter dem Job `1816`. Derselbe Benutzer öffnet die verweigerte Datei weiter. DPAPI auf einem mitgegebenen Blob lieferte `ok`. Ein separates Konto, ein AppContainer-Prozess und eine VM wurden nicht gestartet. Der produktive Apply-Pfad bleibt `apply_ntfs`. Command Execution bleibt aus.
