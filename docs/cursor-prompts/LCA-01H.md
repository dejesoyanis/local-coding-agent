# LCA-01H prompt

The milestone was implemented from the filesystem-hardening brief. The contracts are recorded in [LCA-01H](../architecture/LCA-01H.md), [LCA-ARCH-11](../architecture/adr/LCA-ARCH-11.md), [LCA-ARCH-12](../architecture/adr/LCA-ARCH-12.md), and [LCA-ARCH-13](../architecture/adr/LCA-ARCH-13.md).

# LCA-01H: Filesystem Security and Verified Apply Hardening

**Milestone:** LCA-01H
**Architecture Decisions:** LCA-ARCH-11, LCA-ARCH-12, LCA-ARCH-13
**Branch:** `lca-development`

## Ziel

Schliesse die in LCA-01G nachgewiesenen Windows-Lücken, soweit die Plattform das hergibt. Eine Garantie, die nicht belegt ist, wird nicht behauptet. Ein unsicherer Fallback ist verboten.

Keine Shell. Keine automatische Schreibfreigabe. Keine Modell-Retries. Keine Netzwerktools.

## Handle-gebundener Zugriff

Jeder Pfadbestandteil wird relativ zum geprüften Parent-Handle geöffnet. Gelesen wird dasselbe Handle. Reparse Points, Junctions, Symlinks, `..`, absolute Pfade, UNC, Device Paths, Alternate Data Streams und reservierte Namen werden abgelehnt. `link_count != 1` verweigert `read_file`, `search_files`, Patch-Prepare und Verified Apply. `link_count == 1` beweist nicht, dass die Datei harmlos ist.

## Verified Apply

Der Close-then-Rename-Pfad ist entfernt. Gemessen: ein Rename über ein Handle ohne `FILE_SHARE_DELETE` liefert `STATUS_ACCESS_DENIED` oder `STATUS_SHARING_VIOLATION`. Die Veröffentlichung ist ein Schreiben auf das geprüfte Handle, danach `SetEndOfFile` und `FlushFileBuffers`. Die File Id bleibt gleich.

Atomare Sichtbarkeit des Verzeichniseintrags ist nicht gegeben. `FlushFileBuffers` ist keine Transaktion. Ein Rollback findet nicht statt. Nach Beginn des Schreibens wird der Zustand `Unclear`, bis die Bytes und dieselbe File Id `Applied` oder `Failed` belegen. Recovery schreibt die Datei nicht erneut.

## Fault Injection

`ApplyFault` ist intern. `approve` übergibt immer `None`. Keine Umgebungsvariable aktiviert einen Fehlerpunkt. Die zehn Punkte sind `AfterValidation`, `AfterApproval`, `AfterTempCreate`, `AfterWrite`, `BeforeRename`, `AfterRename`, `BeforeReadback`, `DuringReadback`, `AfterVerification` und `BeforeAudit`. `BeforeRename` liegt vor dem Schreibvorgang. `AfterRename` liegt nach dem Flush. Der Name bezeichnet die Stelle, nicht einen Rename.

## Grenze

Windows ist die einzige Plattform mit verified apply. Linux und macOS bleiben fail-closed. DPAPI schützt nicht vor einem Prozess desselben Benutzers. Die interaktive Freigabe bleibt ein Terminal. Tests rufen `approve` nicht über eine Pipe und nicht über ein Pseudoterminal auf.
