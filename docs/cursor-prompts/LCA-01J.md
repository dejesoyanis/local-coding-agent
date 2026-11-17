# LCA-01J prompt

The milestone was implemented from the controlled-restoration brief. The contracts are recorded in [LCA-01J](../architecture/LCA-01J.md), [LCA-ARCH-17](../architecture/adr/LCA-ARCH-17.md), [LCA-ARCH-18](../architecture/adr/LCA-ARCH-18.md), and [LCA-ARCH-19](../architecture/adr/LCA-ARCH-19.md).

# LCA-01J: Controlled Restoration and Recovery Authorization

**Milestone:** LCA-01J
**Architecture Decisions:** LCA-ARCH-17, LCA-ARCH-18, LCA-ARCH-19
**Branch:** `lca-development`

## Ziel

Eine zerrissene Datei wird nur mit einer neuen Restoration-Identität und einer neuen menschlichen Zeile zurückgeschrieben. Die Patch-Freigabe gilt dafür nicht.

## Entscheidung

Der Contract ist `LCA-01J-RESTORATION-V1`. Die Zeile beginnt mit `restore`. Quellen sind `Unclear` und `Failed`, und nur wenn die `.lcae`-Evidence stimmt und der aktuelle Hash weder Original noch Vorschlag ist. `Applied` und `Conflict` sind keine Quellen. Der Schreibweg ist `apply_ntfs`. Recovery schreibt nicht. `.lcae` wird nicht gelöscht und nicht überschrieben.

Die Publikationsstrategie bleibt das Schreiben auf das exklusive Handle. Ein Rename wird nicht ergänzt. LCA-ARCH-19 begründet das mit der Messung aus LCA-01I.

## Tests

`killed_restoration_is_not_retried` beendet einen Kindprozess mit `taskkill /F`. Die produktive CLI baut kein `KillHold`. `live_restoration_stops_before_human_approval` zeigt die Restoration und stoppt vor der Freigabe, weil kein interaktives Terminal vorhanden war.
