# LCA-01K prompt

The milestone was a measurement, not a new publisher. The record is [LCA-01K](../architecture/LCA-01K.md), [LCA-ARCH-20](../architecture/adr/LCA-ARCH-20.md), [LCA-ARCH-21](../architecture/adr/LCA-ARCH-21.md), and [LCA-ARCH-22](../architecture/adr/LCA-ARCH-22.md).

# LCA-01K: Atomic Publication Feasibility

**Milestone:** LCA-01K
**Architecture Decisions:** LCA-ARCH-20, LCA-ARCH-21, LCA-ARCH-22
**Branch:** `lca-development`

## Ziel

Prüfen, ob eine Windows-Publikation gleichzeitig die geprüfte Identität behält und Lesern nur die vollständige alte oder die vollständige neue Datei zeigt.

## Entscheidung

Atomic Publication ist nicht nachgewiesen. Der produktive Apply-Pfad bleibt `apply_ntfs` und das exklusive Handle. `MoveFileExW`, `ReplaceFileW` und `FileRenameInfoEx` sind nicht eingebaut.

Strategie A behält die File Id und kann reissen. Ein Kindprozess, der während `WriteFile` mit `taskkill /F` endet, hinterlässt die bekannte Mischdatei. Strategien B, C und D wechseln die File Id. Ohne `FILE_SHARE_DELETE` scheitern sie am Pin. Mit Share-Delete kann ein zweiter Prozess den Namen vorher wegnehmen. Eine File-Id-Prüfung und ein späterer Rename sind kein Compare-and-Swap. `FILE_RENAME_INFORMATION_EX` hat kein File-Id-Feld.

Ein Hardlink, der nach der Link-Count-Prüfung und vor dem Schreiben entsteht, macht die neuen Bytes unter einem Namen ausserhalb des Workspace sichtbar. Das ist gemessen und in diesem Meilenstein nicht geändert. Ein Datei-Symlink liess sich hier nicht anlegen (`1314`) und zählt nicht als bestanden. Stromausfall ist nicht gemessen.
