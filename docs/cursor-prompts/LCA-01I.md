# LCA-01I prompt

The milestone was implemented from the crash-safe publication brief. The contracts are recorded in [LCA-01I](../architecture/LCA-01I.md), [LCA-ARCH-14](../architecture/adr/LCA-ARCH-14.md), [LCA-ARCH-15](../architecture/adr/LCA-ARCH-15.md), and [LCA-ARCH-16](../architecture/adr/LCA-ARCH-16.md).

# LCA-01I: Crash-Safe Patch Publication and Recovery

**Milestone:** LCA-01I
**Architecture Decisions:** LCA-ARCH-14, LCA-ARCH-15, LCA-ARCH-16
**Branch:** `lca-development`

## Ziel

Eine Publikation, die das geprüfte Dateiobjekt behält, und eine Recovery, die nach einem Prozessabbruch nicht erneut schreibt. Atomare Sichtbarkeit wird nicht behauptet, wenn die Messung sie nicht hergibt.

## Entscheidung

POSIX-Replace und `ReplaceFileW` wechseln die File Id und verlangen Share-Delete oder ein geschlossenes Handle. Share-Delete lässt einen anderen Rename den Namen wegnehmen. Ein Byte-Range-Lock verhindert das nicht. Die Veröffentlichung bleibt das Schreiben auf das exklusive Handle. Vor dem ersten `WriteFile` wird das Original in `{id}.lcae` versiegelt.

## Recovery

`Unclear` bleibt, wenn der Hash weder das Original noch den Vorschlag ist. `inspect` schreibt nicht. `recover` setzt nur den Proposal-Status. Die alte Freigabe wird nicht wiederverwendet. Eine automatische Rückschrift gibt es nicht.

## Tests

`measured_windows_publication_options` misst die abgelehnten Strategien. `killed_child_is_recovered_without_a_rewrite` beendet einen Kindprozess mit `taskkill /F`. Die Kill-Punkte hängen nicht an einer Umgebungsvariable in der Bibliothek. Die produktive CLI baut `ApplyFault::None` und kein `KillHold`.
