# LCA-01G prompt

The milestone was implemented from the verified-approval brief. The contracts are recorded in [LCA-01G](../architecture/LCA-01G.md), [LCA-ARCH-08](../architecture/adr/LCA-ARCH-08.md), [LCA-ARCH-09](../architecture/adr/LCA-ARCH-09.md), and [LCA-ARCH-10](../architecture/adr/LCA-ARCH-10.md).

# LCA-01G: Verified Patch Approval and Execution Boundary

**Milestone:** LCA-01G
**Architecture Decisions:** LCA-ARCH-08, LCA-ARCH-09, LCA-ARCH-10
**Branch:** `lca-development`

## Ziel

Der Agent bereitet eine Änderung vor. Eine spätere, interaktive CLI-Sitzung prüft und gibt genau diese Bytes frei. Der Agent gibt sich nie selbst frei. Eine Freigabe bindet Proposal, Workspace, Pfad, Originalbytes und neue Bytes. Vor dem Schreiben werden die Bedingungen erneut geprüft.

Keine Shell. Keine automatische Schreiboperation. Keine Netzwerkfreigabe. Keine zweite Patch-Engine.

## Befehle

```text
lca agent execute "<auftrag>"
lca patch list
lca patch show <proposal-id>
lca patch approve <proposal-id>
lca patch reject <proposal-id>
lca patch status <proposal-id>
```

`execute` speichert das Proposal ausserhalb des Workspace und druckt `proposal_id`. Es druckt keine Bestätigungszeile. `approve` ruft kein Modell auf, verlangt ein Terminal und liest genau eine Zeile. `--yes`, `--force` und `--auto-approve` existieren nicht.

## Grenze

Windows ist die einzige Plattform mit verified apply. Die Identität ist Volume Serial plus NTFS File Id. Junctions, Symlinks und Hardlink-Ziele werden beim Schreiben abgelehnt. Linux und macOS bleiben fail-closed. Ein SHA-256-Digest ist keine Authentisierung; die Vertrauensgrenze ist der Windows-Benutzer über DPAPI und eine owner-only ACL.
