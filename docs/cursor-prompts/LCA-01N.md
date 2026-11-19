# LCA-01N prompt

The milestone validates a separate Windows principal for an experimental worker. The record is [LCA-01N](../architecture/LCA-01N.md), [LCA-ARCH-29](../architecture/adr/LCA-ARCH-29.md), [LCA-ARCH-30](../architecture/adr/LCA-ARCH-30.md), and [LCA-ARCH-31](../architecture/adr/LCA-ARCH-31.md).

# LCA-01N: Separate Windows Principal & Cross-Identity Broker Validation

**Milestone:** LCA-01N
**Architecture Decisions:** LCA-ARCH-29, LCA-ARCH-30, LCA-ARCH-31
**Branch:** `lca-development`

## Ziel

Prüfen, ob ein Worker unter einer anderen Windows-Benutzer-SID läuft und der Broker nur registrierte Fähigkeiten an genau diesen Principal vermittelt.

## Entscheidung

**C. Cross-Identity-Grenze nicht nachgewiesen.** `LCA_01N_ACCOUNT` war nicht gesetzt. Es wurde kein Konto angelegt und kein `LogonUserW` aufgerufen. Der Bericht ist `gate=C worker_started=0`. Verträge, `AccessCheck`, eine Same-User-Pipe (`deny:session`) und ein Same-User-Hardlink (`0`) wurden gemessen. Das ist kein zweiter Principal. Der produktive Apply-Pfad bleibt `apply_ntfs`. Command Execution bleibt aus.
