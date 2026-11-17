# LCA-01L prompt

The milestone defines the trust model and measures Windows isolation. The record is [LCA-01L](../architecture/LCA-01L.md), [LCA-ARCH-23](../architecture/adr/LCA-ARCH-23.md), [LCA-ARCH-24](../architecture/adr/LCA-ARCH-24.md), and [LCA-ARCH-25](../architecture/adr/LCA-ARCH-25.md).

# LCA-01L: Workspace Trust Boundaries

**Milestone:** LCA-01L
**Architecture Decisions:** LCA-ARCH-23, LCA-ARCH-24, LCA-ARCH-25
**Branch:** `lca-development`

## Ziel

Festlegen, welche Grenzen der Prozess heute erzwingt und welche eine andere Windows-Identität oder eine VM brauchen.

## Entscheidung

**B. Zusätzliche Isolation ist erforderlich**, bevor ein Same-User-Prozess als ausserhalb des Modells gilt und bevor eine Shell erlaubt wird. Der bestehende Apply-Pfad bleibt `apply_ntfs`.

Das Modell hat keine Freigabe, keine Handles und keinen Moduswechsel. Fehlendes `tools.mutation_mode` ist `read_only`. Ein unbekannter Name lädt die Konfiguration nicht.

Ein zweiter Prozess desselben Benutzers hat den Hardlink angelegt, DPAPI gelesen und die Evidence-Datei überschrieben. Rename am exklusiven Handle blieb bei `32`, Parent-Rename bei `5`. Ein Restricted Token liess sich impersonieren und trennte zwei Testdateien (`0` und `5`). `CreateProcessAsUserW` startete den Prozess, der mit `0xC0000022` endete, bevor der Testcode lief. Das zählt nicht als Sandbox. Low Integrity hat den Medium-Benutzer nicht am Schreiben gehindert.

`cargo test` auf einer Allowlist ist keine Sandbox. Command Execution bleibt aus.
