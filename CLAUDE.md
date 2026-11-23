# KlausClipper-Repo / KlausHackt – Projektgedächtnis

Diese Datei liest Claude Code bei jedem Start automatisch.

## Was hier liegt

**KlausHackt** (`klaushackt/`): Python-Tool für autorisierte, rate-limitierte Schwachstellensuche
mit Lern-Loop. Nur Standardbibliothek; optional `anthropic` (KI-Review/Lernen), `semgrep`, `bandit`, `gitleaks`.

- Start: `python -m klaushackt start --scope scopes/<ziel>.toml --dauer 2h`
- Dashboard: `python -m klaushackt dashboard` → http://127.0.0.1:8765
- Übungsziel: `python demo/ziel_app/server.py` + `scopes/demo.toml`
- Tests: `python -m unittest discover -s tests`
- Website: `website/index.html` (für GitHub Pages)

Name: Der Nutzer wollte ursprünglich „ClaudeHackt“. Wir nutzen **KlausHackt**, weil „Claude“ eine
Marke von Anthropic ist und ein öffentliches Tool mit dem Namen wie ein offizielles Produkt wirken würde.

## Feste Regeln (nicht verhandelbar)

1. Ohne gültige Scope-Datei (Erlaubnis + `bestaetigt = true` + `gueltig_bis`) startet kein Test.
2. Jede Netzwerk-Anfrage läuft durch `netz.SichererClient`: Scope-Prüfung pro Anfrage, harte Drossel
   (Standard 2/s, Deckel 10/s), Gesamtbudget, Abbremsen bei 429/503, Abbruch bei Fehlerserien, Audit-Log.
3. Standardmäßig nur GET/HEAD/OPTIONS. Keine Massenscans, keine Wortlisten, keine zerstörerischen Tests.
4. Zugriffstests nur mit Testkonten aus dem Scope. Geheimnisse in Berichten maskieren.
5. Mensch prüft vor dem Melden. Nichts geht automatisch an Firmen/Plattformen.
6. Prüfer dürfen nie selbst ins Netz (außer `abhaengigkeiten` → öffentliche OSV-Datenbank, nur Paketnamen).

## Lern-Loop (wissen.py)

Funde mit stabilem Fingerabdruck (ohne Zeilennummer) → Nutzer markiert bestätigt/Fehlalarm/behoben →
`lerne_regeln` erzeugt Regex-Regeln (per Claude oder `verallgemeinere`) → Variantensuche im nächsten Lauf.
Fehlalarme werden nie wieder gemeldet; Regeln mit mehr Fehlalarmen als Treffern schalten sich ab;
Technik-Statistik steuert die Reihenfolge; Abdeckung verhindert doppelte KI-Reviews unveränderter Dateien.

## Offene Punkte (Stand 23.11.2026)

- **Ute-Fischer-Seite**: Quellcode liegt in keinem für Claude erreichbaren Repo und in keinem Artifact.
  Nutzer muss Repo/Link/Dateien bereitstellen, dann Audit + Fixes.
- **Klaus Clipper Black-Box-Test**: Klaus läuft lokal auf dem PC des Nutzers (Dashboard). Von der Cloud
  aus nicht erreichbar. Plan: Nutzer startet Klaus, legt `scopes/klaus-clipper.toml` mit
  `urls = ["http://127.0.0.1:<port>/"]` an und führt `--nur web` aus – oder verbindet seinen PC per Remote Control.
- OSV-API ist aus der Cloud-Umgebung blockiert; auf dem PC des Nutzers funktioniert sie.

## Weitere Dokumente

- `docs/RECHERCHE.md` – Tool-Recherche mit Quellen
- `docs/ARCHITEKTUR.md` – ursprünglicher Plan
- `docs/GESPRAECH.md` – Zusammenfassung der Gespräche
