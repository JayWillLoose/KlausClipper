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

## Lastprobe (lastprobe.py) – NEU

Adaptiver AIMD-Loop: beobachten → bewerten → anpassen (additiv +2 / bei Ärger ×0.5) → merken (wissen.db
Tabelle `tempo`). Findet die höchste sichere Rate und den Bruchpunkt + Diagnose (Timeouts/Resets/429/5xx/
Latenz-Knie). `python -m klaushackt lastprobe --scope ... --dauer 5m --start 9 --max 120`.
NUR gegen loopback (127.0.0.1/localhost) erlaubt; fremde Ziele bleiben bei ≤10/s. Live getestet:
robustes Ziel → kein Bruch bis 37/s; schwaches Ziel → Knie bei 18/s (Latenz 69→407 ms), pendelt auf 17/s.

## Offene Punkte (Stand 23.11.2026)

- **Klaus Clipper Black-Box-Test** – HAUPTAUFGABE, noch offen. Klaus läuft auf dem Windows-PC des
  Nutzers (`DESKTOP-QBH3K1F`). Aus der Cloud nicht erreichbar.
  - Remote Control: Nutzer hat den Ordner **„Ideen FBA"** freigegeben, aber der PC bietet ihn Cloud-
    Sessions NICHT an (`list_computer_folders` → `cannot_be_used`, reason `not_available`). Wahrscheinlich
    muss die **Claude-App auf dem Windows-PC aktualisiert** werden, dann wird der Ordner nutzbar.
  - Sobald ein Ordner unter `folders` (nicht `cannot_be_used`) auftaucht: `request_computer_folder`,
    dann auf dem PC `scopes/klaus-clipper.toml` (Port eintragen!) mit `start --nur web` + `lastprobe`.
  - **Klaus-Port ist noch unbekannt** – Nutzer fragen.
  - Alternative: Nutzer führt die 3 Befehle selbst auf dem PC aus (siehe README / klaus-clipper.toml).
  - Wichtig: Klaus = reiner Black-Box-Test, KEIN Quellcode (Scope hat `repos = []`).
- **Modellwechsel**: Ich kann das Modell NICHT selbst umschalten (nur der Nutzer via `/model`). Der kurze
  Wechsel auf Opus 4.8 war ein automatischer System-Fallback, keine eigene Wahl.
- **Ute-Fischer-Seite**: weiterhin nicht auffindbar; Nutzer muss Repo/Link/Dateien liefern.
- OSV-API ist aus der Cloud blockiert; auf dem PC des Nutzers funktioniert sie.

## Neues Vorhaben: eigene Webseiten-Firma (Stand 26.11.2026)

Nutzer + Kumpel wollen Webseiten verkaufen. Eine Hauptdomain (Arbeitstitel **„Klaus Gard“**), alle
Kundenseiten auf **unseren** Servern, Abrechnung komplett über **uns** („wir sind die Hauptdarsteller“).
Recherche: `docs/DOMAIN_RECHERCHE.md`. Kernplan: Domain-Reseller (INWX) statt DENIC-Mitgliedschaft,
Hetzner/Netcup + Coolify (Auto-SSL), Blesta/Invoice Ninja fürs Abo, später Cloudflare for SaaS.
`klausgard.de/.com` waren am 26.11. frei – **nichts kaufen ohne ausdrückliches OK des Nutzers.**
Recherche darf/soll weitergehen (Nutzer wünscht ausdrücklich ausführliche Recherche).

## Weitere Dokumente

- `docs/DOMAIN_RECHERCHE.md` – Domains, Server, Abrechnung, Recht für die Webseiten-Firma
- `docs/SERVER_UND_MAIL_RECHERCHE.md` – Gratis-Start (Cloudflare Pages/Oracle), Umzugsplan, Kapazität,
  Plattform „wie Lieferando“ (Annahme: „Larendo“ = Lieferando, unbestätigt), Firmen-Mail (Workspace/Zoho/Routing)

- `docs/RECHERCHE.md` – Tool-Recherche mit Quellen
- `docs/ARCHITEKTUR.md` – ursprünglicher Plan
- `docs/GESPRAECH.md` – Zusammenfassung der Gespräche
