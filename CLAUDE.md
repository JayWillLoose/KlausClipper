# KlausClipper – Projektgedächtnis

Diese Datei liest Claude Code bei jedem Start automatisch. Sie hält fest, was wir
im ersten Gespräch (23.11.2026) besprochen und entschieden haben.

## Ziel

Ein Python-Tool, das **autorisiert** Software auf Bugs und Sicherheitslücken prüft,
die Funde nach Schweregrad sortiert berichtet und mit jedem Lauf besser wird
(Lern-Loop über Wissensdatenbank, nicht über Modell-Training).

- Zuerst für die eigene Software / Website des Nutzers (mit Quellcode = White-Box).
- Später gratis für andere Firmen, **nur mit schriftlicher Erlaubnis** oder im
  Rahmen eines Bug-Bounty-Scopes (YesWeHack, Intigriti). Prämien können abgelehnt
  oder gespendet werden.
- Läuft lokal auf dem PC des Nutzers.

## Feste Regeln (nicht verhandelbar)

1. **Ohne gültige Scope-Datei startet kein Test.** Scope = erlaubte Ziele,
   Zeitraum, Max. Anfragen/Sekunde, Verweis auf die Erlaubnis.
2. **Rate-Limit wird hart erzwungen**, immer ≤ dem Limit aus dem Programm.
   Standard, wenn nichts angegeben: 2 Anfragen/Sekunde.
3. **Keine Massenscans, keine zerstörerischen Tests**, keine Überlastung, kein
   Zugriff auf echte Nutzerdaten (nur Testkonten).
4. **Jede Anfrage wird protokolliert** (Audit-Log), mit eigenem HTTP-Header zur
   Kennzeichnung, falls das Programm das verlangt.
5. **Mensch prüft vor dem Melden.** Nichts geht automatisch an eine Firma raus.

## Bedienung (geplant)

```
python scanner.py --scope scopes/meine-app.yaml --dauer 60m --min-schwere hoch
```

Zeitbudget statt Dauerbetrieb. Zusätzlich optional nächtlich per GitHub Action.

## Weitere Dokumente

- `docs/RECHERCHE.md` – Tool-Recherche mit Quellen
- `docs/ARCHITEKTUR.md` – Aufbau und Lern-Loop
- `docs/GESPRAECH.md` – Zusammenfassung des ersten Gesprächs

## Offene Fragen an den Nutzer

- Welche Software wird zuerst geprüft (Sprache, Framework, Repo)?
- Wie sollen Funde ankommen (GitHub-Issue, Mail, Dashboard)?
