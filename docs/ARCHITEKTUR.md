# Architektur und Lern-Loop

## Ablauf eines Laufs

```
scanner.py --scope X --dauer 60m
   │
   ├─ 1. Scope prüfen ──────────── ungültig/abgelaufen? → Abbruch
   ├─ 2. Wissensdatenbank laden ─── alte Funde, Fehlalarme, App-Karte, eigene Regeln
   ├─ 3. Plan erstellen ─────────── Priorität: Änderungen > ungeprüft > Rest
   ├─ 4. Prüfen (bis Zeit um) ──── jede Netzwerk-Anfrage durch Rate-Limiter + Audit-Log
   │     a) Semgrep / Bandit / Gitleaks / OSV  (schnell)
   │     b) Claude-Review: Logik, Rollen, IDOR (mit Code)
   │     c) Fuzzing: Schemathesis / Atheris
   │     d) DAST: ZAP / Nuclei (gedrosselt, nur Scope-Ziele)
   ├─ 5. Claude-Triage ───────────── Duplikate & Fehlalarme raus, Schweregrad setzen
   ├─ 6. Bestätigen ──────────────── wo möglich harmloser Nachweis (PoC) gegen Testsystem
   ├─ 7. Bericht ─────────────────── kritisch / hoch / mittel / niedrig
   └─ 8. Lernen ──────────────────── siehe unten
```

## Der Lern-Loop (das „Schlauer-werden“)

Das Modell lernt nicht – das **System** sammelt Wissen und nutzt es beim nächsten Lauf:

| Nach jedem Lauf | Wirkung beim nächsten Lauf |
|---|---|
| Fund bestätigt → **neue Semgrep-/CodeQL-Regel** aus dem Muster | Sucht dasselbe Muster überall (Variantensuche) |
| Fehlalarm markiert → in Ausschlussliste | Weniger Rauschen |
| Neue Endpunkte, Rollen, Datenflüsse → **App-Karte** | Gezieltere Tests, v. a. für IDOR |
| Geprüfte Bereiche → **Abdeckung** | Fokus auf Ungeprüftes |
| Behobener Bug → **Regressionstest** | Kommt nie unbemerkt zurück |
| Trefferquote je Technik messen | Zeitbudget wandert zu den erfolgreichsten Techniken |
| Öffentliche CVEs/Advisories zu genutzten Libraries | Neue Regeln ohne eigenen Fund |

Je mehr Funde, desto mehr Regeln, desto besser die Karte → desto höher die Chance
auf den nächsten Fund. Genau der gewünschte Loop.

## Geplante Ordnerstruktur

```
scanner.py            Einstieg (CLI)
klaus/
  scope.py            Scope laden & erzwingen
  ratelimit.py        harter Token-Bucket + Audit-Log
  runners/            Adapter für Semgrep, ZAP, Nuclei, Schemathesis …
  ai/                 Claude-Review, Triage, Regel-Generator
  knowledge.py        SQLite-Wissensdatenbank
  report.py           Bericht (Markdown/HTML, später Issue/Mail)
scopes/               eine YAML-Datei pro Ziel (+ Erlaubnis-Nachweis)
rules/                selbst gelernte Semgrep-/CodeQL-Regeln
data/knowledge.db     Gedächtnis
```

## Beispiel Scope-Datei

```yaml
name: meine-app
erlaubnis: nachweise/meine-app-freigabe.pdf
gueltig_bis: 2027-12-31
ziele:
  repos: [../meine-app]
  urls: [https://staging.meine-app.de]
ausgeschlossen: [https://staging.meine-app.de/admin/delete]
max_anfragen_pro_sekunde: 2
header: {X-Bug-Bounty: "klausclipper"}
testkonten: [nutzer_a, nutzer_b, admin_test]
verboten: [dos, social_engineering, echte_nutzerdaten]
```
