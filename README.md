# KlausHackt

**Autorisierte Schwachstellensuche mit Lern-Loop.** Du gibst KlausHackt ein Ziel, eine Erlaubnis und ein Zeitbudget. Er sucht Sicherheitslücken von *info* bis *kritisch*, sortiert sie, erklärt jede in verständlichem Deutsch und wird mit jedem bestätigten Fund besser.

```
python -m klaushackt start --scope scopes/meine-app.toml --dauer 2h
```

- **White-Box** (mit Quellcode): Geheimnisse, gefährliche Muster, verwundbare Bibliotheken, Claude-Code-Review
- **Black-Box** (nur Schnittstellen): Header, Cookies, CORS, offene Dateien (`.env`, `.git`, Backups), Fehlerseiten, reflektiertes XSS, Geheimnisse in ausgeliefertem JavaScript, Source Maps
- **Zugriffsrechte (IDOR)** mit mehreren Testkonten: Sieht Konto B die Daten von Konto A?
- **Lern-Loop**: Bestätigte Funde werden zu neuen Suchregeln (Variantensuche), Fehlalarme werden nie wieder gemeldet, erfolgreiche Techniken bekommen mehr Zeit

## Regeln, die KlausHackt immer einhält

| Regel | Umsetzung |
|---|---|
| Kein Test ohne Erlaubnis | Ohne gültige Scope-Datei mit `bestaetigt = true` und Ablaufdatum startet nichts |
| Nur, was im Scope steht | Jede einzelne Anfrage wird gegen Host, Port, Pfad und Ausschlussliste geprüft. Weiterleitungen aus dem Scope heraus werden nicht verfolgt. Platzhalter (`*.example.de`) sind verboten |
| Kein Massenscan | Harte Drossel (Standard 2/s, nie über 10/s), Gesamtbudget pro Lauf, keine Wortlisten, automatisches Abbremsen bei 429/503, Abbruch bei wiederholten Serverfehlern |
| Keine Schäden | Standardmäßig nur `GET`, `HEAD` und `OPTIONS`. Keine Formulare absenden, kein DoS, keine Daten verändern |
| Keine echten Nutzerdaten | Zugriffstests nur mit Testkonten aus dem Scope. Geheimnisse werden in Berichten maskiert |
| Nachvollziehbar | Jede Anfrage landet im Protokoll (`anfragen-laufN.jsonl`), optional mit Kennungs-Header für das Programm |
| Mensch entscheidet | KlausHackt meldet nichts an Dritte. Du prüfst jeden Fund vor dem Melden |

## Schnellstart (5 Minuten, mit Übungsziel)

```bash
git clone <dieses-repo> && cd KlausClipper
python demo/ziel_app/server.py                                    # Terminal 1: absichtlich unsicheres Übungsziel
python -m klaushackt start --scope scopes/demo.toml --dauer 5m    # Terminal 2: Lauf starten
python -m klaushackt dashboard                                    # Dashboard: http://127.0.0.1:8765
```

Du brauchst nur Python 3.11 oder neuer. Optional, für mehr Tiefe:

```bash
pip install anthropic          # Claude-Code-Review und KI-Lernen (dazu ANTHROPIC_API_KEY setzen)
pip install semgrep bandit     # zusätzliche Scanner, werden automatisch erkannt
# gitleaks (Git-Historie)      # https://github.com/gitleaks/gitleaks
```

## Eigenes Ziel prüfen

```bash
python -m klaushackt neuer-scope meine-app        # legt scopes/meine-app.toml an
# Datei ausfüllen: Ziele, Erlaubnis, Tempo, Testkonten, Belohnungstabelle
python -m klaushackt scope-pruefen scopes/meine-app.toml
python -m klaushackt start --scope scopes/meine-app.toml --dauer 2h --min-schwere niedrig
```

Wichtige Optionen für `start`:

| Option | Bedeutung |
|---|---|
| `--dauer 2h` | Zeitbudget (`90m`, `1h30m` …). `Strg+C` stoppt sauber und schreibt trotzdem den Bericht |
| `--min-schwere hoch` | Nur Funde ab dieser Schwere anzeigen |
| `--nur web` | Nur Black-Box. Weitere Werte: `code`, `zugriff`, `geheimnisse` … |
| `--no-ki` | Ohne Claude, rein lokal |

## Der Lern-Loop

1. Ein Lauf findet etwas und speichert es mit stabilem Fingerabdruck in `klaushackt-daten/wissen.db`.
2. Du markierst im Dashboard: **echt**, **Fehlalarm** oder **behoben**.
3. Aus echten Funden leitet KlausHackt neue Suchregeln ab. Mit Claude geschieht das intelligent, ohne Claude über eine Verallgemeinerung des Codes. Damit durchsucht er den ganzen Code nach **Varianten** desselben Fehlers.
4. Fehlalarme werden nie wieder gemeldet. Eine gelernte Regel, die mehr Fehlalarme als Treffer liefert, schaltet sich selbst ab.
5. Techniken, die oft Echtes finden, laufen beim nächsten Mal zuerst. Unveränderte Dateien werden nicht noch einmal per KI geprüft, so geht das Zeitbudget an Neues.
6. Verschwindet ein Fund, markiert KlausHackt ihn automatisch als *behoben*. Taucht er wieder auf, meldet er ihn als **WIEDER DA**.

## Bug-Bounty-Programme (YesWeHack, Intigriti …)

Übernimm Scope, Ausschlüsse, Rate-Limit, Pflicht-Header und Belohnungstabelle aus der Programmbeschreibung in die Scope-Datei. Programme geben fast nie Quellcode heraus. Dort arbeitet KlausHackt im Black-Box-Modus. Viele Programme verbieten automatisierte Scanner oder begrenzen sie stark. **Lies die Programmregeln und halte dich daran.** Im Zweifel `--nur zugriff` mit eigenen Testkonten verwenden oder ganz manuell testen.

## Rechtliches

Nur gegen Systeme einsetzen, für die eine ausdrückliche Erlaubnis vorliegt: eigene Systeme, schriftlicher Auftrag oder der Scope eines Bug-Bounty-Programms. Unerlaubtes Testen ist in Deutschland strafbar (§§ 202a ff. StGB). Das gilt auch, wenn es gut gemeint oder unbezahlt ist.

## Projektstruktur

```
klaushackt/            das Tool (nur Python-Standardbibliothek)
  scope.py             Scope laden und durchsetzen
  netz.py              einziger Weg ins Netz: Drossel, Scope-Prüfung, Protokoll
  wissen.py            Gedächtnis (SQLite): Funde, Regeln, Statistik, Abdeckung
  planer.py            Lauf mit Zeitbudget und Lern-Runde
  pruefer/             die einzelnen Prüfer
  bericht.py           HTML- und Markdown-Bericht
  dashboard.py         lokales Dashboard
scopes/                ein Scope pro Ziel
demo/ziel_app/         absichtlich unsicheres Übungsziel (nur lokal starten!)
website/               Projektseite
tests/                 python -m unittest discover -s tests
```
