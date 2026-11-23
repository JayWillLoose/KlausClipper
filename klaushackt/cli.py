"""Kommandozeile von KlausHackt."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from klaushackt import __version__
from klaushackt.fund import SCHWEREGRADE
from klaushackt.scope import ScopeFehler, lade_scope

BANNER = [
    r" _  ___                 _   _            _    _   ",
    r"| |/ / | __ _ _   _ ___| | | | __ _  ___| | _| |_ ",
    r"| ' /| |/ _` | | | / __| |_| |/ _` |/ __| |/ / __|",
    r"| . \| | (_| | |_| \__ \  _  | (_| | (__|   <| |_ ",
    r"|_|\_\_|\__,_|\__,_|___/_| |_|\__,_|\___|_|\_\\__|",
]
GLITCH = "#@$%&*!?<>/\\|=+~^01"
VERLAUF = [48, 49, 50, 51, 45]  # grün → cyan, Zeile für Zeile


def zeige_banner(animiert: bool) -> None:
    """Banner mit kurzem Glitch-Effekt (< 1 s), nur im echten Terminal."""
    import random
    import time

    from klaushackt.planer import Optik

    o = Optik.automatisch()
    if o.farbe and animiert:
        hoehe = len(BANNER)
        for i, anteil in enumerate((0.55, 0.3, 0.12, 0.0)):
            if i:
                sys.stdout.write(f"\033[{hoehe}A")
            for nr, zeile in enumerate(BANNER):
                zeichen = [random.choice(GLITCH) if c != " " and random.random() < anteil else c for c in zeile]
                versatz = " " * random.choice((0, 0, 1)) if anteil else ""
                farbe = 205 if anteil > 0.4 and nr % 2 else VERLAUF[nr]
                sys.stdout.write("\r  " + o.f(versatz + "".join(zeichen) + " ", farbe, fett=True) + "\033[K\n")
            sys.stdout.flush()
            time.sleep(0.14)
    else:
        for nr, zeile in enumerate(BANNER):
            print("  " + o.f(zeile, VERLAUF[nr], fett=True))
    print("  " + o.f(f"v{__version__}", 205, fett=True) + o.dim("  ·  autorisierte schwachstellensuche mit lern-loop"))
    print("  " + o.f("root@klaus", 48) + o.dim(":") + o.f("~", 51) + o.dim("$ ") +
          "./hackt --nur-mit-erlaubnis  " + o.dim("# versprochen."))
    print()

VORLAGE = '''# KlausHackt-Scope: Was darf getestet werden – und was nicht.
# Ohne gültigen Scope startet KlausHackt keinen einzigen Test.

name = "{name}"
gueltig_ab = "{heute}"
gueltig_bis = "{bis}"          # Pflicht: jeder Scope läuft ab

[erlaubnis]
# Pflicht: ein Nachweis (Datei, z. B. PDF der Freigabe) und/oder eine Beschreibung
# nachweis = "../nachweise/{name}-freigabe.pdf"
beschreibung = "Eigenes Projekt / schriftliche Freigabe von ... vom ..."
bestaetigt = false               # erst auf true setzen, wenn die Erlaubnis wirklich vorliegt

[ziele]
repos = []                       # Quellcode (White-Box), z. B. ["../mein-projekt"]
urls = []                        # laufende Seite (Black-Box), z. B. ["https://staging.example.de/"]
ausgeschlossen = []              # z. B. ["https://staging.example.de/logout"]

[regeln]
anfragen_pro_sekunde = 2         # Programmlimit einhalten (max. 10 erzwingt KlausHackt immer)
max_anfragen_gesamt = 2000
erlaubte_methoden = ["GET", "HEAD", "OPTIONS"]   # keine verändernden Anfragen
verboten = ["dos", "social_engineering", "echte_nutzerdaten"]

[regeln.header]
# Viele Programme verlangen eine Kennung im Header:
# "X-Bug-Bounty" = "dein-name"

[programm]
plattform = ""                   # z. B. "YesWeHack" oder "Intigriti"
url = ""
hinweise = ""

[programm.belohnungen]
# kritisch = "1.000–5.000 €"
# hoch = "500–1.000 €"

# Testkonten – niemals echte Kundenkonten!
# [[testkonten]]
# name = "nutzer_a"
# rolle = "kunde"
# header = {{ Cookie = "session=..." }}

# Zugriffsprüfung (IDOR): Ressource von nutzer_a, abgerufen als alle anderen
# [[zugriff_pruefung]]
# url = "https://staging.example.de/api/rechnungen/1001"
# besitzer = "nutzer_a"
'''


def _wissen(args):
    from klaushackt.wissen import Wissen
    return Wissen(Path(args.daten) / "wissen.db")


def cmd_start(args) -> int:
    from klaushackt.planer import Lauf, parse_dauer
    try:
        scope = lade_scope(args.scope)
        scope.pruefe_gueltig()
        dauer = parse_dauer(args.dauer)
    except (ScopeFehler, ValueError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2
    farbe = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if not args.ruhig:
        zeige_banner(animiert=farbe)
    nur = set(args.nur.split(",")) if args.nur else None
    Lauf(scope, _wissen(args), Path(args.daten), dauer, args.min_schwere, ki=args.ki, nur=nur, farbe=farbe).starte()
    return 0


def cmd_dashboard(args) -> int:
    from klaushackt.dashboard import starte_dashboard
    starte_dashboard(_wissen(args), args.port)
    return 0


def cmd_scope(args) -> int:
    try:
        s = lade_scope(args.datei)
        s.pruefe_gueltig()
    except ScopeFehler as e:
        print(f"✗ Scope ungültig: {e}", file=sys.stderr)
        return 2
    print("✔ Scope gültig\n")
    print(s.zusammenfassung())
    return 0


def cmd_neuer_scope(args) -> int:
    import datetime as dt
    ziel = Path("scopes") / f"{args.name}.toml"
    if ziel.exists():
        print(f"✗ {ziel} existiert bereits", file=sys.stderr)
        return 2
    ziel.parent.mkdir(exist_ok=True)
    heute = dt.date.today()
    ziel.write_text(VORLAGE.format(name=args.name, heute=heute, bis=heute + dt.timedelta(days=30)), encoding="utf-8")
    print(f"✔ Vorlage angelegt: {ziel}\n  Trage Ziele und Erlaubnis ein und setze 'bestaetigt = true'.")
    return 0


def cmd_markiere(args) -> int:
    n = _wissen(args).markiere(args.id, args.status, args.scope)
    print(f"✔ {n} Fund(e) als '{args.status}' markiert" if n else "✗ Kein Fund mit dieser ID")
    return 0 if n else 1


def cmd_funde(args) -> int:
    from klaushackt.fund import rang
    w = _wissen(args)
    funde = [f for f in w.funde(scope=args.scope, status=args.status) if rang(f["schwere"]) >= rang(args.min_schwere)]
    funde.sort(key=lambda f: -rang(f["schwere"]))
    for f in funde:
        ort = f["ort"] + (f":{f['zeile']}" if f["zeile"] else "")
        print(f"{f['fingerabdruck']}  {f['schwere']:<8} {f['status']:<10} {f['titel'][:70]}  ({ort})")
    print(f"\n{len(funde)} Funde")
    return 0


def cmd_lernen(args) -> int:
    from klaushackt.pruefer.ki import lerne_regeln
    n = lerne_regeln(_wissen(args), args.scope, print)
    print(f"✔ {n} neue Regel(n)" if n else "Keine neuen Regeln (bestätige zuerst echte Funde).")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="klaushackt", description="Autorisierte Schwachstellensuche mit Lern-Loop.")
    p.add_argument("--version", action="version", version=f"KlausHackt {__version__}")
    p.add_argument("--daten", default=os.environ.get("KLAUSHACKT_DATEN", "klaushackt-daten"),
                   help="Ordner für Gedächtnis, Berichte und Protokolle")
    sub = p.add_subparsers(dest="befehl", required=True)

    s = sub.add_parser("start", help="Lauf mit Zeitbudget starten")
    s.add_argument("--scope", required=True, help="Pfad zur Scope-Datei (.toml)")
    s.add_argument("--dauer", default="30m", help="Zeitbudget, z. B. 2h, 90m, 1h30m")
    s.add_argument("--min-schwere", default="niedrig", choices=SCHWEREGRADE)
    s.add_argument("--ki", action=argparse.BooleanOptionalAction, default=True,
                   help="Claude für Code-Review und Lernen nutzen (Standard: an, falls verfügbar)")
    s.add_argument("--nur", help="nur bestimmte Prüfer oder Arten, z. B. 'web' oder 'code_muster,geheimnisse'")
    s.add_argument("--ruhig", action="store_true", help="ohne Banner")
    s.set_defaults(f=cmd_start)

    d = sub.add_parser("dashboard", help="lokales Dashboard starten")
    d.add_argument("--port", type=int, default=8765)
    d.set_defaults(f=cmd_dashboard)

    c = sub.add_parser("scope-pruefen", help="Scope-Datei prüfen")
    c.add_argument("datei")
    c.set_defaults(f=cmd_scope)

    n = sub.add_parser("neuer-scope", help="Scope-Vorlage anlegen")
    n.add_argument("name")
    n.set_defaults(f=cmd_neuer_scope)

    m = sub.add_parser("markiere", help="Fund bestätigen / als Fehlalarm markieren")
    m.add_argument("id", help="Fingerabdruck des Fundes")
    m.add_argument("status", choices=["bestaetigt", "fehlalarm", "behoben", "neu"])
    m.add_argument("--scope")
    m.set_defaults(f=cmd_markiere)

    f = sub.add_parser("funde", help="Funde auflisten")
    f.add_argument("--scope")
    f.add_argument("--status", choices=["neu", "bestaetigt", "fehlalarm", "behoben"])
    f.add_argument("--min-schwere", default="info", choices=SCHWEREGRADE)
    f.set_defaults(f=cmd_funde)

    l = sub.add_parser("lernen", help="aus bestätigten Funden neue Regeln lernen")
    l.add_argument("--scope", required=True)
    l.set_defaults(f=cmd_lernen)

    # Sonderzeichen (✔, █, ║) dürfen auf alten Windows-Codepages nicht abstürzen
    for strom in (sys.stdout, sys.stderr):
        try:
            strom.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    args = p.parse_args(argv)
    return args.f(args)
