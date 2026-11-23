"""Der Planer: führt einen Lauf mit Zeitbudget durch.

Reihenfolge: erst die schnellen Prüfer (liefern sofort Ergebnisse), dann die
langsamen – sortiert nach ihrer bisherigen Erfolgsquote aus der
Wissensdatenbank. Bleibt Zeit, startet eine Lern-Runde (Variantensuche).

Die Terminal-Optik steckt in `Optik`: Farben, Tags, Boxen und Balken. Ohne TTY
oder mit NO_COLOR gibt sie reinen Text ohne Escape-Codes aus.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import signal
import sys
import time
from collections import Counter
from pathlib import Path

from klaushackt.bericht import schreibe_berichte
from klaushackt.fund import rang
from klaushackt.kontext import Kontext
from klaushackt.netz import SichererClient
from klaushackt.pruefer import alle_pruefer
from klaushackt.pruefer.code_muster import CodeMuster
from klaushackt.pruefer.ki import lerne_regeln
from klaushackt.scope import Scope
from klaushackt.wissen import Wissen

SCHNELL = {"geheimnisse", "code_muster", "abhaengigkeiten"}
REIHENFOLGE = ("kritisch", "hoch", "mittel", "niedrig", "info")


# ======================================================================
#  Terminal-Optik
# ======================================================================

class Optik:
    """Kleine ANSI-Werkzeugkiste (256 Farben). Ohne Farbe: reiner Text."""

    GRUEN, MINT, CYAN, PINK, GELB, ORANGE, ROT, GRAU, DUNKEL = 48, 121, 51, 205, 220, 208, 197, 245, 239
    SCHWERE = {
        # (Text im Tag, Vordergrund, Hintergrund oder None)
        "kritisch": (" KRITISCH ", 231, 197),
        "hoch": ("  HOCH    ", 208, None),
        "mittel": ("  MITTEL  ", 220, None),
        "niedrig": (" NIEDRIG  ", 51, None),
        "info": ("  INFO    ", 245, None),
    }
    BREITE = 66

    def __init__(self, farbe: bool) -> None:
        self.farbe = farbe
        if farbe and os.name == "nt":
            os.system("")  # VT-Modus in Windows-Konsolen einschalten

    @staticmethod
    def automatisch() -> "Optik":
        return Optik(sys.stdout.isatty() and not os.environ.get("NO_COLOR"))

    # --- Grundbausteine ---
    def f(self, text: str, vg: int | None = None, hg: int | None = None, fett: bool = False, dim: bool = False) -> str:
        if not self.farbe:
            return text
        codes = []
        if fett:
            codes.append("1")
        if dim:
            codes.append("2")
        if vg is not None:
            codes.append(f"38;5;{vg}")
        if hg is not None:
            codes.append(f"48;5;{hg}")
        return f"\033[{';'.join(codes)}m{text}\033[0m" if codes else text

    def dim(self, text: str) -> str:
        return self.f(text, self.GRAU)

    def tag(self, schwere: str) -> str:
        text, vg, hg = self.SCHWERE.get(schwere, (f" {schwere.upper():<8} ", 245, None))
        if not self.farbe:
            return f"[{text.strip():<8}]"
        return self.f(text, vg, hg, fett=True)

    def balken(self, wert: int, maximum: int, breite: int = 22, vg: int | None = None) -> str:
        if maximum <= 0:
            voll = 0
        else:
            voll = max(1, round(wert / maximum * breite)) if wert else 0
        return self.f("█" * voll, vg) + self.f("░" * (breite - voll), self.DUNKEL)

    # --- Boxen ---
    def box(self, titel: str, zeilen: list[tuple[str, str, str]], farbe: int | None = None) -> str:
        """zeilen = (zeichen, schluessel, wert). Feste Breite, Werte werden gekürzt."""
        farbe = farbe if farbe is not None else self.GRUEN
        b = self.BREITE
        kopf = f"┌─[ {titel} ]" + "─" * (b - len(titel) - 7) + "┐"
        aus = [self.f(kopf, farbe)]
        for zeichen, schluessel, wert in zeilen:
            platz = b - 4 - 4 - 14
            wert = wert if len(wert) <= platz else wert[: platz - 1] + "…"
            inhalt_roh = f"[{zeichen}] {schluessel:<13}{wert}"
            luecke = " " * (b - 4 - len(inhalt_roh))
            z_farbe = self.GRUEN if zeichen == "✔" else self.GELB
            inhalt = (self.f("[", self.GRAU) + self.f(zeichen, z_farbe, fett=True) + self.f("]", self.GRAU)
                      + " " + self.f(f"{schluessel:<13}", self.MINT) + wert)
            aus.append(self.f("│ ", farbe) + inhalt + luecke + self.f(" │", farbe))
        aus.append(self.f("└" + "─" * (b - 2) + "┘", farbe))
        return "\n".join(aus)


def parse_dauer(text: str) -> int:
    """'2h', '90m', '1h30m', '45s', '120' (Minuten) → Sekunden."""
    text = text.strip().lower()
    if text.isdigit():
        return int(text) * 60
    teile = re.findall(r"(\d+(?:\.\d+)?)\s*(h|std|m|min|s|sek)", text)
    if not teile or "".join(f"{z}{e}" for z, e in teile) != re.sub(r"\s+", "", text):
        raise ValueError(f"Unbekannte Dauer: {text!r} (Beispiele: 2h, 90m, 1h30m)")
    faktor = {"h": 3600, "std": 3600, "m": 60, "min": 60, "s": 1, "sek": 1}
    return int(sum(float(z) * faktor[e] for z, e in teile))


class Lauf:
    def __init__(self, scope: Scope, wissen: Wissen, daten: Path, dauer_s: int,
                 min_schwere: str = "niedrig", ki: bool = True, nur: set[str] | None = None,
                 farbe: bool = True) -> None:
        self.scope, self.wissen, self.dauer_s = scope, wissen, dauer_s
        self.min_schwere, self.ki, self.nur, self.farbe = min_schwere, ki, nur, farbe
        self.o = Optik(farbe)
        self.ordner = daten / re.sub(r"[^\w\-]", "_", scope.name)
        self.ordner.mkdir(parents=True, exist_ok=True)
        self.lauf_id = 0
        self.abbruch = False
        self.statistik: Counter = Counter()
        self.pruefer_status: list[dict] = []
        self._client: SichererClient | None = None
        self._deadline = 0.0

    # ------------------------------------------------------------------
    def _aus(self, text: str = "") -> None:
        print(text, flush=True)

    def log(self, text: str) -> None:
        """Meldung eines Prüfers oder des Planers: Zeitstempel + gedimmter Text."""
        zeit = time.strftime("%H:%M:%S")
        self._aus(f"{self.o.f(zeit, Optik.DUNKEL)}  {self.o.f('·', Optik.GRUEN)} {self.o.dim(text)}")
        if self.lauf_id:
            self.wissen.ereignis(self.lauf_id, text)

    def _ereignis(self, text: str) -> None:
        if self.lauf_id:
            self.wissen.ereignis(self.lauf_id, text)

    def _zeige_fund(self, f, ergebnis: str) -> None:
        if rang(f.schwere) < rang(self.min_schwere):
            return
        o = self.o
        ort = f"{f.ort}:{f.zeile}" if f.zeile else f.ort
        marke = {"neu": o.f("+neu", Optik.GRUEN, fett=True), "wieder_da": o.f("!wieder da", Optik.PINK, fett=True),
                 "bekannt": o.dim("bekannt")}.get(ergebnis, o.dim(ergebnis))
        if not o.farbe:
            marke = {"neu": "+neu", "wieder_da": "!wieder da"}.get(ergebnis, ergebnis)
        titel = o.f(f.titel, fett=f.schwere in ("kritisch", "hoch"))
        self._aus(f"   {o.tag(f.schwere)} {titel}  {marke}")
        self._aus(f"   {' ' * 10} {o.dim('└─ ' + ort)}")

    def _status(self) -> str:
        """Kurze Statuszeile: Restzeit, Anfragen, Funde gesamt."""
        rest = max(0, int(self._deadline - time.monotonic()))
        m, s = divmod(rest, 60)
        h, m = divmod(m, 60)
        anfragen = self._client.anzahl if self._client else 0
        gesamt = sum(self.statistik.values())
        teile = [f"⏱ {h:02d}:{m:02d}:{s:02d} übrig", f"⇅ {anfragen} req", f"Σ {gesamt} funde"]
        if self.statistik.get("kritisch"):
            teile.append(self.o.f(f"☠ {self.statistik['kritisch']} kritisch", Optik.ROT, fett=True))
        return self.o.dim("   " + "  ·  ".join(teile[:3])) + ("  ·  " + teile[3] if len(teile) > 3 else "")

    # ------------------------------------------------------------------
    def _preflight(self) -> None:
        s = self.scope
        heute = dt.date.today()
        tage = (s.gueltig_bis - heute).days
        ziele = []
        if s.repos:
            ziele.append(f"{len(s.repos)} repo")
        if s.urls:
            ziele.append(f"{len(s.urls)} url")
        if s.ausgeschlossen:
            ziele.append(f"{len(s.ausgeschlossen)} ausgenommen")
        lesend = s.erlaubte_methoden <= {"GET", "HEAD", "OPTIONS"}
        erlaubnis = str(s.erlaubnis.name) if s.erlaubnis else s.erlaubnis_text
        zeilen = [
            ("✔", "erlaubnis", erlaubnis or "–"),
            ("✔", "gültig bis", f"{s.gueltig_bis} (noch {tage} Tage)"),
            ("✔", "ziele", " · ".join(ziele) or "–"),
            ("✔", "tempo", f"max {s.anfragen_pro_sekunde:g} req/s · budget {s.max_anfragen_gesamt}"),
            ("✔" if lesend else "!", "methoden",
             " ".join(sorted(s.erlaubte_methoden)) + (" (nur lesend)" if lesend else " (verändernd!)")),
            ("✔", "testkonten", ", ".join(k.name for k in s.testkonten) or "keine"),
            ("✔", "zeitbudget", self._dauer_text(self.dauer_s)),
        ]
        self._aus(self.o.box(f"PRE-FLIGHT · {s.name}", zeilen))
        self._aus(self.o.f("   >> alle checks grün. ", Optik.GRUEN, fett=True)
                  + self.o.dim(f"lauf #{self.lauf_id} startet. strg+c bricht sauber ab."))
        for zeile in s.zusammenfassung().splitlines():
            self._ereignis("  " + zeile)

    def starte(self) -> Path:
        self.scope.pruefe_gueltig()
        self.lauf_id = self.wissen.neuer_lauf(self.scope.name, self.dauer_s)
        deadline = time.monotonic() + self.dauer_s
        self._deadline = deadline
        client = None
        if self.scope.urls:
            client = SichererClient(self.scope, self.ordner / f"anfragen-lauf{self.lauf_id}.jsonl")
        self._client = client
        k = Kontext(scope=self.scope, wissen=self.wissen, lauf=self.lauf_id, client=client,
                    deadline=deadline, log=self.log, min_schwere=self.min_schwere, ki_aktiv=self.ki)

        alter_handler = signal.getsignal(signal.SIGINT)

        def stopp(_sig, _frame):
            if self.abbruch:
                raise KeyboardInterrupt
            self.abbruch = True
            k.deadline = time.monotonic()
            self._deadline = k.deadline
            self.log("Abbruch angefordert – aktueller Schritt wird sauber beendet, Bericht wird geschrieben …")

        signal.signal(signal.SIGINT, stopp)
        self._ereignis(f"Lauf #{self.lauf_id} für '{self.scope.name}' gestartet – "
                       f"Zeitbudget {self._dauer_text(self.dauer_s)}")
        self._preflight()

        vollstaendig: set[str] = set()
        try:
            pruefer = [p for p in alle_pruefer() if not self.nur or p.name in self.nur or p.art in self.nur]
            pruefer.sort(key=lambda p: (0 if p.name in SCHNELL else 1, -self.wissen.technik_gewicht(p.name)))
            for p in pruefer:
                if k.zeit_um():
                    self.pruefer_status.append({"name": p.name, "status": "keine Zeit mehr"})
                    continue
                ok, grund = p.verfuegbar(k)
                if not ok:
                    self._aus(self.o.f("[-]", Optik.DUNKEL) + " " + self.o.dim(f"modul :: {p.name:<16}") +
                              self.o.f(f"übersprungen – {grund}", Optik.DUNKEL))
                    self._ereignis(f"– {p.name}: übersprungen ({grund})")
                    self.pruefer_status.append({"name": p.name, "status": f"übersprungen: {grund}"})
                    continue
                if self._fuehre_aus(k, p):
                    vollstaendig.add(p.name)

            # ---- Lern-Runde: Variantensuche mit neu gelernten Regeln ----
            if not k.zeit_um() and self.scope.repos:
                neu = lerne_regeln(self.wissen, self.scope.name, self.log)
                if neu and not k.zeit_um():
                    self.log("Variantensuche: Code wird mit den neu gelernten Regeln erneut durchsucht")
                    self._fuehre_aus(k, CodeMuster(), name="variantensuche")

            rest = k.zeit_uebrig()
            if rest > 60 and not self.abbruch:
                self._aus()
                self.log(f"Alle Prüfungen fertig – {self._dauer_text(int(rest))} Restzeit nicht nötig. "
                         "Tipp: --ki aktivieren oder mehr Ziele/Testkonten in den Scope, damit mehr geprüft wird.")
        finally:
            signal.signal(signal.SIGINT, alter_handler)
            behoben = self.wissen.markiere_verschwundene_als_behoben(
                self.scope.name, self.lauf_id, vollstaendig & {"geheimnisse", "code_muster"})
            if behoben:
                self.log(f"{behoben} früherer Fund/Funde tauchen nicht mehr auf → als 'behoben' markiert")
            self.wissen.lauf_update(self.lauf_id, ende=time.time(),
                                    status="abgebrochen" if self.abbruch else "fertig", phase="",
                                    anfragen=client.anzahl if client else 0)
        pfad = schreibe_berichte(self.wissen, self.scope, self.lauf_id, self.ordner, self.min_schwere,
                                 self.pruefer_status, client.anzahl if client else 0)
        self._zusammenfassung(pfad)
        return pfad

    def _fuehre_aus(self, k: Kontext, p, name: str | None = None) -> bool:
        name = name or p.name
        o = self.o
        self._aus()
        self._aus(o.f("[>]", Optik.GRUEN, fett=True) + " " + o.f("modul", Optik.GRAU) + o.f(" :: ", Optik.PINK)
                  + o.f(name, Optik.MINT, fett=True) + "  " + o.dim(p.beschreibung))
        self._ereignis(f"▶ {name}: {p.beschreibung}")
        self.wissen.lauf_update(self.lauf_id, phase=name, anfragen=k.client.anzahl if k.client else 0)
        start = time.monotonic()
        anzahl = neu = ignoriert = 0
        fertig = True
        try:
            for f in p.laufe(k):
                if self.wissen.ist_fehlalarm(self.scope.name, f):
                    ignoriert += 1
                    continue
                ergebnis = self.wissen.speichere_fund(self.scope.name, self.lauf_id, f)
                anzahl += 1
                neu += ergebnis in ("neu", "wieder_da")
                self.statistik[f.schwere] += 1
                self._zeige_fund(f, ergebnis)
            if k.zeit_um():
                fertig = False
        except Exception as e:  # noqa: BLE001 – ein kaputter Prüfer darf den Lauf nicht beenden
            fertig = False
            self._aus(o.f("[x]", Optik.ROT, fett=True) + " " + o.f(f"{name}: Fehler – {type(e).__name__}: {e}", Optik.ROT))
            self._ereignis(f"✗ {name}: Fehler – {type(e).__name__}: {e}")
        dauer = time.monotonic() - start
        self.wissen.technik_lauf(p.name, dauer, neu)
        extra = f", {ignoriert} bekannte Fehlalarme ausgeblendet" if ignoriert else ""
        zeichen = o.f("✔", Optik.GRUEN, fett=True) if fertig else o.f("◐", Optik.GELB, fett=True)
        self._aus(f"   {zeichen} " + o.dim(f"{anzahl} funde ({neu} neu{extra}) in {dauer:.1f}s"))
        self._aus(self._status())
        self._ereignis(f"✔ {name}: {anzahl} Funde ({neu} neu{extra}) in {dauer:.1f}s")
        self.pruefer_status.append({"name": name, "status": "fertig" if fertig else "unvollständig",
                                    "funde": anzahl, "neu": neu, "sekunden": round(dauer, 1)})
        return fertig

    @staticmethod
    def _dauer_text(s: int) -> str:
        h, rest = divmod(s, 3600)
        m, sek = divmod(rest, 60)
        return (f"{h} h " if h else "") + (f"{m} min" if m else "") + (f" {sek} s" if not h and not m else "")

    def _zusammenfassung(self, pfad: Path) -> None:
        o = self.o
        maximum = max(self.statistik.values(), default=0)
        farben = {"kritisch": Optik.ROT, "hoch": Optik.ORANGE, "mittel": Optik.GELB, "niedrig": Optik.CYAN,
                  "info": Optik.GRAU}
        rahmen = o.f("║", Optik.GRUEN)
        titel = f"ERGEBNIS · lauf #{self.lauf_id} · {self.scope.name}"
        self._aus()
        self._aus(o.f("╔═[ ", Optik.GRUEN) + o.f(titel, Optik.GRUEN, fett=True) + o.f(" ]" + "═" * max(4, Optik.BREITE - len(titel) - 7), Optik.GRUEN))
        for s in REIHENFOLGE:
            n = self.statistik.get(s, 0)
            self._aus(f"{rahmen}  {o.tag(s)} {o.f(f'{n:>4}', farben[s], fett=n > 0)}  "
                      f"{o.balken(n, maximum, 30, farben[s])}")
        self._aus(rahmen)
        self._aus(f"{rahmen}  {o.f('bericht   →', Optik.MINT)} {pfad}")
        self._aus(f"{rahmen}  {o.f('dashboard →', Optik.MINT)} python -m klaushackt dashboard")
        self._aus(o.f("╚" + "═" * (Optik.BREITE - 1), Optik.GRUEN))
        if self.statistik.get("kritisch"):
            self._aus(o.f("   >> kritische funde zuerst anschauen. kaffee kann warten.", Optik.PINK))
        elif sum(self.statistik.values()) == 0:
            self._aus(o.dim("   >> nichts gefunden. heißt nicht „sicher“, nur „diese checks sind grün“."))
        self._aus()
        teile = [f"{self.statistik.get(s, 0)} {s}" for s in REIHENFOLGE]
        self._ereignis("Ergebnis: " + " · ".join(teile))
        self._ereignis(f"Bericht: {pfad}")
