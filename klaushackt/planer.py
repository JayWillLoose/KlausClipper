"""Der Planer: führt einen Lauf mit Zeitbudget durch.

Reihenfolge: erst die schnellen Prüfer (liefern sofort Ergebnisse), dann die
langsamen – sortiert nach ihrer bisherigen Erfolgsquote aus der
Wissensdatenbank. Bleibt Zeit, startet eine Lern-Runde (Variantensuche).
"""

from __future__ import annotations

import re
import signal
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
FARBEN = {"kritisch": "\033[1;97;41m", "hoch": "\033[1;31m", "mittel": "\033[33m", "niedrig": "\033[36m",
          "info": "\033[2m"}
RESET = "\033[0m"


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
        self.ordner = daten / re.sub(r"[^\w\-]", "_", scope.name)
        self.ordner.mkdir(parents=True, exist_ok=True)
        self.lauf_id = 0
        self.abbruch = False
        self.statistik: Counter = Counter()
        self.pruefer_status: list[dict] = []

    # ------------------------------------------------------------------
    def log(self, text: str) -> None:
        zeit = time.strftime("%H:%M:%S")
        print(f"\033[2m{zeit}\033[0m  {text}" if self.farbe else f"{zeit}  {text}", flush=True)
        if self.lauf_id:
            self.wissen.ereignis(self.lauf_id, text)

    def _zeige_fund(self, f, ergebnis: str) -> None:
        if rang(f.schwere) < rang(self.min_schwere):
            return
        marke = {"neu": "NEU", "wieder_da": "WIEDER DA", "bekannt": "bekannt"}.get(ergebnis, ergebnis)
        ort = f"{f.ort}:{f.zeile}" if f.zeile else f.ort
        s = f.schwere.upper()
        if self.farbe:
            s = f"{FARBEN.get(f.schwere, '')} {s} {RESET}"
        print(f"          {s}  {f.titel}  \033[2m[{marke}] {ort}\033[0m" if self.farbe else
              f"          [{s}] {f.titel} [{marke}] {ort}", flush=True)

    # ------------------------------------------------------------------
    def starte(self) -> Path:
        self.scope.pruefe_gueltig()
        self.lauf_id = self.wissen.neuer_lauf(self.scope.name, self.dauer_s)
        deadline = time.monotonic() + self.dauer_s
        client = None
        if self.scope.urls:
            client = SichererClient(self.scope, self.ordner / f"anfragen-lauf{self.lauf_id}.jsonl")
        k = Kontext(scope=self.scope, wissen=self.wissen, lauf=self.lauf_id, client=client,
                    deadline=deadline, log=self.log, min_schwere=self.min_schwere, ki_aktiv=self.ki)

        alter_handler = signal.getsignal(signal.SIGINT)

        def stopp(_sig, _frame):
            if self.abbruch:
                raise KeyboardInterrupt
            self.abbruch = True
            k.deadline = time.monotonic()
            self.log("Abbruch angefordert – aktueller Schritt wird sauber beendet, Bericht wird geschrieben …")

        signal.signal(signal.SIGINT, stopp)
        self.log(f"Lauf #{self.lauf_id} für '{self.scope.name}' gestartet – Zeitbudget {self._dauer_text(self.dauer_s)}")
        for zeile in self.scope.zusammenfassung().splitlines():
            self.log("  " + zeile)

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
                    self.log(f"– {p.name}: übersprungen ({grund})")
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
        self.log(f"▶ {name}: {p.beschreibung}")
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
            self.log(f"✗ {name}: Fehler – {type(e).__name__}: {e}")
        dauer = time.monotonic() - start
        self.wissen.technik_lauf(p.name, dauer, neu)
        extra = f", {ignoriert} bekannte Fehlalarme ausgeblendet" if ignoriert else ""
        self.log(f"✔ {name}: {anzahl} Funde ({neu} neu{extra}) in {dauer:.1f}s")
        self.pruefer_status.append({"name": name, "status": "fertig" if fertig else "unvollständig",
                                    "funde": anzahl, "neu": neu, "sekunden": round(dauer, 1)})
        return fertig

    @staticmethod
    def _dauer_text(s: int) -> str:
        h, rest = divmod(s, 3600)
        m, sek = divmod(rest, 60)
        return (f"{h} h " if h else "") + (f"{m} min" if m else "") + (f" {sek} s" if not h and not m else "")

    def _zusammenfassung(self, pfad: Path) -> None:
        print()
        teile = [f"{self.statistik.get(s, 0)} {s}" for s in ("kritisch", "hoch", "mittel", "niedrig", "info")]
        self.log("Ergebnis: " + " · ".join(teile))
        self.log(f"Bericht: {pfad}")
        self.log("Dashboard: python -m klaushackt dashboard")
