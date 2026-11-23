"""Adaptive Lastprobe: findet selbst die höchste Rate, die ein Ziel verträgt.

Der Kreislauf (AIMD – additives Erhöhen, multiplikatives Absenken):

  1. BEOBACHTEN  Eine Portion Anfragen schicken, Antwortzeit und Fehler messen.
  2. BEWERTEN    Mit der Grundlinie vergleichen: schnell & sauber = ok, Timeouts/Fehler = zu hoch.
  3. ANPASSEN    War es gut: Rate ein Stück rauf (+Schritt). Gab es Ärger: Rate halbieren.
  4. MERKEN      Die bewährte Rate speichern, damit der nächste Lauf dort startet, nicht bei null.

WICHTIG: Lastproben dürfen ausdrücklich das normale Tempolimit überschreiten, aber NUR gegen
den eigenen Rechner (127.0.0.1 / localhost / ::1). Gegen fremde Ziele verweigert KlausHackt die
Lastprobe – dort bleibt es bei höchstens 10 Anfragen/s, damit nichts einem fremden Programm schadet.
"""

from __future__ import annotations

import json
import statistics
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from klaushackt import __version__
from klaushackt.scope import Scope, ScopeFehler

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
HARTE_OBERGRENZE = 300.0        # auch lokal nicht sinnlos drüber
FENSTER_S = 4.0                 # Dauer einer Messportion
MIN_PROBEN = 12                 # so viele Anfragen braucht eine Portion mindestens
START_RATE = 4.0
SCHRITT = 2.0                   # additives Erhöhen: +2/s pro guter Runde
ABSENK_FAKTOR = 0.5            # multiplikatives Absenken: halbieren bei Ärger
USER_AGENT = f"KlausHackt-Lastprobe/{__version__} (eigener Rechner, autorisiert)"


def ist_loopback(scope: Scope) -> tuple[bool, str]:
    if not scope.urls:
        return False, "keine URLs im Scope"
    for u in scope.urls:
        host = (urlsplit(u).hostname or "").lower()
        if host not in LOOPBACK_HOSTS:
            return False, (f"Ziel '{host}' ist nicht dein eigener Rechner. Die Lastprobe läuft nur gegen "
                           "127.0.0.1 / localhost. Fremde Ziele werden nie über 10 Anfragen/s belastet.")
    return True, ""


@dataclass
class Messung:
    rate: float
    gesendet: int = 0
    ok: int = 0
    fehler: int = 0
    status_5xx: int = 0
    status_429: int = 0
    timeouts: int = 0
    resets: int = 0
    latenzen: list[float] = field(default_factory=list)

    @property
    def fehlerquote(self) -> float:
        return self.fehler / self.gesendet if self.gesendet else 0.0

    @property
    def p50(self) -> float:
        return statistics.median(self.latenzen) if self.latenzen else 0.0

    @property
    def p95(self) -> float:
        if not self.latenzen:
            return 0.0
        s = sorted(self.latenzen)
        return s[min(len(s) - 1, int(len(s) * 0.95))]

    @property
    def echte_rate(self) -> float:
        """Tatsächlich erreichter Durchsatz (ok-Antworten pro Sekunde im Fenster)."""
        if not self.latenzen:
            return 0.0
        return self.ok / FENSTER_S


def _eine_anfrage(url: str, header: dict, timeout: float) -> tuple[str, float, int]:
    req = urllib.request.Request(url, method="GET", headers=header)
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(65536)
            return "ok", time.monotonic() - start, r.status
    except urllib.error.HTTPError as e:
        dauer = time.monotonic() - start
        if e.code == 429:
            return "429", dauer, 429
        if e.code >= 500:
            return "5xx", dauer, e.code
        return "ok", dauer, e.code          # 4xx ist eine gültige, schnelle Antwort
    except TimeoutError:
        return "timeout", timeout, 0
    except (urllib.error.URLError, ConnectionResetError, ConnectionRefusedError, OSError) as e:
        grund = getattr(e, "reason", e)
        if isinstance(grund, TimeoutError):
            return "timeout", timeout, 0
        return "reset", time.monotonic() - start, 0


def sende_fenster(url: str, rate: float, header: dict, protokoll, timeout: float = 5.0) -> Messung:
    """BEOBACHTEN: Eine Portion Anfragen im Takt von `rate`/s senden und messen."""
    m = Messung(rate=rate)
    anzahl = max(MIN_PROBEN, int(rate * FENSTER_S))
    abstand = 1.0 / rate
    lock = threading.Lock()
    max_worker = min(int(rate * 2) + 4, 128)

    def auftrag(i: int):
        art, dauer, _status = _eine_anfrage(url, header, timeout)
        with lock:
            m.gesendet += 1
            m.latenzen.append(dauer)
            if art == "ok":
                m.ok += 1
            else:
                m.fehler += 1
                if art == "5xx":
                    m.status_5xx += 1
                elif art == "429":
                    m.status_429 += 1
                elif art == "timeout":
                    m.timeouts += 1
                elif art == "reset":
                    m.resets += 1

    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=max_worker) as pool:
        for i in range(anzahl):
            soll = start + i * abstand
            pause = soll - time.monotonic()
            if pause > 0:
                time.sleep(pause)
            pool.submit(auftrag, i)
    protokoll({"zeit": time.strftime("%H:%M:%S"), "rate": round(rate, 1), "gesendet": m.gesendet,
               "ok": m.ok, "fehler": m.fehler, "p50_ms": round(m.p50 * 1000),
               "p95_ms": round(m.p95 * 1000), "timeouts": m.timeouts, "resets": m.resets,
               "s5xx": m.status_5xx, "s429": m.status_429})
    return m


def bewerte(m: Messung, basis_p95: float) -> tuple[bool, str]:
    """BEWERTEN: War diese Rate ok? Gibt (gut, grund) zurück."""
    if m.fehlerquote > 0.10:
        return False, _fehlerbild(m)
    grenze = max(basis_p95 * 4, basis_p95 + 0.25)
    if basis_p95 > 0 and m.p95 > grenze:
        return False, (f"Antwortzeit bricht ein: p95 {m.p95*1000:.0f} ms gegenüber {basis_p95*1000:.0f} ms "
                       "in Ruhe. Das Ziel ist am Anschlag – Anfragen stauen sich, bevor es noch Fehler wirft.")
    return True, ""


def _fehlerbild(m: Messung) -> str:
    """Was ist kaputtgegangen – und warum?"""
    teile = []
    if m.timeouts:
        teile.append(f"{m.timeouts} Timeouts (Server antwortet nicht mehr rechtzeitig: Worker/Threads "
                     "oder Event-Loop sind überlastet, Anfragen stauen sich)")
    if m.resets:
        teile.append(f"{m.resets} abgebrochene Verbindungen (die Warteschlange für neue Verbindungen ist "
                     "voll, der Server lehnt weitere ab)")
    if m.status_429:
        teile.append(f"{m.status_429}× HTTP 429 (ein eingebautes Rate-Limit greift – genau die Grenze, "
                     "die ein Bug-Bounty-Programm meint)")
    if m.status_5xx:
        teile.append(f"{m.status_5xx}× HTTP 5xx (der Server macht unter Last Fehler oder stürzt ab)")
    return "; ".join(teile) or f"Fehlerquote {m.fehlerquote:.0%}"


@dataclass
class Ergebnis:
    sicher_rate: float
    knie_rate: float
    failure_mode: str
    runden: list[dict]
    basis_p95_ms: float


class Lastprobe:
    def __init__(self, scope: Scope, wissen, ordner: Path, dauer_s: int,
                 start_rate: float | None = None, max_rate: float = HARTE_OBERGRENZE,
                 log=print) -> None:
        self.scope = scope
        self.wissen = wissen
        self.ordner = ordner
        self.dauer_s = dauer_s
        self.max_rate = min(max_rate, HARTE_OBERGRENZE)
        self.log = log
        self.url = scope.urls[0]
        self.header = {"User-Agent": USER_AGENT, "Accept": "*/*", **scope.header}
        gemerkt = wissen.gelerntes_tempo(scope.name) if hasattr(wissen, "gelerntes_tempo") else None
        self.start_rate = start_rate or (gemerkt or START_RATE)
        self.protokoll_datei = ordner / "lastprobe.jsonl"
        self.runden: list[dict] = []

    def _log_json(self, eintrag: dict) -> None:
        self.ordner.mkdir(parents=True, exist_ok=True)
        with self.protokoll_datei.open("a", encoding="utf-8") as f:
            f.write(json.dumps(eintrag, ensure_ascii=False) + "\n")
        self.runden.append(eintrag)

    def starte(self) -> Ergebnis:
        ok, grund = ist_loopback(self.scope)
        if not ok:
            raise ScopeFehler(grund)
        self.scope.pruefe_gueltig()
        deadline = time.monotonic() + self.dauer_s

        self.log(f"Grundlinie messen bei {START_RATE:.0f} Anfragen/s …")
        basis = sende_fenster(self.url, START_RATE, self.header, self._log_json)
        if basis.fehlerquote > 0.2:
            self.log("Schon in Ruhe kommen Fehler – stimmt die URL/der Port? Abbruch.")
            return Ergebnis(0, 0, _fehlerbild(basis), self.runden, basis.p95 * 1000)
        basis_p95 = basis.p95
        self.log(f"  Grundlinie: p50 {basis.p50*1000:.0f} ms · p95 {basis_p95*1000:.0f} ms · sauber")

        rate = max(self.start_rate, START_RATE)
        sicher = START_RATE
        knie = 0.0
        failure = ""
        absenkungen = 0

        while time.monotonic() < deadline and rate <= self.max_rate:
            self.log(f"[beobachten] Portion bei {rate:.1f} Anfragen/s …")
            m = sende_fenster(self.url, rate, self.header, self._log_json)
            gut, grund = bewerte(m, basis_p95)
            if gut:
                sicher = rate
                self.log(f"  [ok] {rate:.1f}/s · p95 {m.p95*1000:.0f} ms · {m.ok}/{m.gesendet} sauber "
                         f"· echter Durchsatz ~{m.echte_rate:.0f}/s  → Rate hoch")
                rate = rate + SCHRITT                      # additives Erhöhen
                if knie and rate >= knie:                   # nach gefundenem Knie nicht wieder drüber
                    self.log(f"  Knie bei {knie:.1f}/s bereits gefunden – stabil bei {sicher:.1f}/s. Fertig.")
                    break
            else:
                knie = rate
                failure = grund
                self.log(f"  [!] {rate:.1f}/s bricht: {grund}")
                neu = max(START_RATE, rate * ABSENK_FAKTOR)  # multiplikatives Absenken
                absenkungen += 1
                self.log(f"  → Rate runter auf {neu:.1f}/s")
                rate = neu
                if absenkungen >= 3:
                    self.log("  Dreimal abgesenkt – sichere Rate ist eingependelt. Fertig.")
                    break
        else:
            if rate > self.max_rate:
                self.log(f"Obergrenze {self.max_rate:.0f}/s erreicht, ohne dass es brach. "
                         "Das Ziel verträgt mehr, als sinnvoll zu testen ist.")

        # MERKEN
        gemerkt = min(sicher, (knie * 0.8) if knie else sicher)
        if hasattr(self.wissen, "merke_tempo"):
            self.wissen.merke_tempo(self.scope.name, gemerkt, basis_p95)
        self.log(f"Gemerkt: sichere Startrate {gemerkt:.1f}/s für den nächsten Lauf.")
        return Ergebnis(sicher, knie, failure, self.runden, basis_p95 * 1000)
