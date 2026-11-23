"""Der einzige Weg ins Netz: gedrosselt, scope-geprüft, protokolliert.

Kein Prüfer darf selbst Anfragen schicken – alles läuft durch `SichererClient`.
So kann ein Fehler in einem Prüfer nie zu einem Massenscan werden.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from klaushackt import __version__
from klaushackt.scope import Scope, ScopeFehler

USER_AGENT = f"KlausHackt/{__version__} (autorisierter Sicherheitstest)"
MAX_ANTWORT_BYTES = 2_000_000


class Budgetende(Exception):
    """Anfrage-Budget aufgebraucht oder Ziel signalisiert Überlastung."""


@dataclass
class Antwort:
    url: str
    status: int
    header: dict[str, str]
    koerper: bytes
    dauer: float
    roh_header: list = field(default_factory=list)

    def text(self) -> str:
        return self.koerper.decode("utf-8", "replace")

    def header_liste(self, name: str) -> list[str]:
        return [w for k, w in self.roh_header if k.lower() == name.lower()]


class Drossel:
    """Token-Bucket ohne Burst: Anfragen kommen nie schneller als erlaubt."""

    def __init__(self, pro_sekunde: float) -> None:
        self.abstand = 1.0 / pro_sekunde
        self._naechste = 0.0
        self._lock = threading.Lock()

    def warte(self) -> None:
        with self._lock:
            jetzt = time.monotonic()
            start = max(jetzt, self._naechste)
            self._naechste = start + self.abstand
        pause = start - time.monotonic()
        if pause > 0:
            time.sleep(pause)

    def bremse(self, faktor: float) -> None:
        """Bei 429/503 langsamer werden – nie schneller."""
        with self._lock:
            self.abstand *= faktor


class _KeineWeiterleitung(urllib.request.HTTPRedirectHandler):
    # Weiterleitungen nicht automatisch folgen – das Ziel könnte außerhalb des Scopes liegen.
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


class SichererClient:
    def __init__(self, scope: Scope, protokoll: Path, timeout: float = 15.0) -> None:
        self.scope = scope
        self.drossel = Drossel(scope.anfragen_pro_sekunde)
        self.timeout = timeout
        self.anzahl = 0
        self.protokoll = protokoll
        protokoll.parent.mkdir(parents=True, exist_ok=True)
        self._fehler_in_folge = 0
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener(_KeineWeiterleitung)

    def anfrage(self, url: str, methode: str = "GET", header: dict[str, str] | None = None,
                konto: str = "", folge_weiterleitungen: int = 3) -> Antwort:
        aktuelle = url
        for _ in range(folge_weiterleitungen + 1):
            antwort = self._einzeln(aktuelle, methode, header, konto)
            ort = antwort.header.get("location")
            if antwort.status in (301, 302, 303, 307, 308) and ort:
                naechste = urllib.parse.urljoin(aktuelle, ort)
                if not self.scope.url_erlaubt(naechste):
                    return antwort  # Weiterleitung aus dem Scope heraus: nicht folgen
                aktuelle = naechste
                continue
            return antwort
        return antwort

    def _einzeln(self, url: str, methode: str, header: dict[str, str] | None, konto: str) -> Antwort:
        methode = methode.upper()
        self.scope.pruefe_url(url, methode)  # wirft ScopeFehler
        with self._lock:
            if self.anzahl >= self.scope.max_anfragen_gesamt:
                raise Budgetende(f"Anfrage-Budget von {self.scope.max_anfragen_gesamt} erreicht.")
            self.anzahl += 1
        self.drossel.warte()

        h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        h.update(self.scope.header)
        h.update(header or {})
        req = urllib.request.Request(url, method=methode, headers=h)
        start = time.monotonic()
        status, roh_header, koerper = 0, [], b""
        try:
            with self._opener.open(req, timeout=self.timeout) as r:
                status = r.status
                roh_header = list(r.headers.items())
                koerper = r.read(MAX_ANTWORT_BYTES)
        except urllib.error.HTTPError as e:
            status = e.code
            roh_header = list(e.headers.items()) if e.headers else []
            try:
                koerper = e.read(MAX_ANTWORT_BYTES)
            except Exception:
                koerper = b""
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            self._log(url, methode, 0, time.monotonic() - start, konto, fehler=str(e))
            self._zaehle_fehler(True)
            raise ConnectionError(f"{url}: {e}") from e
        dauer = time.monotonic() - start
        self._log(url, methode, status, dauer, konto)

        if status in (429, 503):
            self.drossel.bremse(2.0)
            self._zaehle_fehler(True)
        else:
            self._zaehle_fehler(status >= 500)

        return Antwort(url=url, status=status, header={k.lower(): v for k, v in roh_header},
                       koerper=koerper, dauer=dauer, roh_header=roh_header)

    def _zaehle_fehler(self, fehler: bool) -> None:
        with self._lock:
            self._fehler_in_folge = self._fehler_in_folge + 1 if fehler else 0
            if self._fehler_in_folge >= 5:
                raise Budgetende("Ziel antwortet wiederholt mit Fehlern – Abbruch zum Schutz des Ziels.")

    def _log(self, url: str, methode: str, status: int, dauer: float, konto: str, fehler: str = "") -> None:
        eintrag = {"zeit": time.strftime("%Y-%m-%dT%H:%M:%S"), "methode": methode, "url": url,
                   "status": status, "ms": round(dauer * 1000), "konto": konto}
        if fehler:
            eintrag["fehler"] = fehler
        with self._lock, self.protokoll.open("a", encoding="utf-8") as f:
            f.write(json.dumps(eintrag, ensure_ascii=False) + "\n")


__all__ = ["SichererClient", "Antwort", "Budgetende", "ScopeFehler", "Drossel"]
