"""Scope: Was darf getestet werden – und was ausdrücklich nicht.

Ohne gültigen Scope startet KlausHackt keinen einzigen Test. Das ist die
wichtigste Sicherheitsregel des ganzen Tools.
"""

from __future__ import annotations

import datetime as dt
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# Harte Obergrenze, egal was im Scope steht. Bug-Bounty-Programme erlauben
# typischerweise 2–10 Anfragen/Sekunde; mehr wäre ein Massenscan.
MAX_ANFRAGEN_PRO_SEKUNDE = 10.0
STANDARD_ANFRAGEN_PRO_SEKUNDE = 2.0

# Methoden, die keine Daten verändern. Alles andere muss explizit erlaubt werden.
SICHERE_METHODEN = {"GET", "HEAD", "OPTIONS"}


class ScopeFehler(Exception):
    """Scope fehlt, ist ungültig, abgelaufen oder ein Ziel liegt außerhalb."""


@dataclass
class Testkonto:
    name: str
    rolle: str = ""
    header: dict[str, str] = field(default_factory=dict)  # z. B. Cookie / Authorization


@dataclass
class Scope:
    name: str
    datei: Path
    erlaubnis: Path | None
    erlaubnis_text: str
    gueltig_ab: dt.date | None
    gueltig_bis: dt.date
    repos: list[Path]
    urls: list[str]
    ausgeschlossen: list[str]
    anfragen_pro_sekunde: float
    max_anfragen_gesamt: int
    erlaubte_methoden: set[str]
    header: dict[str, str]
    testkonten: list[Testkonto]
    verboten: list[str]
    belohnungen: dict[str, str]
    zugriff_pruefungen: list[dict]
    plattform: str = ""
    programm_url: str = ""
    hinweise: str = ""

    # ---------- Prüfungen ----------

    def pruefe_gueltig(self, heute: dt.date | None = None) -> None:
        heute = heute or dt.date.today()
        if self.gueltig_ab and heute < self.gueltig_ab:
            raise ScopeFehler(f"Scope '{self.name}' gilt erst ab {self.gueltig_ab}.")
        if heute > self.gueltig_bis:
            raise ScopeFehler(f"Scope '{self.name}' ist seit {self.gueltig_bis} abgelaufen.")

    def url_erlaubt(self, url: str) -> bool:
        """Eine URL ist erlaubt, wenn sie unter einer Scope-URL liegt
        (gleiches Schema, gleicher Host, Pfad-Präfix) und nicht ausgeschlossen ist."""
        teile = urlsplit(url)
        if teile.scheme not in ("http", "https") or not teile.hostname:
            return False
        if teile.username or teile.password:
            return False
        for aus in self.ausgeschlossen:
            if _unter(teile, urlsplit(aus)):
                return False
        return any(_unter(teile, urlsplit(basis)) for basis in self.urls)

    def pruefe_url(self, url: str, methode: str = "GET") -> None:
        if not self.url_erlaubt(url):
            raise ScopeFehler(f"Außerhalb des Scopes: {url}")
        if methode.upper() not in self.erlaubte_methoden:
            raise ScopeFehler(f"Methode {methode} ist im Scope nicht erlaubt.")

    def zusammenfassung(self) -> str:
        zeilen = [
            f"Scope:        {self.name}",
            f"Gültig bis:   {self.gueltig_bis}",
            f"Erlaubnis:    {self.erlaubnis or self.erlaubnis_text}",
            f"Code:         {', '.join(map(str, self.repos)) or '–'}",
            f"URLs:         {', '.join(self.urls) or '–'}",
            f"Ausgenommen:  {', '.join(self.ausgeschlossen) or '–'}",
            f"Tempo:        max. {self.anfragen_pro_sekunde:g} Anfragen/s, "
            f"höchstens {self.max_anfragen_gesamt} insgesamt",
            f"Methoden:     {', '.join(sorted(self.erlaubte_methoden))}",
            f"Testkonten:   {', '.join(k.name for k in self.testkonten) or '–'}",
        ]
        return "\n".join(zeilen)


def _unter(teile, basis) -> bool:
    if teile.scheme != basis.scheme:
        return False
    if (teile.hostname or "").lower() != (basis.hostname or "").lower():
        return False
    if (teile.port or _std_port(teile.scheme)) != (basis.port or _std_port(basis.scheme)):
        return False
    basis_pfad = basis.path or "/"
    pfad = teile.path or "/"
    if basis_pfad.endswith("/"):
        return pfad.startswith(basis_pfad) or pfad + "/" == basis_pfad
    return pfad == basis_pfad or pfad.startswith(basis_pfad + "/")


def _std_port(schema: str) -> int:
    return 443 if schema == "https" else 80


def _datum(wert, feld: str) -> dt.date | None:
    if wert is None:
        return None
    if isinstance(wert, dt.datetime):
        return wert.date()
    if isinstance(wert, dt.date):
        return wert
    try:
        return dt.date.fromisoformat(str(wert))
    except ValueError as e:
        raise ScopeFehler(f"'{feld}' ist kein Datum (JJJJ-MM-TT): {wert!r}") from e


def lade_scope(pfad: str | Path) -> Scope:
    pfad = Path(pfad).resolve()
    if not pfad.is_file():
        raise ScopeFehler(f"Scope-Datei nicht gefunden: {pfad}")
    try:
        daten = tomllib.loads(pfad.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ScopeFehler(f"Scope-Datei ist kein gültiges TOML: {e}") from e

    basis = pfad.parent

    name = str(daten.get("name") or pfad.stem)

    # --- Erlaubnis ist Pflicht ---
    erl = daten.get("erlaubnis") or {}
    erlaubnis_datei = erl.get("nachweis")
    erlaubnis_text = str(erl.get("beschreibung") or "").strip()
    erlaubnis_pfad = None
    if erlaubnis_datei:
        erlaubnis_pfad = (basis / erlaubnis_datei).resolve()
        if not erlaubnis_pfad.is_file():
            raise ScopeFehler(f"Erlaubnis-Nachweis fehlt: {erlaubnis_pfad}")
    if not erlaubnis_pfad and not erlaubnis_text:
        raise ScopeFehler(
            "Keine Erlaubnis angegeben. Trage unter [erlaubnis] einen 'nachweis' "
            "(Datei) oder eine 'beschreibung' (z. B. Link zum Bug-Bounty-Programm) ein."
        )
    if erl.get("bestaetigt") is not True:
        raise ScopeFehler(
            "Setze unter [erlaubnis] 'bestaetigt = true', um zu bestätigen, dass eine "
            "gültige Erlaubnis für alle Ziele dieses Scopes vorliegt."
        )

    gueltig_bis = _datum(daten.get("gueltig_bis"), "gueltig_bis")
    if gueltig_bis is None:
        raise ScopeFehler("'gueltig_bis' fehlt. Jeder Scope braucht ein Ablaufdatum.")

    ziele = daten.get("ziele") or {}
    repos = [(basis / r).resolve() for r in ziele.get("repos", [])]
    for r in repos:
        if not r.exists():
            raise ScopeFehler(f"Code-Verzeichnis existiert nicht: {r}")
    urls = [str(u).rstrip() for u in ziele.get("urls", [])]
    for u in urls:
        t = urlsplit(u)
        if t.scheme not in ("http", "https") or not t.hostname:
            raise ScopeFehler(f"Ungültige Ziel-URL: {u!r}")
        if "*" in u:
            raise ScopeFehler(f"Platzhalter (*) sind nicht erlaubt – liste Hosts einzeln auf: {u}")
    if not repos and not urls:
        raise ScopeFehler("Der Scope enthält keine Ziele (weder 'repos' noch 'urls').")

    regeln = daten.get("regeln") or {}
    aps = float(regeln.get("anfragen_pro_sekunde", STANDARD_ANFRAGEN_PRO_SEKUNDE))
    if aps <= 0:
        raise ScopeFehler("'anfragen_pro_sekunde' muss größer als 0 sein.")
    aps = min(aps, MAX_ANFRAGEN_PRO_SEKUNDE)
    max_gesamt = int(regeln.get("max_anfragen_gesamt", 2000))
    methoden = {m.upper() for m in regeln.get("erlaubte_methoden", sorted(SICHERE_METHODEN))}

    konten = []
    for k in daten.get("testkonten", []):
        if not k.get("name"):
            raise ScopeFehler("Jedes Testkonto braucht einen 'name'.")
        konten.append(Testkonto(name=k["name"], rolle=k.get("rolle", ""),
                                header={str(a): str(b) for a, b in (k.get("header") or {}).items()}))

    programm = daten.get("programm") or {}

    return Scope(
        name=name,
        datei=pfad,
        erlaubnis=erlaubnis_pfad,
        erlaubnis_text=erlaubnis_text,
        gueltig_ab=_datum(daten.get("gueltig_ab"), "gueltig_ab"),
        gueltig_bis=gueltig_bis,
        repos=repos,
        urls=urls,
        ausgeschlossen=[str(a) for a in ziele.get("ausgeschlossen", [])],
        anfragen_pro_sekunde=aps,
        max_anfragen_gesamt=max_gesamt,
        erlaubte_methoden=methoden,
        header={str(a): str(b) for a, b in (regeln.get("header") or {}).items()},
        testkonten=konten,
        verboten=[str(v) for v in regeln.get("verboten", [])],
        belohnungen={str(a): str(b) for a, b in (programm.get("belohnungen") or {}).items()},
        zugriff_pruefungen=list(daten.get("zugriff_pruefung", [])),
        plattform=str(programm.get("plattform", "")),
        programm_url=str(programm.get("url", "")),
        hinweise=str(programm.get("hinweise", "")),
    )
