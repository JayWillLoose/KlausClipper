"""Datenmodell für Funde und Schweregrade."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

SCHWEREGRADE = ["info", "niedrig", "mittel", "hoch", "kritisch"]
_RANG = {name: i for i, name in enumerate(SCHWEREGRADE)}


def rang(schwere: str) -> int:
    """Zahl für Sortierung: höher = schlimmer. Unbekannt zählt als info."""
    return _RANG.get(schwere, 0)


def pruefe_schwere(schwere: str) -> str:
    if schwere not in _RANG:
        raise ValueError(f"Unbekannter Schweregrad: {schwere!r} (erlaubt: {', '.join(SCHWEREGRADE)})")
    return schwere


@dataclass
class Fund:
    pruefer: str          # welches Modul hat es gefunden (z. B. "code_muster")
    regel: str            # Regel-ID (z. B. "js-innerhtml")
    titel: str
    schwere: str
    beschreibung: str
    ort: str              # Datei oder URL
    zeile: int | None = None
    ausschnitt: str = ""  # Code-/Antwort-Ausschnitt als Beleg
    behebung: str = ""
    cwe: str = ""
    sicherheit: str = "mittel"  # wie sicher ist der Fund: niedrig/mittel/hoch
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        pruefe_schwere(self.schwere)

    @property
    def fingerabdruck(self) -> str:
        """Stabil über Läufe hinweg: hängt nicht von der Zeilennummer ab,
        damit verschobener Code nicht als neuer Fund zählt."""
        norm = re.sub(r"\s+", " ", self.ausschnitt).strip()[:200]
        roh = f"{self.regel}|{self.ort}|{norm}"
        return hashlib.sha256(roh.encode("utf-8", "replace")).hexdigest()[:16]
