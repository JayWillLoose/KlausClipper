"""Alle Prüfer. Jeder Prüfer hat einen Namen, eine Art (code/web) und eine
Methode `laufe(kontext)`, die Funde liefert."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from klaushackt.fund import Fund
from klaushackt.kontext import Kontext


class Pruefer(Protocol):
    name: str
    art: str          # "code" oder "web"
    beschreibung: str

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]: ...

    def laufe(self, k: Kontext) -> Iterable[Fund]: ...


def alle_pruefer() -> list[Pruefer]:
    from klaushackt.pruefer.abhaengigkeiten import Abhaengigkeiten
    from klaushackt.pruefer.code_muster import CodeMuster
    from klaushackt.pruefer.externe_tools import ExterneTools
    from klaushackt.pruefer.geheimnisse import Geheimnisse
    from klaushackt.pruefer.ki import KiReview
    from klaushackt.pruefer.web_passiv import WebPassiv
    from klaushackt.pruefer.zugriff import Zugriff

    return [Geheimnisse(), CodeMuster(), Abhaengigkeiten(), ExterneTools(),
            WebPassiv(), Zugriff(), KiReview()]
