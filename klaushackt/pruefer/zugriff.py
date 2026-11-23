"""Zugriffsrechte-Prüfung (IDOR / fehlerhafte Zugriffskontrolle) mit Testkonten.

Idee: Eine Ressource, die Testkonto A gehört, wird erst als A, dann als
Testkonto B und ohne Login abgerufen. Bekommt B (oder ein Anonymer) dieselben
Daten zu sehen, ist die Zugriffskontrolle kaputt – einer der häufigsten
kritischen Funde in Bug-Bounty-Programmen.

Es werden nur GET-Anfragen und nur Testkonten verwendet – nie echte Kunden.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable

from klaushackt.fund import Fund
from klaushackt.kontext import Kontext
from klaushackt.netz import Budgetende
from klaushackt.scope import ScopeFehler


def aehnlich(a: bytes, b: bytes) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:20000], b[:20000], autojunk=False).quick_ratio()


class Zugriff:
    name = "zugriff"
    art = "web"
    beschreibung = "Zugriffsrechte mit mehreren Testkonten vergleichen (IDOR)"

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]:
        if not k.scope.zugriff_pruefungen:
            return False, "keine [[zugriff_pruefung]] im Scope"
        if k.client is None:
            return False, "kein Netzwerk-Client"
        return True, ""

    def laufe(self, k: Kontext) -> Iterable[Fund]:
        konten = {t.name: t for t in k.scope.testkonten}
        for p in k.scope.zugriff_pruefungen:
            if k.zeit_um():
                return
            url, besitzer = p.get("url", ""), p.get("besitzer", "")
            if besitzer not in konten:
                k.log(f"Zugriff: Besitzer-Konto '{besitzer}' fehlt unter [[testkonten]] – übersprungen")
                continue
            try:
                eigen = k.client.anfrage(url, header=konten[besitzer].header, konto=besitzer)
            except (ScopeFehler, ConnectionError) as e:
                k.log(f"Zugriff: {e}")
                continue
            except Budgetende:
                return
            if eigen.status != 200:
                k.log(f"Zugriff: {url} liefert für den Besitzer HTTP {eigen.status} – Prüfung übersprungen")
                continue
            andere = [(n, konten[n].header) for n in p.get("fremde", [n for n in konten if n != besitzer]) if n in konten]
            if p.get("ohne_login", True):
                andere.append(("(ohne Login)", {}))
            for name, header in andere:
                try:
                    fremd = k.client.anfrage(url, header=header, konto=name)
                except (ScopeFehler, ConnectionError):
                    continue
                except Budgetende:
                    return
                q = aehnlich(eigen.koerper, fremd.koerper)
                if fremd.status == 200 and q >= 0.9:
                    anonym = name == "(ohne Login)"
                    yield Fund(
                        pruefer=self.name, regel="idor", sicherheit="hoch" if q > 0.98 else "mittel",
                        titel=("Fremde Daten ohne Login abrufbar" if anonym else
                               f"Konto '{name}' sieht Daten von '{besitzer}'"),
                        schwere="kritisch" if anonym else "hoch", cwe="CWE-639", ort=url,
                        ausschnitt=f"Besitzer {besitzer}: HTTP {eigen.status}, {len(eigen.koerper)} B · "
                                   f"{name}: HTTP {fremd.status}, {len(fremd.koerper)} B · Übereinstimmung {q:.0%}",
                        beschreibung=p.get("beschreibung") or
                        "Die Ressource gehört einem anderen Konto, wird aber trotzdem ausgeliefert. "
                        "Ändert ein Angreifer die ID in der URL, kann er die Daten aller Nutzer abgreifen.",
                        behebung="Bei jedem Zugriff serverseitig prüfen, ob das angemeldete Konto Eigentümer "
                                 "der Ressource ist (nicht nur, ob jemand angemeldet ist).",
                    )
