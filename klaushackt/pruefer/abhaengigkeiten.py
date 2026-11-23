"""Bekannte Sicherheitslücken in Abhängigkeiten über die öffentliche OSV-Datenbank.

Wichtig: Diese Anfragen gehen an api.osv.dev (öffentliche Datenbank), nicht an
das Testziel. Übertragen werden nur Paketnamen und Versionen.
"""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Iterable
from pathlib import Path

from klaushackt.fund import Fund
from klaushackt.kontext import Kontext, lies

OSV = "https://api.osv.dev/v1"
SCHWERE_MAP = {"CRITICAL": "kritisch", "HIGH": "hoch", "MODERATE": "mittel", "MEDIUM": "mittel", "LOW": "niedrig"}


def _pakete(pfad: Path) -> list[tuple[str, str, str]]:
    """(ökosystem, name, version) aus bekannten Manifest-/Lock-Dateien."""
    name = pfad.name.lower()
    text = lies(pfad)
    out: list[tuple[str, str, str]] = []
    if name.startswith("requirements") and name.endswith(".txt"):
        for z in text.splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+]+)", z)
            if m:
                out.append(("PyPI", m.group(1), m.group(3)))
    elif name == "package-lock.json":
        try:
            d = json.loads(text)
        except json.JSONDecodeError:
            return out
        for schluessel, info in (d.get("packages") or {}).items():
            if schluessel and "node_modules/" in schluessel and info.get("version"):
                out.append(("npm", schluessel.split("node_modules/")[-1], info["version"]))
    elif name == "package.json":
        try:
            d = json.loads(text)
        except json.JSONDecodeError:
            return out
        for abschnitt in ("dependencies", "devDependencies"):
            for paket, v in (d.get(abschnitt) or {}).items():
                m = re.match(r"^[\^~=v]?(\d+\.\d+\.\d+[\w.\-]*)$", str(v).strip())
                if m:
                    out.append(("npm", paket, m.group(1)))
    elif name == "composer.lock":
        try:
            d = json.loads(text)
        except json.JSONDecodeError:
            return out
        for p in d.get("packages", []) + d.get("packages-dev", []):
            out.append(("Packagist", p["name"], str(p.get("version", "")).lstrip("v")))
    elif name == "poetry.lock":
        for m in re.finditer(r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"', text):
            out.append(("PyPI", m.group(1), m.group(2)))
    return out


def _post(url: str, daten: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(daten).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "KlausHackt"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "KlausHackt"}), timeout=20) as r:
        return json.loads(r.read())


class Abhaengigkeiten:
    name = "abhaengigkeiten"
    art = "code"
    beschreibung = "Bekannte Lücken in Bibliotheken (OSV-Datenbank)"

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]:
        return (bool(k.scope.repos), "kein Quellcode im Scope")

    def laufe(self, k: Kontext) -> Iterable[Fund]:
        pakete: dict[tuple[str, str, str], str] = {}
        for pfad in k.dateien():
            if pfad.name.lower() in ("package-lock.json", "package.json", "composer.lock", "poetry.lock") or (
                    pfad.name.lower().startswith("requirements") and pfad.suffix == ".txt"):
                for p in _pakete(pfad):
                    pakete.setdefault(p, k.relativ(pfad))
        if not pakete:
            k.log("Abhängigkeiten: keine Manifest-Dateien mit festen Versionen gefunden")
            return
        liste = list(pakete)
        k.log(f"Abhängigkeiten: {len(liste)} Pakete werden in der OSV-Datenbank nachgeschlagen")
        try:
            ergebnisse = []
            for i in range(0, len(liste), 500):
                teil = liste[i:i + 500]
                antwort = _post(f"{OSV}/querybatch", {"queries": [
                    {"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in teil]})
                ergebnisse.extend(zip(teil, antwort.get("results", [])))
        except Exception as e:  # noqa: BLE001
            k.log(f"Abhängigkeiten: OSV nicht erreichbar ({e}). Tipp: 'pip-audit' oder 'osv-scanner' installieren.")
            return
        details_cache: dict[str, dict] = {}
        for (eco, paket, version), res in ergebnisse:
            for v in (res.get("vulns") or [])[:15]:
                vid = v["id"]
                if vid not in details_cache and len(details_cache) < 80 and not k.zeit_um():
                    try:
                        details_cache[vid] = _get(f"{OSV}/vulns/{vid}")
                    except Exception:  # noqa: BLE001
                        details_cache[vid] = {}
                d = details_cache.get(vid, {})
                sev = (d.get("database_specific") or {}).get("severity", "")
                schwere = SCHWERE_MAP.get(str(sev).upper(), "mittel")
                behoben = sorted({ev["fixed"] for a in d.get("affected", []) for r in a.get("ranges", [])
                                  for ev in r.get("events", []) if "fixed" in ev})
                aliase = ", ".join(d.get("aliases", [])[:3])
                yield Fund(
                    pruefer=self.name, regel=vid, titel=f"{paket} {version}: {d.get('summary') or vid}",
                    schwere=schwere, cwe=", ".join((d.get("database_specific") or {}).get("cwe_ids", [])[:2]),
                    beschreibung=(d.get("details") or d.get("summary") or "Bekannte Sicherheitslücke.")[:700]
                                 + (f" ({aliase})" if aliase else ""),
                    ort=pakete[(eco, paket, version)], ausschnitt=f"{paket}=={version}",
                    behebung=(f"Auf eine behobene Version aktualisieren: {', '.join(behoben[-3:])}."
                              if behoben else "Paket aktualisieren oder ersetzen."),
                    sicherheit="hoch", extra={"link": f"https://osv.dev/vulnerability/{vid}"},
                )
