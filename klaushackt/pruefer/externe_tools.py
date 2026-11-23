"""Bindet bewährte Open-Source-Scanner ein, wenn sie installiert sind:
Semgrep, Bandit und Gitleaks. Fehlt eines, wird es einfach übersprungen."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

from klaushackt.fund import Fund
from klaushackt.kontext import Kontext

SEMGREP = {"ERROR": "hoch", "WARNING": "mittel", "INFO": "niedrig"}
BANDIT = {"HIGH": "hoch", "MEDIUM": "mittel", "LOW": "niedrig"}


def _rel(k: Kontext, pfad: str) -> str:
    return k.relativ(Path(pfad).resolve())


class ExterneTools:
    name = "externe_tools"
    art = "code"
    beschreibung = "Semgrep, Bandit, Gitleaks (falls installiert)"

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]:
        if not k.scope.repos:
            return False, "kein Quellcode im Scope"
        if not any(shutil.which(t) for t in ("semgrep", "bandit", "gitleaks")):
            return False, "keines installiert (pip install semgrep bandit)"
        return True, ""

    def _lauf(self, k: Kontext, befehl: list[str]) -> str:
        timeout = max(30, min(900, int(k.zeit_uebrig())))
        try:
            r = subprocess.run(befehl, capture_output=True, text=True, timeout=timeout, check=False)
            return r.stdout
        except (subprocess.TimeoutExpired, OSError) as e:
            k.log(f"{befehl[0]}: abgebrochen ({e})")
            return ""

    def laufe(self, k: Kontext) -> Iterable[Fund]:
        for repo in k.scope.repos:
            if shutil.which("semgrep") and not k.zeit_um():
                k.log(f"Semgrep läuft auf {repo.name} …")
                aus = self._lauf(k, ["semgrep", "scan", "--config", "auto", "--json", "--quiet",
                                     "--metrics", "off", str(repo)])
                try:
                    for r in json.loads(aus or "{}").get("results", []):
                        x = r.get("extra", {})
                        yield Fund(pruefer=self.name, regel="semgrep:" + r.get("check_id", "?").split(".")[-1],
                                   titel=x.get("message", "Semgrep-Fund")[:120],
                                   schwere=SEMGREP.get(x.get("severity", ""), "mittel"),
                                   beschreibung=x.get("message", ""), ort=_rel(k, r["path"]),
                                   zeile=r.get("start", {}).get("line"), ausschnitt=(x.get("lines") or "")[:300],
                                   cwe=", ".join((x.get("metadata") or {}).get("cwe", [])[:1]) if isinstance(
                                       (x.get("metadata") or {}).get("cwe"), list) else "",
                                   sicherheit="mittel")
                except json.JSONDecodeError:
                    pass
            if shutil.which("bandit") and not k.zeit_um():
                k.log(f"Bandit läuft auf {repo.name} …")
                aus = self._lauf(k, ["bandit", "-r", "-f", "json", "-q", str(repo)])
                try:
                    for r in json.loads(aus or "{}").get("results", []):
                        yield Fund(pruefer=self.name, regel="bandit:" + r.get("test_id", "?"),
                                   titel=r.get("issue_text", "Bandit-Fund")[:120],
                                   schwere=BANDIT.get(r.get("issue_severity", ""), "mittel"),
                                   beschreibung=r.get("issue_text", ""), ort=_rel(k, r["filename"]),
                                   zeile=r.get("line_number"), ausschnitt=(r.get("code") or "")[:300],
                                   cwe=f"CWE-{(r.get('issue_cwe') or {}).get('id', '')}",
                                   sicherheit=BANDIT.get(r.get("issue_confidence", ""), "mittel"))
                except json.JSONDecodeError:
                    pass
            if shutil.which("gitleaks") and not k.zeit_um():
                k.log(f"Gitleaks durchsucht die Git-Historie von {repo.name} …")
                bericht = Path(k.wissen.pfad).parent / "gitleaks.json"
                self._lauf(k, ["gitleaks", "detect", "--source", str(repo), "--report-format", "json",
                               "--report-path", str(bericht), "--redact", "--no-banner"])
                try:
                    for r in json.loads(bericht.read_text() if bericht.exists() else "[]"):
                        yield Fund(pruefer=self.name, regel="gitleaks:" + r.get("RuleID", "?"),
                                   titel=f"Geheimnis in Git-Historie: {r.get('Description', '')}"[:120],
                                   schwere="hoch", cwe="CWE-798",
                                   beschreibung="Auch gelöschte Geheimnisse bleiben in der Git-Historie abrufbar. "
                                                f"Commit {str(r.get('Commit', ''))[:10]}.",
                                   ort=r.get("File", ""), zeile=r.get("StartLine"),
                                   ausschnitt=(r.get("Match") or "")[:200],
                                   behebung="Geheimnis widerrufen und neu erzeugen; Historie mit git filter-repo bereinigen.",
                                   sicherheit="hoch")
                finally:
                    bericht.unlink(missing_ok=True)
