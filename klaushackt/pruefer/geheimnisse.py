"""Sucht eingecheckte Geheimnisse: API-Keys, Tokens, private Schlüssel, Passwörter.

Geheimnisse werden im Bericht immer maskiert – der Bericht selbst soll kein
neues Datenleck werden.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable

from klaushackt.fund import Fund
from klaushackt.kontext import Kontext, lies

MUSTER = [
    ("aws-key", "AWS Access Key", "kritisch", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("github-token", "GitHub-Token", "kritisch", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    ("anthropic-key", "Anthropic API-Key", "kritisch", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    ("openai-key", "OpenAI API-Key", "kritisch", r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}"),
    ("google-key", "Google API-Key", "hoch", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("stripe-live", "Stripe Live-Key", "kritisch", r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
    ("slack-token", "Slack-Token", "hoch", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"),
    ("slack-webhook", "Slack-Webhook", "mittel", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),
    ("discord-webhook", "Discord-Webhook", "mittel", r"https://discord(app)?\.com/api/webhooks/\d+/[\w\-]+"),
    ("telegram-bot", "Telegram-Bot-Token", "hoch", r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"),
    ("private-key", "Privater Schlüssel", "kritisch", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("db-url-passwort", "Datenbank-URL mit Passwort", "hoch",
     r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:/@]+:[^\s@/]{3,}@"),
    ("jwt", "Fest eingebautes JWT", "mittel", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
]

# Zuweisung an verdächtig benannte Variable: password = "..."
ZUWEISUNG = re.compile(
    r"""(?i)\b([\w.\-]*(passw(or)?d|passwort|secret|api[_\-]?key|token|auth[_\-]?key|private[_\-]?key|client[_\-]?secret))\b"""
    r"""\s*[:=]\s*["']([^"'\s]{8,})["']"""
)
PLATZHALTER = re.compile(r"(?i)(xxx|changeme|example|beispiel|dummy|placeholder|your[_\-]|<|\$\{|\{\{|process\.env|os\.environ|getenv|test|fake|\*\*\*)")


def entropie(s: str) -> float:
    if not s:
        return 0.0
    haeufig = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in haeufig.values())


def maskiere(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return s[:4] + "…" + "*" * 6 + s[-2:]


class Geheimnisse:
    name = "geheimnisse"
    art = "code"
    beschreibung = "Eingecheckte API-Keys, Passwörter und Schlüssel"

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]:
        return (bool(k.scope.repos), "kein Quellcode im Scope")

    def laufe(self, k: Kontext) -> Iterable[Fund]:
        regexe = [(i, t, s, re.compile(m)) for i, t, s, m in MUSTER]
        for pfad in k.dateien():
            if k.zeit_um():
                return
            try:
                text = lies(pfad)
            except OSError:
                continue
            rel = k.relativ(pfad)
            ist_env = pfad.name.startswith(".env")
            for nr, zeile in enumerate(text.splitlines(), start=1):
                if "klaushackt: ignorieren" in zeile:
                    continue
                for rid, titel, schwere, rx in regexe:
                    m = rx.search(zeile)
                    if m:
                        yield self._fund(rid, titel, schwere, rel, nr, zeile, m.group(0), ist_env)
                m = ZUWEISUNG.search(zeile)
                if m:
                    wert = m.group(4)
                    if PLATZHALTER.search(wert) or entropie(wert) < 3.0:
                        continue
                    yield self._fund("passwort-im-code", f"Geheimnis in Variable '{m.group(1)}'", "hoch",
                                     rel, nr, zeile, wert, ist_env)

    def _fund(self, rid, titel, schwere, ort, zeile, roh, wert, ist_env) -> Fund:
        maskiert = roh.replace(wert, maskiere(wert)).strip()[:200]
        hinweis = (" Die Datei ist eine .env-Datei – prüfe, ob sie in .gitignore steht und nicht "
                   "mit ausgeliefert wird." if ist_env else "")
        return Fund(
            pruefer=self.name, regel=rid, titel=titel, schwere=schwere, cwe="CWE-798",
            beschreibung="Ein Geheimnis steht im Klartext im Code. Jeder mit Zugriff auf das Repo, "
                         "ein Backup oder ausgelieferte Dateien kann es benutzen." + hinweis,
            ort=ort, zeile=zeile, ausschnitt=maskiert,
            behebung="Geheimnis sofort beim Anbieter widerrufen/neu erzeugen, aus dem Code entfernen "
                     "und über Umgebungsvariablen oder einen Secret-Manager laden. Achtung: Es bleibt "
                     "in der Git-Historie, bis diese bereinigt ist.",
            sicherheit="hoch" if rid != "passwort-im-code" else "mittel",
        )
