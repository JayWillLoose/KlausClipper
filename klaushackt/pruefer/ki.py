"""Claude als Code-Prüfer, Triage und Regel-Lehrer.

Drei Aufgaben:
1. review:   Dateien lesen und Logikfehler finden, die Muster nie sehen
             (fehlende Rechteprüfungen, IDOR, Race Conditions, Geschäftslogik).
2. triage:   bestehende Funde bewerten – echt oder Fehlalarm?
3. lernen:   aus bestätigten Funden neue Suchregeln (Regex) ableiten,
             damit dasselbe Fehlermuster überall gefunden wird (Variantensuche).

Benötigt `pip install anthropic` und einen API-Key (ANTHROPIC_API_KEY oder
`ant auth login`). Ohne beides läuft KlausHackt einfach ohne KI weiter.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable

from klaushackt.fund import SCHWEREGRADE, Fund
from klaushackt.kontext import Kontext, datei_hash, lies

MODELL = os.environ.get("KLAUSHACKT_MODELL", "claude-opus-5-5")
MAX_ZEICHEN_PRO_DATEI = 60_000

SYSTEM = (
    "Du bist ein erfahrener Application-Security-Reviewer. Du prüfst Quellcode im Rahmen eines "
    "autorisierten Sicherheitsaudits des Eigentümers, damit Lücken behoben werden können. "
    "Melde nur Probleme, die realistisch ausnutzbar sind oder klar gegen sichere Praxis verstoßen. "
    "Achte besonders auf: fehlende Authentifizierung/Autorisierung, IDOR, Injection (SQL, Befehle, "
    "Templates), XSS, SSRF, Path Traversal, unsichere Deserialisierung, Geheimnisse im Code, "
    "kaputte Kryptografie, Race Conditions und Fehler in der Geschäftslogik. "
    "Schreibe alle Texte auf Deutsch, verständlich für Nicht-Experten. Erfinde nichts: Wenn du "
    "unsicher bist, setze sicherheit auf 'niedrig'. Keine Exploits, nur Beschreibung und Behebung."
)

FUND_SCHEMA = {
    "type": "object",
    "properties": {
        "funde": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "titel": {"type": "string"},
                    "schwere": {"type": "string", "enum": SCHWEREGRADE},
                    "zeile": {"type": "integer"},
                    "ausschnitt": {"type": "string"},
                    "beschreibung": {"type": "string"},
                    "behebung": {"type": "string"},
                    "cwe": {"type": "string"},
                    "sicherheit": {"type": "string", "enum": ["niedrig", "mittel", "hoch"]},
                },
                "required": ["titel", "schwere", "zeile", "ausschnitt", "beschreibung", "behebung", "cwe",
                             "sicherheit"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["funde"],
    "additionalProperties": False,
}

REGEL_SCHEMA = {
    "type": "object",
    "properties": {
        "regeln": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "endungen": {"type": "string"},
                    "muster": {"type": "string"},
                    "titel": {"type": "string"},
                    "schwere": {"type": "string", "enum": SCHWEREGRADE},
                    "beschreibung": {"type": "string"},
                    "behebung": {"type": "string"},
                    "cwe": {"type": "string"},
                },
                "required": ["id", "endungen", "muster", "titel", "schwere", "beschreibung", "behebung", "cwe"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["regeln"],
    "additionalProperties": False,
}


class KiNichtVerfuegbar(Exception):
    pass


def _client():
    try:
        import anthropic  # noqa: PLC0415
    except ImportError as e:
        raise KiNichtVerfuegbar("Python-Paket 'anthropic' fehlt (pip install anthropic)") from e
    try:
        return anthropic, anthropic.Anthropic()
    except Exception as e:  # noqa: BLE001 – fehlende Zugangsdaten u. ä.
        raise KiNichtVerfuegbar(f"Kein Zugang zur Claude-API: {e}") from e


def frage_json(prompt: str, schema: dict, max_tokens: int = 16000) -> dict:
    """Eine Anfrage mit garantiert gültigem JSON zurück (Structured Outputs)."""
    anthropic, client = _client()
    try:
        antwort = client.beta.messages.create(
            model=MODELL,
            max_tokens=max_tokens,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            output_config={"effort": "high", "format": {"type": "json_schema", "schema": schema}},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.RateLimitError as e:
        raise KiNichtVerfuegbar(f"Rate-Limit der Claude-API: {e}") from e
    except anthropic.APIStatusError as e:
        raise KiNichtVerfuegbar(f"Claude-API-Fehler {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise KiNichtVerfuegbar(f"Claude-API nicht erreichbar: {e}") from e
    if antwort.stop_reason == "refusal":
        grund = getattr(getattr(antwort, "stop_details", None), "category", None)
        raise KiNichtVerfuegbar(f"Claude hat diese Anfrage abgelehnt ({grund}).")
    if antwort.stop_reason == "max_tokens":
        raise KiNichtVerfuegbar("Antwort war zu lang und wurde abgeschnitten.")
    text = "".join(b.text for b in antwort.content if getattr(b, "type", "") == "text")
    return json.loads(text)


def ki_verfuegbar() -> tuple[bool, str]:
    try:
        _client()
        return True, ""
    except KiNichtVerfuegbar as e:
        return False, str(e)


class KiReview:
    name = "ki_review"
    art = "code"
    beschreibung = "Claude liest den Code und sucht Logik- und Rechtefehler"

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]:
        if not k.scope.repos:
            return False, "kein Quellcode im Scope"
        if not k.ki_aktiv:
            return False, "KI ausgeschaltet (--ki)"
        return ki_verfuegbar()

    def _prioritaet(self, k: Kontext) -> list:
        """Geänderte und noch nie geprüfte Dateien zuerst, dann Dateien mit
        sicherheitsrelevanten Namen."""
        wichtig = re.compile(r"(?i)(auth|login|user|admin|api|route|view|controller|server|app|db|query|upload|pay|token|session)")
        liste = []
        for p in k.dateien():
            if p.suffix.lower() in (".json", ".lock", ".toml", ".yml", ".yaml", ".md", ".txt"):
                continue
            h = datei_hash(p)
            rel = k.relativ(p)
            neu = not k.wissen.schon_geprueft(k.scope.name, rel, "datei", h, self.name)
            liste.append((0 if neu else 1, 0 if wichtig.search(rel) else 1, rel, p, h))
        liste.sort()
        return [(rel, p, h, prio == 0) for prio, _w, rel, p, h in liste]

    def laufe(self, k: Kontext) -> Iterable[Fund]:
        kandidaten = self._prioritaet(k)
        neue = sum(1 for *_x, ist_neu in kandidaten if ist_neu)
        k.log(f"KI-Review: {len(kandidaten)} Dateien, davon {neue} neu oder geändert seit dem letzten Lauf")
        for rel, pfad, h, ist_neu in kandidaten:
            if k.zeit_uebrig() < 60:
                k.log("KI-Review: Zeitbudget fast aufgebraucht – Rest beim nächsten Lauf")
                return
            if not ist_neu:
                continue  # unverändert & schon geprüft: keine Tokens verschwenden
            code = lies(pfad)
            if len(code) > MAX_ZEICHEN_PRO_DATEI:
                k.log(f"KI-Review: {rel} ist zu groß ({len(code)} Zeichen) – nur Muster-Prüfung")
                continue
            nummeriert = "\n".join(f"{i:5d}| {z}" for i, z in enumerate(code.splitlines(), 1))
            prompt = (f"Prüfe diese Datei aus dem Projekt '{k.scope.name}' auf Sicherheitslücken.\n"
                      f"Datei: {rel}\n\n<code>\n{nummeriert}\n</code>\n\n"
                      "Gib für jedes Problem die Zeilennummer und den exakten Code-Ausschnitt an. "
                      "Gibt es keine Probleme, liefere eine leere Liste.")
            try:
                ergebnis = frage_json(prompt, FUND_SCHEMA)
            except KiNichtVerfuegbar as e:
                k.log(f"KI-Review gestoppt: {e}")
                return
            except json.JSONDecodeError:
                k.log(f"KI-Review: unlesbare Antwort zu {rel} – übersprungen")
                continue
            anzahl = 0
            for f in ergebnis.get("funde", []):
                anzahl += 1
                yield Fund(pruefer=self.name, regel="ki:" + re.sub(r"[^a-z0-9]+", "-", f["titel"].lower())[:40],
                           titel=f["titel"], schwere=f["schwere"], beschreibung=f["beschreibung"], ort=rel,
                           zeile=f["zeile"], ausschnitt=f["ausschnitt"][:300], behebung=f["behebung"],
                           cwe=f["cwe"], sicherheit=f["sicherheit"])
            k.wissen.als_geprueft(k.scope.name, rel, "datei", h, self.name)
            k.log(f"KI-Review: {rel} → {anzahl} Fund(e)")


FESTE_WOERTER = {"True", "False", "None", "true", "false", "null", "await", "new", "return", "this", "self"}


def verallgemeinere(ausschnitt: str) -> str:
    """Macht aus einer konkreten Code-Zeile ein Suchmuster für Varianten:
    Funktions-/Methodennamen und Schlüsselwort-Argumente bleiben erhalten
    (sie tragen die Bedeutung), Variablennamen, Zahlen und String-Inhalte
    werden verallgemeinert."""
    kern = re.sub(r"\s+", " ", ausschnitt).strip()[:160]
    kern = re.sub(r"(['\"])(?:(?!\1).)*\1", "\x00", kern)  # String-Inhalte -> Platzhalter
    tokens = re.findall(r"[A-Za-z_]\w*|\d+|\s+|\x00|.", kern)
    teile = []
    for i, t in enumerate(tokens):
        folgend = next((x for x in tokens[i + 1:] if not x.isspace()), "")
        vorher = next((x for x in reversed(tokens[:i]) if not x.isspace()), "")
        ist_kwarg = folgend == "=" and vorher in ("(", ",")
        if t == "\x00":
            teile.append(r"""["'`].*?["'`]""")
        elif t.isspace():
            teile.append(r"\s*")
        elif t.isdigit():
            teile.append(r"\d+")
        elif re.match(r"[A-Za-z_]", t):
            if folgend == "(" or ist_kwarg or t in FESTE_WOERTER:
                teile.append(re.escape(t))
            else:
                teile.append(r"\w+")
        else:
            teile.append(re.escape(t))
    muster = "".join(teile)
    return re.sub(r"(\\s\*)+", r"\\s*", muster)


def lerne_regeln(wissen, scope: str, log) -> int:
    """Lern-Loop: Aus bestätigten Funden neue Regex-Regeln ableiten.
    Ohne KI wird eine einfache Regel direkt aus dem Code-Ausschnitt erzeugt."""
    bestaetigt = [f for f in wissen.funde(scope=scope, status="bestaetigt")
                  if f["pruefer"] in ("ki_review", "code_muster", "externe_tools") and f["ausschnitt"]]
    if not bestaetigt:
        return 0
    neu = 0
    ok, _grund = ki_verfuegbar()
    if ok:
        beispiele = "\n\n".join(
            f"- Titel: {f['titel']}\n  Datei: {f['ort']}\n  CWE: {f['cwe']}\n  Code: {f['ausschnitt']}"
            for f in bestaetigt[:20])
        prompt = ("Diese Sicherheitslücken wurden vom Projekteigentümer als echt bestätigt:\n\n"
                  f"{beispiele}\n\n"
                  "Leite daraus allgemeine Python-Regex-Muster (re-Modul, eine Zeile, IGNORECASE) ab, die "
                  "VARIANTEN desselben Fehlers an anderen Stellen finden – nicht nur exakt diese Zeile. "
                  "Die Muster sollen präzise genug sein, um wenige Fehlalarme zu erzeugen. "
                  "'endungen' ist eine Komma-Liste wie '.py,.js' oder '*'. id in kebab-case mit Präfix 'gelernt-'.")
        try:
            daten = frage_json(prompt, REGEL_SCHEMA, max_tokens=8000)
            for r in daten.get("regeln", []):
                try:
                    re.compile(r["muster"])
                except re.error:
                    continue
                if wissen.regel_speichern({**r, "sprache": r["endungen"], "herkunft": "ki"}):
                    neu += 1
        except (KiNichtVerfuegbar, json.JSONDecodeError) as e:
            log(f"Lernen per KI nicht möglich ({e}) – nutze einfache Ableitung")
    if neu == 0:
        for f in bestaetigt:
            muster = verallgemeinere(f["ausschnitt"])
            rid = "gelernt-" + f["fingerabdruck"][:8]
            endung = "." + f["ort"].rsplit(".", 1)[-1] if "." in f["ort"] else "*"
            if len(muster) > 12 and wissen.regel_speichern(dict(
                    id=rid, sprache=endung, muster=muster, titel=f"Variante von: {f['titel']}",
                    schwere=f["schwere"], beschreibung=f["beschreibung"], behebung=f["behebung"],
                    cwe=f["cwe"], herkunft=f["fingerabdruck"])):
                neu += 1
    if neu:
        log(f"Lern-Loop: {neu} neue Suchregel(n) aus bestätigten Funden gelernt")
    return neu
