"""Black-Box-Prüfung einer laufenden Website – ohne Quellcode.

Alles hier ist bewusst schonend: nur GET/HEAD, gedrosselt durch den
SicherenClient, eine kleine feste Liste an Pfaden statt Wortlisten-Bruteforce,
keine Formulare abschicken, keine Daten verändern.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Iterable
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from klaushackt.fund import Fund
from klaushackt.kontext import Kontext
from klaushackt.netz import Antwort, Budgetende
from klaushackt.pruefer.geheimnisse import MUSTER as GEHEIM_MUSTER
from klaushackt.pruefer.geheimnisse import maskiere
from klaushackt.scope import ScopeFehler

MAX_SEITEN = 60
BOESE_ORIGIN = "https://klaushackt-cors-test.invalid"

# Kleine, feste Liste typischer Datenlecks. Jede Datei hat eine Signatur,
# damit „Seite nicht gefunden"-Seiten mit Status 200 nicht als Fund zählen.
SENSIBLE_PFADE = [
    (".git/HEAD", r"^ref: refs/", "kritisch", "Git-Repository öffentlich",
     "Über /.git/ lässt sich der komplette Quellcode inklusive Historie herunterladen – oft samt Passwörtern."),
    (".git/config", r"\[core\]", "kritisch", "Git-Konfiguration öffentlich",
     "Verrät Repository-Adressen und manchmal Zugangsdaten."),
    (".env", r"(?m)^[A-Z_][A-Z0-9_]*\s*=", "kritisch", ".env-Datei öffentlich",
     "Enthält typischerweise Datenbank-Passwörter, API-Keys und geheime Schlüssel."),
    (".env.local", r"(?m)^[A-Z_][A-Z0-9_]*\s*=", "kritisch", ".env.local öffentlich", "Wie .env."),
    (".env.production", r"(?m)^[A-Z_][A-Z0-9_]*\s*=", "kritisch", ".env.production öffentlich", "Wie .env."),
    ("config.json", r"(?i)\"(password|secret|api_?key|token)\"", "hoch", "config.json mit Geheimnissen",
     "Konfigurationsdatei mit Zugangsdaten ist abrufbar."),
    ("docker-compose.yml", r"(?m)^services:", "mittel", "docker-compose.yml öffentlich",
     "Verrät Infrastruktur und oft Passwörter in Umgebungsvariablen."),
    ("backup.zip", r"^PK\x03\x04", "kritisch", "Backup-Archiv öffentlich", "Ein komplettes Backup ist herunterladbar."),
    ("backup.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "kritisch", "Datenbank-Dump öffentlich",
     "Ein Datenbank-Export mit potenziell allen Nutzerdaten ist abrufbar."),
    ("dump.sql", r"(?i)(CREATE TABLE|INSERT INTO)", "kritisch", "Datenbank-Dump öffentlich", "Wie backup.sql."),
    ("database.sqlite", r"^SQLite format 3", "kritisch", "SQLite-Datenbank öffentlich",
     "Die komplette Datenbank ist herunterladbar."),
    ("db.sqlite3", r"^SQLite format 3", "kritisch", "SQLite-Datenbank öffentlich", "Wie database.sqlite."),
    (".DS_Store", r"^\x00\x00\x00\x01Bud1", "niedrig", ".DS_Store öffentlich", "Verrät Datei- und Ordnernamen."),
    ("phpinfo.php", r"(?i)<title>phpinfo\(\)", "mittel", "phpinfo() öffentlich",
     "Verrät Serverkonfiguration, Pfade und Umgebungsvariablen."),
    ("server-status", r"(?i)Apache Server Status", "mittel", "Apache server-status öffentlich",
     "Zeigt aktuelle Anfragen inkl. URLs anderer Besucher."),
    ("actuator/env", r"(?i)\"(propertySources|activeProfiles)\"", "kritisch", "Spring Actuator /env offen",
     "Gibt Umgebungsvariablen inklusive Geheimnissen aus."),
    ("swagger.json", r"\"(swagger|openapi)\"\s*:", "info", "API-Dokumentation öffentlich",
     "Nicht unbedingt ein Problem, verrät aber alle Schnittstellen."),
    ("openapi.json", r"\"openapi\"\s*:", "info", "API-Dokumentation öffentlich",
     "Nicht unbedingt ein Problem, verrät aber alle Schnittstellen."),
    (".vscode/sftp.json", r"(?i)\"(password|host)\"", "kritisch", "SFTP-Zugangsdaten öffentlich",
     "Editor-Konfiguration mit Server-Zugangsdaten ist abrufbar."),
    ("wp-config.php.bak", r"DB_PASSWORD", "kritisch", "WordPress-Konfigurations-Backup öffentlich",
     "Enthält das Datenbank-Passwort im Klartext."),
    (".well-known/security.txt", r"(?i)^contact:", "info", "", ""),  # positiv: wird unten ausgewertet
]

FEHLER_SIGNATUREN = [
    (r"Traceback \(most recent call last\)", "Python-Fehlerseite mit Stacktrace"),
    (r"(?i)Werkzeug Debugger|The debugger caught an exception", "Werkzeug-Debugger aktiv"),
    (r"(?i)You have an error in your SQL syntax|SQLSTATE\[|PG::SyntaxError|sqlite3\.OperationalError|ORA-\d{5}",
     "SQL-Fehlermeldung"),
    (r"(?i)<b>(Fatal error|Warning|Notice)</b>:.*? in <b>/", "PHP-Fehlermeldung mit Pfad"),
    (r"(?i)at [\w.$]+\([\w]+\.java:\d+\)", "Java-Stacktrace"),
    (r"(?i)Error: .*\n\s+at .*\(/.*\.js:\d+:\d+\)", "Node.js-Stacktrace"),
]

SICHERHEITS_HEADER = [
    ("content-security-policy", "niedrig", "Content-Security-Policy fehlt",
     "Ohne CSP kann eingeschleustes JavaScript ungehindert laufen und Daten abgreifen.",
     "Header setzen, z. B. Content-Security-Policy: default-src 'self'; frame-ancestors 'none'"),
    ("x-content-type-options", "niedrig", "X-Content-Type-Options fehlt",
     "Browser könnten Dateien als ausführbaren Code interpretieren (MIME-Sniffing).",
     "X-Content-Type-Options: nosniff"),
    ("referrer-policy", "info", "Referrer-Policy fehlt",
     "Vollständige URLs (inkl. Tokens in Parametern) können an fremde Seiten weitergegeben werden.",
     "Referrer-Policy: strict-origin-when-cross-origin"),
]


class _Linksammler(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.skripte: list[str] = []
        self.formulare: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.skripte.append(a["src"])
        elif tag == "link" and a.get("href") and "stylesheet" not in (a.get("rel") or ""):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "felder": []}
            self.formulare.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["felder"].append({"name": a.get("name", ""), "type": (a.get("type") or "text").lower()})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _ohne_fragment(url: str) -> str:
    t = urlsplit(url)
    return urlunsplit((t.scheme, t.netloc, t.path or "/", t.query, ""))


class WebPassiv:
    name = "web_passiv"
    art = "web"
    beschreibung = "Black-Box: Header, Cookies, CORS, offene Dateien, Fehlerseiten, JS-Geheimnisse"

    def verfuegbar(self, k: Kontext) -> tuple[bool, str]:
        if not k.scope.urls:
            return False, "keine URLs im Scope"
        if k.client is None:
            return False, "kein Netzwerk-Client"
        return True, ""

    def laufe(self, k: Kontext) -> Iterable[Fund]:
        try:
            yield from self._laufe(k)
        except Budgetende as e:
            k.log(f"Web: gestoppt – {e}")

    # ------------------------------------------------------------------
    def _hole(self, k: Kontext, url: str, **kw) -> Antwort | None:
        try:
            return k.client.anfrage(url, **kw)
        except ScopeFehler:
            return None
        except ConnectionError as e:
            k.log(f"Web: nicht erreichbar – {e}")
            return None

    def _laufe(self, k: Kontext) -> Iterable[Fund]:
        besucht: set[str] = set()
        warteschlange = [_ohne_fragment(u) for u in k.scope.urls]
        skripte: set[str] = set()
        gemeldet_header: set[tuple[str, str]] = set()

        for basis in k.scope.urls:
            if k.zeit_um():
                return
            yield from self._basis_pruefungen(k, basis)

        # ---- Crawlen (begrenzt) ----
        while warteschlange and len(besucht) < MAX_SEITEN and not k.zeit_um():
            url = warteschlange.pop(0)
            if url in besucht or not k.scope.url_erlaubt(url):
                continue
            besucht.add(url)
            a = self._hole(k, url)
            if a is None:
                continue
            host = urlsplit(url).netloc
            yield from self._header_pruefen(k, a, host, gemeldet_header)
            yield from self._fehlerseite(k, a)
            if "html" not in a.header.get("content-type", ""):
                continue
            k.wissen.als_geprueft(k.scope.name, url, "seite", hashlib.sha1(a.koerper).hexdigest()[:16], self.name)
            p = _Linksammler()
            try:
                p.feed(a.text())
            except Exception:  # noqa: BLE001
                pass
            for f in p.formulare:
                yield from self._formular(k, url, f)
            for s in p.skripte:
                skripte.add(_ohne_fragment(urljoin(url, s)))
            for l in p.links:
                if l.startswith(("mailto:", "tel:", "javascript:", "data:")):
                    continue
                ziel = _ohne_fragment(urljoin(url, l))
                if ziel not in besucht and k.scope.url_erlaubt(ziel):
                    warteschlange.append(ziel)

        k.log(f"Web: {len(besucht)} Seiten und {len(skripte)} Skripte gefunden")
        for s in sorted(skripte):
            if k.zeit_um():
                return
            if k.scope.url_erlaubt(s):
                yield from self._skript(k, s)

        # ---- Reflexions-/Fehler-Probe an URLs mit Parametern ----
        mit_param = [u for u in besucht if urlsplit(u).query][:15]
        for u in mit_param:
            if k.zeit_um():
                return
            yield from self._reflexion(k, u)

    # ------------------------------------------------------------------
    def _basis_pruefungen(self, k: Kontext, basis: str) -> Iterable[Fund]:
        start = basis if basis.endswith("/") else basis + "/"
        # Referenz für „nicht gefunden" (gegen Soft-404-Fehlalarme)
        zufall = self._hole(k, urljoin(start, f"klaushackt-{secrets.token_hex(6)}"))
        ref_laenge = len(zufall.koerper) if zufall else -1

        for pfad, signatur, schwere, titel, text in SENSIBLE_PFADE:
            if k.zeit_um():
                return
            url = urljoin(start, pfad)
            a = self._hole(k, url)
            if pfad.endswith("security.txt"):
                if a is None or a.status != 200 or not re.search(signatur, a.text(), re.M):
                    yield Fund(pruefer=self.name, regel="keine-security-txt", titel="Keine security.txt",
                               schwere="info", ort=url, ausschnitt="/.well-known/security.txt fehlt",
                               beschreibung="Sicherheitsforscher finden keinen offiziellen Meldeweg für Lücken.",
                               behebung="security.txt mit Contact- und Expires-Feld anlegen (RFC 9116).")
                continue
            if a is None or a.status != 200 or not a.koerper:
                continue
            if abs(len(a.koerper) - ref_laenge) < 8 and zufall and zufall.status == 200:
                continue
            roh = a.koerper[:4096].decode("latin-1")
            if re.search(signatur, roh):
                beleg = roh[:120].splitlines()[0] if roh else ""
                for rid, _t, _s, rx in GEHEIM_MUSTER:
                    m = re.search(rx, beleg)
                    if m:
                        beleg = beleg.replace(m.group(0), maskiere(m.group(0)))
                yield Fund(pruefer=self.name, regel="offene-datei:" + pfad, titel=titel, schwere=schwere,
                           ort=url, ausschnitt=f"HTTP 200 · {len(a.koerper)} Bytes · {beleg[:80]!r}",
                           beschreibung=text, cwe="CWE-538",
                           behebung="Datei vom Webserver entfernen bzw. den Zugriff sperren; enthaltene "
                                    "Zugangsdaten als kompromittiert behandeln und erneuern.",
                           sicherheit="hoch")

        # CORS-Probe: spiegelt der Server eine fremde Herkunft zurück?
        a = self._hole(k, start, header={"Origin": BOESE_ORIGIN})
        if a is not None:
            acao = a.header.get("access-control-allow-origin", "")
            acac = a.header.get("access-control-allow-credentials", "").lower() == "true"
            if acao == BOESE_ORIGIN or acao == "null":
                yield Fund(pruefer=self.name, regel="cors-spiegel", ort=start,
                           titel="CORS akzeptiert jede fremde Website" + (" – mit Cookies" if acac else ""),
                           schwere="hoch" if acac else "mittel", cwe="CWE-942",
                           ausschnitt=f"Access-Control-Allow-Origin: {acao}; Allow-Credentials: {acac}",
                           beschreibung="Der Server übernimmt die Origin des Aufrufers ungeprüft. "
                                        + ("Da auch Cookies erlaubt sind, kann jede fremde Seite eingeloggten "
                                           "Nutzern ihre Daten abziehen." if acac else
                                           "Öffentliche Antworten können von jeder Seite gelesen werden."),
                           behebung="Origin gegen eine feste Erlaubt-Liste prüfen.", sicherheit="hoch")

    def _header_pruefen(self, k: Kontext, a: Antwort, host: str, gemeldet: set) -> Iterable[Fund]:
        if a.status >= 400 or "html" not in a.header.get("content-type", ""):
            return
        for name, schwere, titel, text, beh in SICHERHEITS_HEADER:
            if name not in a.header and (host, name) not in gemeldet:
                gemeldet.add((host, name))
                yield Fund(pruefer=self.name, regel="header:" + name, titel=titel, schwere=schwere,
                           ort=f"{urlsplit(a.url).scheme}://{host}/", ausschnitt=f"{name}: (fehlt)",
                           beschreibung=text, behebung=beh, cwe="CWE-693", sicherheit="hoch")
        csp = a.header.get("content-security-policy", "")
        xfo = a.header.get("x-frame-options", "")
        if not xfo and "frame-ancestors" not in csp and (host, "frame") not in gemeldet:
            gemeldet.add((host, "frame"))
            yield Fund(pruefer=self.name, regel="header:clickjacking", titel="Seite lässt sich in fremde Frames laden",
                       schwere="niedrig", ort=f"{urlsplit(a.url).scheme}://{host}/", cwe="CWE-1021",
                       ausschnitt="weder X-Frame-Options noch frame-ancestors",
                       beschreibung="Angreifer können die Seite unsichtbar einbetten und Klicks erschleichen (Clickjacking).",
                       behebung="Content-Security-Policy: frame-ancestors 'self' (oder X-Frame-Options: DENY).",
                       sicherheit="hoch")
        if a.url.startswith("https://") and "strict-transport-security" not in a.header and (host, "hsts") not in gemeldet:
            gemeldet.add((host, "hsts"))
            yield Fund(pruefer=self.name, regel="header:hsts", titel="HSTS fehlt", schwere="niedrig",
                       ort=f"https://{host}/", ausschnitt="Strict-Transport-Security: (fehlt)", cwe="CWE-319",
                       beschreibung="Beim ersten Aufruf über http:// kann die Verbindung abgefangen werden.",
                       behebung="Strict-Transport-Security: max-age=31536000; includeSubDomains", sicherheit="hoch")
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            wert = a.header.get(name, "")
            if re.search(r"\d+\.\d+", wert) and (host, name + "v") not in gemeldet:
                gemeldet.add((host, name + "v"))
                yield Fund(pruefer=self.name, regel="versionsangabe:" + name, titel="Server verrät Software-Version",
                           schwere="info", ort=f"{urlsplit(a.url).scheme}://{host}/", ausschnitt=f"{name}: {wert}",
                           beschreibung="Angreifer können gezielt nach bekannten Lücken dieser Version suchen.",
                           behebung="Versionsangabe im Webserver abschalten.", sicherheit="hoch")
        for c in a.header_liste("set-cookie"):
            cname = c.split("=", 1)[0].strip()
            klein = c.lower()
            fehlt = [f for f, ok in (("Secure", "secure" in klein or not a.url.startswith("https")),
                                     ("HttpOnly", "httponly" in klein), ("SameSite", "samesite" in klein)) if not ok]
            if fehlt and (host, "cookie:" + cname) not in gemeldet:
                gemeldet.add((host, "cookie:" + cname))
                sitzung = bool(re.search(r"(?i)sess|auth|token|sid|jwt|login", cname))
                yield Fund(pruefer=self.name, regel="cookie-flags", titel=f"Cookie '{cname}' ohne {', '.join(fehlt)}",
                           schwere="mittel" if sitzung and "HttpOnly" in fehlt else "niedrig",
                           ort=a.url, ausschnitt=c.split(";")[0][:20] + "…; " + "; ".join(p.strip() for p in c.split(";")[1:])[:150],
                           cwe="CWE-1004", sicherheit="hoch",
                           beschreibung="Fehlt HttpOnly, kann eingeschleustes JavaScript das Cookie stehlen; "
                                        "fehlt Secure, geht es unverschlüsselt über die Leitung; ohne SameSite "
                                        "sind CSRF-Angriffe leichter.",
                           behebung="Set-Cookie: …; Secure; HttpOnly; SameSite=Lax")
        if re.search(r"(?i)<title>Index of /|<h1>Index of /|Directory listing for /", a.text()[:3000]):
            yield Fund(pruefer=self.name, regel="verzeichnisliste", titel="Verzeichnisinhalt wird aufgelistet",
                       schwere="mittel", ort=a.url, ausschnitt="Index of /…", cwe="CWE-548", sicherheit="hoch",
                       beschreibung="Jeder kann alle Dateien im Ordner sehen und herunterladen – inklusive Backups.",
                       behebung="Directory Listing im Webserver abschalten (Options -Indexes / autoindex off).")

    def _fehlerseite(self, k: Kontext, a: Antwort) -> Iterable[Fund]:
        text = a.text()[:200_000]
        for muster, titel in FEHLER_SIGNATUREN:
            m = re.search(muster, text)
            if m:
                yield Fund(pruefer=self.name, regel="fehlerseite", titel=titel, schwere="mittel", ort=a.url,
                           ausschnitt=m.group(0)[:150], cwe="CWE-209", sicherheit="hoch",
                           beschreibung="Interne Fehlermeldungen verraten Code-Pfade, Bibliotheken und manchmal "
                                        "Datenbankstrukturen – eine Landkarte für Angreifer.",
                           behebung="Im Produktivbetrieb eine generische Fehlerseite zeigen; Details nur ins Log.")
                return

    def _formular(self, k: Kontext, url: str, f: dict) -> Iterable[Fund]:
        typen = {x["type"] for x in f["felder"]}
        namen = " ".join(x["name"].lower() for x in f["felder"])
        ziel = urljoin(url, f["action"] or url)
        if "password" in typen and f["method"] != "post":
            yield Fund(pruefer=self.name, regel="form-passwort-get", titel="Login-Formular sendet per GET",
                       schwere="mittel", ort=url, ausschnitt=f"<form method={f['method']} action={f['action']!r}>",
                       cwe="CWE-598", sicherheit="hoch",
                       beschreibung="Das Passwort landet in der Adresszeile, im Verlauf und in Server-Logs.",
                       behebung='method="post" verwenden.')
        if "password" in typen and ziel.startswith("http://"):
            yield Fund(pruefer=self.name, regel="form-passwort-http", titel="Passwort wird unverschlüsselt gesendet",
                       schwere="hoch", ort=url, ausschnitt=f"action={ziel}", cwe="CWE-319", sicherheit="hoch",
                       beschreibung="Jeder im selben Netz (z. B. öffentliches WLAN) kann das Passwort mitlesen.",
                       behebung="Formular ausschließlich über HTTPS absenden.")
        if f["method"] == "post" and not re.search(r"csrf|xsrf|_token|authenticity", namen):
            yield Fund(pruefer=self.name, regel="form-ohne-csrf", titel="Formular ohne erkennbares CSRF-Token",
                       schwere="niedrig", ort=url, ausschnitt=f"<form method=post action={f['action']!r}> Felder: {namen[:80]}",
                       cwe="CWE-352", sicherheit="niedrig",
                       beschreibung="Eine fremde Seite könnte das Formular im Namen eingeloggter Nutzer absenden. "
                                    "Fehlalarm möglich, falls SameSite-Cookies oder Header-Tokens schützen.",
                       behebung="CSRF-Token einbauen oder SameSite=Strict/Lax-Cookies verwenden.")

    def _skript(self, k: Kontext, url: str) -> Iterable[Fund]:
        a = self._hole(k, url)
        if a is None or a.status != 200:
            return
        text = a.text()
        for rid, titel, schwere, rx in GEHEIM_MUSTER:
            for m in re.finditer(rx, text):
                yield Fund(pruefer=self.name, regel="js-geheimnis:" + rid, titel=f"{titel} im ausgelieferten JavaScript",
                           schwere=schwere, ort=url, ausschnitt=maskiere(m.group(0)), cwe="CWE-798", sicherheit="hoch",
                           beschreibung="Jeder Besucher kann dieses Geheimnis im Browser auslesen.",
                           behebung="Geheimnis widerrufen; Aufrufe, die es brauchen, über das eigene Backend leiten.")
        endpunkte = sorted(set(re.findall(r"""["'`](/(?:api|v\d|graphql|admin|internal)[\w/\-.{}:]*)["'`]""", text)))
        for e in endpunkte[:200]:
            k.wissen.als_geprueft(k.scope.name, e, "endpunkt", "", "js-extrakt")
        if endpunkte:
            k.log(f"Web: {len(endpunkte)} API-Endpunkte aus {url.rsplit('/', 1)[-1]} in die App-Karte übernommen")
        if re.search(r"//[#@] sourceMappingURL=(?!data:)(\S+)", text):
            karte = urljoin(url, re.search(r"//[#@] sourceMappingURL=(\S+)", text).group(1))
            if k.scope.url_erlaubt(karte):
                b = self._hole(k, karte, methode="HEAD")
                if b is not None and b.status == 200:
                    yield Fund(pruefer=self.name, regel="sourcemap", titel="Source Map öffentlich",
                               schwere="niedrig", ort=karte, ausschnitt="HTTP 200", cwe="CWE-540", sicherheit="hoch",
                               beschreibung="Der unminifizierte Original-Quellcode des Frontends ist abrufbar.",
                               behebung="Source Maps nicht in Produktion ausliefern.")

    def _reflexion(self, k: Kontext, url: str) -> Iterable[Fund]:
        """Ersetzt Parameterwerte durch einen harmlosen Marker und prüft, ob er
        ungefiltert im HTML landet (Hinweis auf XSS) oder Fehler auslöst."""
        t = urlsplit(url)
        params = parse_qsl(t.query, keep_blank_values=True)
        for i, (name, _wert) in enumerate(params[:5]):
            marker = f"kh{secrets.token_hex(3)}"
            probe = f"{marker}'\"<{marker}>"
            neu = params.copy()
            neu[i] = (name, probe)
            ziel = urlunsplit((t.scheme, t.netloc, t.path, urlencode(neu), ""))
            a = self._hole(k, ziel)
            if a is None:
                continue
            text = a.text()
            if f"<{marker}>" in text and "html" in a.header.get("content-type", ""):
                yield Fund(pruefer=self.name, regel="reflektiert-xss", titel=f"Parameter '{name}' wird ungefiltert ausgegeben",
                           schwere="hoch", ort=url, ausschnitt=f"?{name}=<{marker}> erscheint roh im HTML",
                           cwe="CWE-79", sicherheit="mittel",
                           beschreibung="Eingaben aus der URL landen ohne Escaping im HTML. Damit kann ein präparierter "
                                        "Link JavaScript im Namen des Opfers ausführen (reflektiertes XSS).",
                           behebung="Ausgaben kontextgerecht escapen; CSP als zweite Verteidigungslinie.")
            for muster, titel in FEHLER_SIGNATUREN:
                m = re.search(muster, text)
                if m:
                    yield Fund(pruefer=self.name, regel="fehler-bei-eingabe", titel=f"{titel} bei Sonderzeichen in '{name}'",
                               schwere="hoch" if "SQL" in titel else "mittel", ort=url, ausschnitt=m.group(0)[:150],
                               cwe="CWE-89" if "SQL" in titel else "CWE-209", sicherheit="mittel",
                               beschreibung="Ein Anführungszeichen im Parameter löst einen Server-Fehler aus. "
                                            "Bei SQL-Fehlern ist das ein starkes Indiz für SQL-Injection.",
                           behebung="Eingaben nur über parametrisierte Abfragen verwenden; Fehlerdetails nicht ausgeben.")
                    break
