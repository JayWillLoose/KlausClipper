"""ÜBUNGSZIEL – ABSICHTLICH UNSICHER. NIEMALS ÖFFENTLICH BETREIBEN.

Eine winzige Web-App mit eingebauten, typischen Lücken, damit man KlausHackt
gefahrlos ausprobieren kann. Lauscht nur auf 127.0.0.1.

Start:  python demo/ziel_app/server.py
"""

import json
import pickle  # noqa: F401  (absichtlich: Demo für den Muster-Prüfer)
import sqlite3
import subprocess
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

DEBUG = True
API_SECRET = "q8Zr2vLm9Xw4Tp1Ks7Yd3Hn"          # absichtlich: Geheimnis im Code
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"                  # offizieller AWS-Beispielschlüssel

STATIC = Path(__file__).parent / "static"
SITZUNGEN = {"anna-sitzung-123": "anna", "ben-sitzung-456": "ben"}
RECHNUNGEN = {
    "1001": {"id": 1001, "kunde": "anna", "betrag": "129,00 €", "iban": "DE89 3704 0044 0532 0130 00"},
    "1002": {"id": 1002, "kunde": "ben", "betrag": "54,90 €", "iban": "DE02 1203 0000 0000 2020 51"},
}

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE produkte (id TEXT, name TEXT)")
db.executemany("INSERT INTO produkte VALUES (?,?)", [("1", "Kaffee"), ("2", "Tee")])


def backup_erstellen(name):
    # absichtlich: Befehl aus Variable über die Shell
    subprocess.run(f"tar czf /tmp/{name}.tgz static", shell=True, check=False)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _antwort(self, code, inhalt, typ="text/html; charset=utf-8", extra=None):
        daten = inhalt.encode() if isinstance(inhalt, str) else inhalt
        self.send_response(code)
        self.send_header("Content-Type", typ)
        origin = self.headers.get("Origin")
        if origin:  # absichtlich: CORS spiegelt jede Herkunft – mit Cookies
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(daten)

    def _nutzer(self):
        for teil in self.headers.get("Cookie", "").split(";"):
            k, _, v = teil.strip().partition("=")
            if k == "session" and v in SITZUNGEN:
                return SITZUNGEN[v]
        return None

    def do_GET(self):
        url = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if url.path == "/":
                return self._antwort(200, (STATIC / "index.html").read_text(),
                                     extra={"Set-Cookie": "session_hint=demo; Path=/"})
            if url.path == "/suche":
                # absichtlich: reflektiertes XSS
                return self._antwort(200, f"<html><body><h1>Ergebnisse für {q.get('q', '')}</h1></body></html>")
            if url.path == "/produkt":
                # absichtlich: SQL-Injection + Stacktrace im Fehlerfall
                zeile = db.execute(f"SELECT name FROM produkte WHERE id = '{q.get('id', '')}'").fetchone()
                return self._antwort(200, f"<html><body><p>{zeile[0] if zeile else 'unbekannt'}</p></body></html>")
            if url.path.startswith("/api/rechnungen/"):
                if not self._nutzer():
                    return self._antwort(401, '{"fehler":"login nötig"}', "application/json")
                # absichtlich: IDOR – es wird nicht geprüft, wem die Rechnung gehört
                r = RECHNUNGEN.get(url.path.rsplit("/", 1)[-1])
                return self._antwort(200 if r else 404, json.dumps(r or {}), "application/json")
            datei = (STATIC / url.path.lstrip("/")).resolve()
            if datei.is_file() and STATIC.resolve() in datei.parents:  # absichtlich: liefert auch .env aus
                typ = "application/javascript" if datei.suffix == ".js" else "text/plain"
                return self._antwort(200, datei.read_bytes(), typ)
            return self._antwort(404, "<html><body>Nicht gefunden</body></html>")
        except Exception:
            # absichtlich: Debug-Ausgabe mit Stacktrace
            return self._antwort(500, f"<pre>{traceback.format_exc()}</pre>" if DEBUG else "Fehler")


if __name__ == "__main__":
    print("ÜBUNGSZIEL läuft auf http://127.0.0.1:8088 (absichtlich unsicher, nur lokal!)")
    ThreadingHTTPServer(("127.0.0.1", 8088), Handler).serve_forever()
