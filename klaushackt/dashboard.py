"""Lokales Dashboard: Läufe live verfolgen, Funde bestätigen oder als Fehlalarm
markieren – jede Markierung füttert den Lern-Loop.

Sicherheit des Dashboards selbst:
- lauscht nur auf 127.0.0.1
- prüft den Host-Header (Schutz gegen DNS-Rebinding)
- alle Änderungen nur per POST mit zufälligem CSRF-Token + Origin-Prüfung
- alle Inhalte werden escaped, CSP verbietet Scripts komplett
"""

from __future__ import annotations

import datetime as dt
import hmac
import html
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from klaushackt.bericht import CSS, LOGO, fund_html
from klaushackt.fund import SCHWEREGRADE, rang
from klaushackt.pruefer.ki import lerne_regeln
from klaushackt.wissen import Wissen

E = html.escape
TOKEN = secrets.token_urlsafe(24)
EXTRA_CSS = """
nav{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
nav a,nav span{font:600 12px var(--mono);padding:6px 10px;border-radius:3px;border:1px solid var(--li);
text-decoration:none;color:var(--le);background:#05070a}nav a:hover{color:var(--ti);border-color:var(--le)}
nav a.an{border-color:var(--ak);color:var(--ak);box-shadow:0 0 14px -6px var(--ak)}
nav a.an::before{content:"● ";font-size:9px;vertical-align:1px}
.live{display:flex;gap:10px;align-items:center}.punkt{width:9px;height:9px;border-radius:50%;background:var(--ak);
box-shadow:0 0 0 0 var(--ak);animation:p 1.6s infinite}@keyframes p{70%{box-shadow:0 0 0 10px transparent}}
@media (prefers-reduced-motion:reduce){.punkt,h1::after{animation:none}}
.ereignisse{font:12.5px/1.7 var(--mono);background:#05070a;border:1px solid var(--li);color:#b9f5d2;
border-radius:4px;padding:12px 14px;max-height:340px;overflow:auto;box-shadow:inset 0 0 40px rgba(43,255,143,.04)}
.ereignisse::before{content:"klaus@hackt:~$ tail -f lauf.log";display:block;color:var(--pink);margin-bottom:6px}
form{display:inline}
"""


def _seite(titel: str, inhalt: str, auffrischen: bool = False) -> bytes:
    meta = '<meta http-equiv="refresh" content="5">' if auffrischen else ""
    return f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">{meta}
<title>{E(titel)}</title><style>{CSS}{EXTRA_CSS}</style></head><body><div class="w">
<header style="display:grid;gap:10px"><pre class="logo">{E(LOGO)}</pre>
<span class="eb">Dashboard · nur lokal</span><h1>{E(titel)}</h1></header>
{inhalt}<footer>läuft nur auf 127.0.0.1 · jede markierung füttert den lern-loop</footer>
</div></body></html>""".encode()


def _knoepfe(fp: str, scope: str, zurueck: str) -> str:
    def k(status: str, text: str) -> str:
        return (f'<form method="post" action="/markiere"><input type="hidden" name="t" value="{TOKEN}">'
                f'<input type="hidden" name="fp" value="{E(fp)}"><input type="hidden" name="scope" value="{E(scope)}">'
                f'<input type="hidden" name="status" value="{status}"><input type="hidden" name="zurueck" value="{E(zurueck)}">'
                f'<button>{text}</button></form>')
    return ('<div class="btns">' + k("bestaetigt", "✔ Echt – bestätigen") + k("fehlalarm", "✕ Fehlalarm")
            + k("behoben", "Behoben") + k("neu", "Zurücksetzen") + "</div>")


class Handler(BaseHTTPRequestHandler):
    wissen: Wissen
    port: int

    def log_message(self, *_a):  # leise
        pass

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in (f"127.0.0.1:{self.port}", f"localhost:{self.port}")

    def _senden(self, code: int, koerper: bytes, typ: str = "text/html; charset=utf-8", extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", typ)
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(koerper)

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._senden(421, b"Falscher Host", "text/plain")
        teile = urlsplit(self.path)
        q = {k: v[0] for k, v in parse_qs(teile.query).items()}
        if teile.path == "/":
            return self._senden(200, self._uebersicht(q))
        return self._senden(404, b"Nicht gefunden", "text/plain")

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return self._senden(421, b"Falscher Host", "text/plain")
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{self.port}", f"http://localhost:{self.port}"):
            return self._senden(403, b"Fremde Herkunft", "text/plain")
        laenge = min(int(self.headers.get("Content-Length", "0") or 0), 10_000)
        daten = {k: v[0] for k, v in parse_qs(self.rfile.read(laenge).decode()).items()}
        if not hmac.compare_digest(daten.get("t", ""), TOKEN):
            return self._senden(403, b"Ungueltiges Token", "text/plain")
        zurueck = daten.get("zurueck", "/")
        if not zurueck.startswith("/") or zurueck.startswith("//"):
            zurueck = "/"
        if self.path == "/markiere":
            try:
                self.wissen.markiere(daten.get("fp", ""), daten.get("status", ""), daten.get("scope") or None)
            except ValueError:
                return self._senden(400, b"Ungueltiger Status", "text/plain")
            zurueck += f"#f-{daten.get('fp', '')}"
        elif self.path == "/lernen":
            lerne_regeln(self.wissen, daten.get("scope", ""), lambda _t: None)
        return self._senden(303, b"", extra={"Location": zurueck})

    # ------------------------------------------------------------------
    def _uebersicht(self, q: dict) -> bytes:
        db = self.wissen.db
        scopes = [r["scope"] for r in db.execute("SELECT DISTINCT scope FROM funde UNION SELECT DISTINCT scope FROM laeufe")]
        scope = q.get("scope") or (scopes[0] if scopes else "")
        status = q.get("status", "offen")
        min_s = q.get("min", "niedrig")
        if not scopes:
            return _seite("Noch keine Läufe",
                          "<p>Starte einen Lauf: <code>python -m klaushackt start --scope scopes/demo.toml --dauer 10m</code></p>")

        def link(**neu) -> str:
            p = {"scope": scope, "status": status, "min": min_s, **neu}
            return "/?" + urlencode(p)

        nav = "<nav>" + "".join(
            f'<a class="{"an" if s == scope else ""}" href="{E(link(scope=s))}">{E(s)}</a>' for s in scopes) + "</nav>"
        nav += "<nav>" + "".join(
            f'<a class="{"an" if s == status else ""}" href="{E(link(status=s))}">{t}</a>'
            for s, t in (("offen", "Offen"), ("bestaetigt", "Bestätigt"), ("fehlalarm", "Fehlalarme"),
                         ("behoben", "Behoben"), ("alle", "Alle"))) + "</nav>"
        nav += "<nav>" + "".join(
            f'<a class="{"an" if s == min_s else ""}" href="{E(link(min=s))}">ab {s}</a>' for s in SCHWEREGRADE) + "</nav>"

        aktiv = db.execute("SELECT * FROM laeufe WHERE scope=? ORDER BY id DESC LIMIT 1", (scope,)).fetchone()
        live = ""
        if aktiv:
            ev = db.execute("SELECT * FROM ereignisse WHERE lauf=? ORDER BY id DESC LIMIT 40", (aktiv["id"],)).fetchall()
            zeilen = "<br>".join(f"{dt.datetime.fromtimestamp(e['zeit']):%H:%M:%S}  {E(e['text'])}" for e in ev)
            laeuft = aktiv["status"] == "laeuft"
            rest = ""
            if laeuft and aktiv["budget_s"]:
                uebrig = max(0, int(aktiv["start"] + aktiv["budget_s"] - dt.datetime.now().timestamp()))
                rest = f" · noch ca. {uebrig // 60} min"
            live = (f"<section><div class='live'>{'<span class=punkt></span>' if laeuft else ''}"
                    f"<span class='eb'>Lauf #{aktiv['id']} · {E(aktiv['status'])}"
                    f"{' · ' + E(aktiv['phase']) if aktiv['phase'] else ''}{rest} · {aktiv['anfragen']} Anfragen</span>"
                    f"</div><div class='ereignisse'>{zeilen or 'Noch keine Ereignisse.'}</div></section>")

        alle = self.wissen.funde(scope=scope)
        zaehler = {s: sum(1 for f in alle if f["schwere"] == s and f["status"] in ("neu", "bestaetigt")) for s in SCHWEREGRADE}
        maximum = max(zaehler.values(), default=0) or 1
        kacheln = '<div class="kacheln">' + "".join(
            f'<div class="kachel k-{s}" style="--w:{round(zaehler[s] / maximum * 100)}%"><b>{zaehler[s]}</b>'
            f'<span>{s} offen</span><i></i></div>' for s in reversed(SCHWEREGRADE)) + "</div>"

        if status == "offen":
            gefiltert = [f for f in alle if f["status"] in ("neu", "bestaetigt")]
        elif status == "alle":
            gefiltert = alle
        else:
            gefiltert = [f for f in alle if f["status"] == status]
        gefiltert = [f for f in gefiltert if rang(f["schwere"]) >= rang(min_s)]
        gefiltert.sort(key=lambda f: (-rang(f["schwere"]), f["status"] != "neu", f["ort"]))
        zurueck = link()
        funde_html = "".join(fund_html(f, _knoepfe(f["fingerabdruck"], scope, zurueck)) for f in gefiltert[:500])

        regeln = self.wissen.gelernte_regeln()
        technik = db.execute("SELECT * FROM technik ORDER BY bestaetigt DESC, funde DESC").fetchall()
        lern = ("<section><span class='eb'>Lern-Loop</span>"
                f"<p>{len(regeln)} selbst gelernte Suchregeln aktiv. Bestätige echte Funde, damit KlausHackt daraus "
                "neue Regeln ableitet und dieselben Fehler auch an anderen Stellen findet.</p>"
                f'<form method="post" action="/lernen"><input type="hidden" name="t" value="{TOKEN}">'
                f'<input type="hidden" name="scope" value="{E(scope)}"><input type="hidden" name="zurueck" value="{E(zurueck)}">'
                '<div class="btns"><button>Jetzt aus Bestätigungen lernen</button></div></form>'
                "<table><tr><th>Technik</th><th>Läufe</th><th>Funde</th><th>bestätigt</th><th>Fehlalarme</th></tr>"
                + "".join(f"<tr><td class='mono'>{E(t['name'])}</td><td>{t['laeufe']}</td><td>{t['funde']}</td>"
                          f"<td>{t['bestaetigt']}</td><td>{t['fehlalarme']}</td></tr>" for t in technik)
                + "</table></section>")

        inhalt = (nav + live + kacheln + f"<section><span class='eb'>{len(gefiltert)} Funde</span>{funde_html or '<p>Keine.</p>'}</section>" + lern)
        return _seite(scope, inhalt, auffrischen=bool(aktiv and aktiv["status"] == "laeuft"))


def starte_dashboard(wissen: Wissen, port: int = 8765) -> None:
    Handler.wissen = wissen
    Handler.port = port
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Dashboard läuft auf http://127.0.0.1:{port}  (Strg+C zum Beenden)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
