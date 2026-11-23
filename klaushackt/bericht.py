"""Berichte als HTML (zum Anschauen/Weitergeben) und Markdown (für Issues/Tickets).

Alle Inhalte aus Funden stammen potenziell vom Ziel (z. B. HTML-Ausschnitte)
und werden deshalb konsequent escaped – der Bericht darf selbst keine
XSS-Lücke sein.
"""

from __future__ import annotations

import datetime as dt
import html
import json
from collections import Counter
from pathlib import Path

from klaushackt import __version__
from klaushackt.fund import SCHWEREGRADE, rang

E = html.escape

SCHWERE_TEXT = {
    "kritisch": "Sofort handeln: Übernahme, Datenabfluss oder Zugangsdaten offen.",
    "hoch": "Zeitnah beheben: realistisch ausnutzbar.",
    "mittel": "Einplanen: ausnutzbar unter Bedingungen.",
    "niedrig": "Härtung: erschwert Angriffe, kein direktes Leck.",
    "info": "Zur Kenntnis.",
}

CSS = """
/* Bewusst nur dunkel: Terminal-Look. Alle Farben explizit. */
:root{--bg:#090c11;--fl:#0f141c;--fl2:#131a24;--ti:#d9e1e8;--le:#7f8b99;--li:#1c2531;--ak:#2bff8f;--pink:#ff5fd2;
--cyan:#3ee8ff;--kritisch:#ff2d6f;--hoch:#ff8a1f;--mittel:#ffd21f;--niedrig:#3ee8ff;--info:#8692a1;
--mono:"JetBrains Mono","Cascadia Code","Fira Code",ui-monospace,Menlo,Consolas,monospace;color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ti);font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;
padding:32px max(16px,4vw) 64px;
background-image:repeating-linear-gradient(0deg,rgba(255,255,255,.018) 0 1px,transparent 1px 3px),
radial-gradient(1200px 500px at 85% -10%,rgba(43,255,143,.07),transparent 60%)}
.w{max-width:1000px;margin:0 auto;display:grid;gap:28px}
h1,h2,h3{margin:0;line-height:1.2;font-family:var(--mono)}
h1{font-size:clamp(26px,4.4vw,40px);font-weight:700;color:#fff;letter-spacing:-.02em}
h1::before{content:"> ";color:var(--ak)}
h1::after{content:"_";color:var(--ak);margin-left:2px}
@media (prefers-reduced-motion:no-preference){h1::after{animation:cursor 1.1s steps(1) infinite}}
@keyframes cursor{50%{opacity:0}}
h2{font-size:20px}h3{font-size:15px;font-weight:600;color:#fff}
.mono,code,pre{font-family:var(--mono)}
.logo{margin:0;font:600 11px/1.3 var(--mono);color:var(--ak);background:none;border:0;padding:0;
white-space:pre;overflow-x:auto;text-shadow:0 0 12px rgba(43,255,143,.35)}
.logo::before{content:none}
.eb{font:600 11.5px/1 var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--ak)}
.eb::before{content:"[>] ";color:var(--pink)}
.le{color:var(--le)}
.kacheln{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.kachel{background:var(--fl);border:1px solid var(--li);border-radius:6px;padding:14px 16px;display:grid;gap:6px;
position:relative;overflow:hidden}
.kachel b{font:700 34px/1 var(--mono)}.kachel span{font:600 11px/1 var(--mono);color:var(--le);text-transform:uppercase;letter-spacing:.1em}
.kachel i{display:block;height:4px;background:var(--li);border-radius:2px;overflow:hidden}
.kachel i::after{content:"";display:block;height:100%;width:var(--w,0%);background:var(--c)}
.k-kritisch{--c:var(--kritisch)}.k-hoch{--c:var(--hoch)}.k-mittel{--c:var(--mittel)}.k-niedrig{--c:var(--niedrig)}.k-info{--c:var(--info)}
.kachel b{color:var(--c)}
.k-kritisch{box-shadow:inset 0 0 0 1px rgba(255,45,111,.35),0 0 24px -10px rgba(255,45,111,.6)}
.fund{background:var(--fl);border:1px solid var(--li);border-left:3px solid var(--c,var(--li));
border-radius:6px;padding:14px 18px;display:grid;gap:10px}
.fund[open]{background:var(--fl2)}
.fund summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.fund summary::-webkit-details-marker{display:none}
.fund summary::before{content:"+";font:700 14px/1 var(--mono);color:var(--le);width:12px}
.fund[open] summary::before{content:"−"}
.pill{font:700 10.5px/1 var(--mono);text-transform:uppercase;letter-spacing:.1em;padding:5px 8px;
border-radius:3px;color:var(--c);border:1px solid var(--c);background:transparent;min-width:84px;text-align:center}
.s-kritisch .pill{background:var(--kritisch);color:#fff;border-color:var(--kritisch)}
.tag{font:500 11px/1 var(--mono);padding:4px 7px;border-radius:3px;border:1px solid var(--li);color:var(--le)}
.tag.neu{border-color:var(--ak);color:var(--ak)}
.ort{font:500 12px/1.4 var(--mono);color:var(--cyan);word-break:break-all}
.ort::before{content:"└─ ";color:var(--le)}
pre{background:#05070a;border:1px solid var(--li);border-radius:4px;padding:10px 12px;margin:0;
white-space:pre-wrap;word-break:break-word;font-size:12.5px;color:#c6f7da}
pre::before{content:"$ ";color:var(--pink)}
dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 14px;margin:0}
dt{font:600 11px/1.9 var(--mono);text-transform:uppercase;letter-spacing:.08em;color:var(--le)}
dd{margin:0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px 10px 8px 0;
border-bottom:1px dashed var(--li);vertical-align:top}th{font:600 11px var(--mono);
text-transform:uppercase;letter-spacing:.08em;color:var(--le)}
.s-kritisch{--c:var(--kritisch)}.s-hoch{--c:var(--hoch)}.s-mittel{--c:var(--mittel)}.s-niedrig{--c:var(--niedrig)}.s-info{--c:var(--info)}
footer{font:12px/1.6 var(--mono);color:var(--le);border-top:1px dashed var(--li);padding-top:14px}
footer::before{content:"// ";color:var(--pink)}
.btns{display:flex;gap:8px;flex-wrap:wrap}
.btns button{font:600 12.5px var(--mono);padding:7px 12px;border-radius:4px;border:1px solid var(--li);
background:#05070a;color:var(--ti);cursor:pointer}.btns button:hover{border-color:var(--ak);color:var(--ak)}
.btns button:focus-visible,a:focus-visible,summary:focus-visible{outline:2px solid var(--ak);outline-offset:2px}
a{color:var(--ak)}
"""

LOGO = "\n".join([
    r" _  ___                 _   _            _    _   ",
    r"| |/ / | __ _ _   _ ___| | | | __ _  ___| | _| |_ ",
    r"| ' /| |/ _` | | | / __| |_| |/ _` |/ __| |/ / __|",
    r"| . \| | (_| | |_| \__ \  _  | (_| | (__|   <| |_ ",
    r"|_|\_\_|\__,_|\__,_|___/_| |_|\__,_|\___|_|\_\\__|",
])


def fund_html(f, mit_knoepfen: str = "") -> str:
    ort = f["ort"] + (f":{f['zeile']}" if f["zeile"] else "")
    try:
        extra = json.loads(f["extra"] or "{}")
    except (TypeError, json.JSONDecodeError):
        extra = {}
    link = extra.get("link", "")
    status = f["status"]
    tags = f'<span class="tag {"neu" if status == "neu" else ""}">{E(status)}</span>'
    if extra.get("gelernt"):
        tags += '<span class="tag neu">gelernte Regel</span>'
    return f"""
<details class="fund s-{E(f['schwere'])}" id="f-{E(f['fingerabdruck'])}">
<summary><span class="pill">{E(f['schwere'])}</span><h3>{E(f['titel'])}</h3>{tags}</summary>
<div class="ort">{E(ort)}</div>
<p>{E(f['beschreibung'] or '')}</p>
{f'<pre>{E(f["ausschnitt"])}</pre>' if f['ausschnitt'] else ''}
<dl>
<dt>Behebung</dt><dd>{E(f['behebung'] or '–')}</dd>
<dt>Klasse</dt><dd class="mono">{E(f['cwe'] or '–')}</dd>
<dt>Sicherheit</dt><dd>{E(f['sicherheit'] or '–')} · gefunden von <span class="mono">{E(f['pruefer'])}</span> · Regel <span class="mono">{E(f['regel'])}</span></dd>
<dt>ID</dt><dd class="mono">{E(f['fingerabdruck'])}</dd>
{f'<dt>Mehr</dt><dd><a href="{E(link)}" rel="noopener noreferrer">{E(link)}</a></dd>' if link.startswith("https://") else ''}
</dl>
{mit_knoepfen}
</details>"""


def schreibe_berichte(wissen, scope, lauf: int, ordner: Path, min_schwere: str,
                      pruefer_status: list[dict], anfragen: int) -> Path:
    funde = [f for f in wissen.funde(scope=scope.name, lauf=lauf)
             if f["status"] != "fehlalarm" and rang(f["schwere"]) >= rang(min_schwere)]
    funde.sort(key=lambda f: (-rang(f["schwere"]), f["status"] != "neu", f["ort"], f["zeile"] or 0))
    zaehler = Counter(f["schwere"] for f in funde)
    lauf_row = wissen.db.execute("SELECT * FROM laeufe WHERE id=?", (lauf,)).fetchone()
    start = dt.datetime.fromtimestamp(lauf_row["start"])
    dauer = int((lauf_row["ende"] or lauf_row["start"]) - lauf_row["start"])
    gelernte = len(wissen.gelernte_regeln())

    maximum = max(zaehler.values(), default=0) or 1
    kacheln = "".join(f'<div class="kachel k-{s}" style="--w:{round(zaehler.get(s, 0) / maximum * 100)}%">'
                      f'<b>{zaehler.get(s, 0)}</b><span>{s}</span><i></i></div>'
                      for s in reversed(SCHWEREGRADE))
    belohnung = ""
    if scope.belohnungen:
        zeilen = "".join(f"<tr><td>{E(s)}</td><td>{zaehler.get(s, 0)}</td><td>{E(scope.belohnungen.get(s, '–'))}</td></tr>"
                         for s in reversed(SCHWEREGRADE) if s in scope.belohnungen)
        belohnung = (f"<section><span class='eb'>Belohnungstabelle des Programms</span><table><tr><th>Schwere</th>"
                     f"<th>Funde</th><th>Prämie laut Programm</th></tr>{zeilen}</table>"
                     "<p class='le'>Nur Richtwert: Programme zahlen nur für bestätigte, neue Funde im Scope. "
                     "Prämien kannst du auch ablehnen oder spenden.</p></section>")
    status_zeilen = "".join(
        f"<tr><td class='mono'>{E(p['name'])}</td><td>{E(str(p.get('status')))}</td>"
        f"<td>{p.get('funde', '–')}</td><td>{p.get('sekunden', '–')}</td></tr>" for p in pruefer_status)
    gruppen = ""
    for s in reversed(SCHWEREGRADE):
        teil = [f for f in funde if f["schwere"] == s]
        if teil:
            gruppen += (f"<section><span class='eb'>{E(s)} · {len(teil)}</span><p class='le'>{E(SCHWERE_TEXT[s])}</p>"
                        + "".join(fund_html(f) for f in teil) + "</section>")
    if not funde:
        gruppen = "<section><h2>Keine Funde ab dieser Schwere.</h2><p class='le'>Das heißt nicht, dass das Ziel " \
                  "sicher ist – nur, dass diese Prüfungen nichts gefunden haben.</p></section>"

    html_text = f"""<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>KlausHackt · {E(scope.name)} · Lauf {lauf}</title><style>{CSS}</style></head><body><div class="w">
<header style="display:grid;gap:12px"><pre class="logo">{E(LOGO)}</pre><span class="eb">KlausHackt-Bericht · Lauf #{lauf}</span>
<h1>{E(scope.name)}</h1>
<p class="le">{start:%d.%m.%Y %H:%M} · {dauer // 60} min {dauer % 60} s · {anfragen} Anfragen an das Ziel
(max. {scope.anfragen_pro_sekunde:g}/s) · {gelernte} gelernte Regeln im Gedächtnis</p></header>
<div class="kacheln">{kacheln}</div>
{belohnung}
{gruppen}
<section><span class="eb">Was geprüft wurde</span><table><tr><th>Prüfer</th><th>Status</th><th>Funde</th><th>Sekunden</th></tr>
{status_zeilen}</table></section>
<section class="le"><span class="eb">Scope</span><pre>{E(scope.zusammenfassung())}</pre></section>
<footer>Erstellt mit KlausHackt {__version__}. Nur für autorisierte Tests. Funde vor dem Melden manuell prüfen.</footer>
</div></body></html>"""
    html_pfad = ordner / f"bericht-lauf{lauf}.html"
    html_pfad.write_text(html_text, encoding="utf-8")

    md = [f"# KlausHackt-Bericht: {scope.name} (Lauf #{lauf})", "",
          f"{start:%d.%m.%Y %H:%M} · {dauer // 60} min · {anfragen} Anfragen", "",
          " · ".join(f"**{zaehler.get(s, 0)}** {s}" for s in reversed(SCHWEREGRADE)), ""]
    for f in funde:
        ort = f["ort"] + (f":{f['zeile']}" if f["zeile"] else "")
        md += [f"## [{f['schwere'].upper()}] {f['titel']}", "", f"- **Ort:** `{ort}`",
               f"- **Klasse:** {f['cwe'] or '–'} · **Sicherheit:** {f['sicherheit']} · **Status:** {f['status']}",
               f"- **ID:** `{f['fingerabdruck']}`", "", f["beschreibung"] or "", ""]
        if f["ausschnitt"]:
            md += ["```", f["ausschnitt"].replace("```", "ˋˋˋ"), "```", ""]
        md += [f"**Behebung:** {f['behebung'] or '–'}", ""]
    (ordner / f"bericht-lauf{lauf}.md").write_text("\n".join(md), encoding="utf-8")
    return html_pfad
