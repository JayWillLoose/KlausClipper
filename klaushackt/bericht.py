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
:root{--bg:#f4f5f2;--fl:#fff;--ti:#0c1117;--le:#5a6470;--li:#dfe3e0;--ak:#0b8f5a;
--kritisch:#c81e3a;--hoch:#e0531f;--mittel:#c98a00;--niedrig:#2f7dc0;--info:#7b8590;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#07090c;--fl:#0f141a;--ti:#e7ece9;
--le:#8b96a0;--li:#1e2730;--ak:#57f2a6;--kritisch:#ff4d6a;--hoch:#ff7a45;--mittel:#ffc233;--niedrig:#5aa9ff;
--info:#8b96a0;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ti);
font:15px/1.6 Inter,system-ui,-apple-system,sans-serif;padding:32px max(16px,4vw) 64px}
.w{max-width:980px;margin:0 auto;display:grid;gap:28px}
h1,h2,h3{margin:0;line-height:1.15;letter-spacing:-.01em}h1{font-size:clamp(30px,5vw,46px);font-weight:800}
h2{font-size:22px}h3{font-size:16px}
.mono,code,pre{font-family:"JetBrains Mono",ui-monospace,Menlo,monospace}
.eb{font:600 11px/1 "JetBrains Mono",ui-monospace,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--ak)}
.le{color:var(--le)}
.kacheln{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px}
.kachel{background:var(--fl);border:1px solid var(--li);border-radius:12px;padding:14px 16px;display:grid;gap:2px}
.kachel b{font:800 32px/1 Inter,system-ui,sans-serif}.kachel span{font-size:12px;color:var(--le);text-transform:uppercase;letter-spacing:.08em}
.k-kritisch b{color:var(--kritisch)}.k-hoch b{color:var(--hoch)}.k-mittel b{color:var(--mittel)}
.k-niedrig b{color:var(--niedrig)}.k-info b{color:var(--info)}
.fund{background:var(--fl);border:1px solid var(--li);border-left:4px solid var(--c,var(--li));
border-radius:10px;padding:16px 18px;display:grid;gap:8px}
.fund summary{cursor:pointer;list-style:none;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.fund summary::-webkit-details-marker{display:none}
.pill{font:700 11px/1 "JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:.08em;padding:5px 8px;
border-radius:6px;color:#fff;background:var(--c)}
.tag{font:500 11px/1 "JetBrains Mono",monospace;padding:4px 7px;border-radius:6px;border:1px solid var(--li);color:var(--le)}
.tag.neu{border-color:var(--ak);color:var(--ak)}
.ort{font:500 12px/1.4 "JetBrains Mono",monospace;color:var(--le);word-break:break-all}
pre{background:var(--bg);border:1px solid var(--li);border-radius:8px;padding:10px 12px;margin:0;
white-space:pre-wrap;word-break:break-word;font-size:12.5px}
dl{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 14px;margin:0}
dt{font:600 11px/1.9 "JetBrains Mono",monospace;text-transform:uppercase;letter-spacing:.06em;color:var(--le)}
dd{margin:0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px 10px 8px 0;
border-bottom:1px solid var(--li);vertical-align:top}th{font:600 11px "JetBrains Mono",monospace;
text-transform:uppercase;letter-spacing:.06em;color:var(--le)}
.s-kritisch{--c:var(--kritisch)}.s-hoch{--c:var(--hoch)}.s-mittel{--c:var(--mittel)}.s-niedrig{--c:var(--niedrig)}.s-info{--c:var(--info)}
footer{font-size:12px;color:var(--le);border-top:1px solid var(--li);padding-top:14px}
.btns{display:flex;gap:8px;flex-wrap:wrap}
.btns button{font:600 13px Inter,system-ui,sans-serif;padding:7px 12px;border-radius:8px;border:1px solid var(--li);
background:var(--fl);color:var(--ti);cursor:pointer}.btns button:hover{border-color:var(--ak)}
a{color:var(--ak)}
"""


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

    kacheln = "".join(f'<div class="kachel k-{s}"><b>{zaehler.get(s, 0)}</b><span>{s}</span></div>'
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
<header style="display:grid;gap:10px"><span class="eb">KlausHackt-Bericht · Lauf #{lauf}</span>
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
