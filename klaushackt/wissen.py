"""Das Gedächtnis: SQLite-Datenbank, die mit jedem Lauf wächst.

Hier steckt der Lern-Loop: Funde, Fehlalarme, gelernte Regeln,
Erfolgsquoten der Techniken und die Abdeckung (was ist schon geprüft).
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from klaushackt.fund import Fund

SCHEMA = """
CREATE TABLE IF NOT EXISTS laeufe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,
    start REAL NOT NULL,
    ende REAL,
    budget_s INTEGER,
    status TEXT NOT NULL DEFAULT 'laeuft',
    phase TEXT DEFAULT '',
    anfragen INTEGER DEFAULT 0,
    notiz TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS funde (
    fingerabdruck TEXT NOT NULL,
    scope TEXT NOT NULL,
    pruefer TEXT, regel TEXT, titel TEXT, schwere TEXT, beschreibung TEXT,
    ort TEXT, zeile INTEGER, ausschnitt TEXT, behebung TEXT, cwe TEXT, sicherheit TEXT,
    extra TEXT,
    status TEXT NOT NULL DEFAULT 'neu',   -- neu | bestaetigt | fehlalarm | behoben
    erster_lauf INTEGER, letzter_lauf INTEGER,
    zuerst REAL, zuletzt REAL,
    PRIMARY KEY (fingerabdruck, scope)
);
CREATE TABLE IF NOT EXISTS regeln (
    id TEXT PRIMARY KEY,
    sprache TEXT, muster TEXT NOT NULL, titel TEXT, schwere TEXT,
    beschreibung TEXT, behebung TEXT, cwe TEXT,
    herkunft TEXT,          -- aus welchem Fund gelernt
    aktiv INTEGER DEFAULT 1,
    treffer INTEGER DEFAULT 0, fehlalarme INTEGER DEFAULT 0,
    erstellt REAL
);
CREATE TABLE IF NOT EXISTS technik (
    name TEXT PRIMARY KEY,
    laeufe INTEGER DEFAULT 0, sekunden REAL DEFAULT 0,
    funde INTEGER DEFAULT 0, bestaetigt INTEGER DEFAULT 0, fehlalarme INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS abdeckung (
    scope TEXT, objekt TEXT, art TEXT, hash TEXT, geprueft REAL, technik TEXT,
    PRIMARY KEY (scope, objekt, art, technik)
);
CREATE TABLE IF NOT EXISTS ereignisse (
    id INTEGER PRIMARY KEY AUTOINCREMENT, lauf INTEGER, zeit REAL, text TEXT
);
CREATE TABLE IF NOT EXISTS tempo (
    scope TEXT PRIMARY KEY, rate REAL, basis_p95 REAL, aktualisiert REAL
);
"""


class Wissen:
    def __init__(self, pfad: str | Path) -> None:
        self.pfad = Path(pfad)
        self.pfad.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.pfad, check_same_thread=False, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------- Läufe ----------
    def neuer_lauf(self, scope: str, budget_s: int) -> int:
        cur = self.db.execute("INSERT INTO laeufe (scope, start, budget_s) VALUES (?,?,?)",
                              (scope, time.time(), budget_s))
        self.db.commit()
        return int(cur.lastrowid)

    def lauf_update(self, lauf: int, **felder) -> None:
        if not felder:
            return
        erlaubt = {"ende", "status", "phase", "anfragen", "notiz"}
        teile = [f"{k}=?" for k in felder if k in erlaubt]
        self.db.execute(f"UPDATE laeufe SET {', '.join(teile)} WHERE id=?",
                        [felder[k] for k in felder if k in erlaubt] + [lauf])
        self.db.commit()

    def ereignis(self, lauf: int, text: str) -> None:
        self.db.execute("INSERT INTO ereignisse (lauf, zeit, text) VALUES (?,?,?)", (lauf, time.time(), text))
        self.db.commit()

    # ---------- Funde ----------
    def speichere_fund(self, scope: str, lauf: int, f: Fund) -> str:
        """Gibt 'neu', 'bekannt', 'fehlalarm' oder 'wieder_da' zurück."""
        fp = f.fingerabdruck
        alt = self.db.execute("SELECT status FROM funde WHERE fingerabdruck=? AND scope=?", (fp, scope)).fetchone()
        jetzt = time.time()
        if alt is None:
            self.db.execute(
                """INSERT INTO funde (fingerabdruck, scope, pruefer, regel, titel, schwere, beschreibung, ort,
                   zeile, ausschnitt, behebung, cwe, sicherheit, extra, erster_lauf, letzter_lauf, zuerst, zuletzt)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (fp, scope, f.pruefer, f.regel, f.titel, f.schwere, f.beschreibung, f.ort, f.zeile,
                 f.ausschnitt[:2000], f.behebung, f.cwe, f.sicherheit, json.dumps(f.extra, ensure_ascii=False),
                 lauf, lauf, jetzt, jetzt))
            ergebnis = "neu"
        else:
            status = alt["status"]
            neuer_status = "neu" if status == "behoben" else status
            self.db.execute("UPDATE funde SET letzter_lauf=?, zuletzt=?, zeile=?, status=? "
                            "WHERE fingerabdruck=? AND scope=?", (lauf, jetzt, f.zeile, neuer_status, fp, scope))
            ergebnis = {"fehlalarm": "fehlalarm", "behoben": "wieder_da"}.get(status, "bekannt")
        self.db.commit()
        return ergebnis

    def ist_fehlalarm(self, scope: str, f: Fund) -> bool:
        r = self.db.execute("SELECT 1 FROM funde WHERE fingerabdruck=? AND scope=? AND status='fehlalarm'",
                            (f.fingerabdruck, scope)).fetchone()
        return r is not None

    def markiere(self, fingerabdruck: str, status: str, scope: str | None = None) -> int:
        if status not in ("neu", "bestaetigt", "fehlalarm", "behoben"):
            raise ValueError(f"Unbekannter Status: {status}")
        sql = "UPDATE funde SET status=? WHERE fingerabdruck=?"
        werte: list = [status, fingerabdruck]
        if scope:
            sql += " AND scope=?"
            werte.append(scope)
        cur = self.db.execute(sql, werte)
        # Lernsignal an Technik + Regel zurückmelden
        for r in self.db.execute("SELECT pruefer, regel FROM funde WHERE fingerabdruck=?", (fingerabdruck,)):
            if status == "bestaetigt":
                self._technik_plus(r["pruefer"], bestaetigt=1)
            elif status == "fehlalarm":
                self._technik_plus(r["pruefer"], fehlalarme=1)
                self.db.execute("UPDATE regeln SET fehlalarme=fehlalarme+1 WHERE id=?", (r["regel"],))
                # Regeln, die überwiegend Fehlalarme liefern, schalten sich selbst ab
                self.db.execute("UPDATE regeln SET aktiv=0 WHERE id=? AND herkunft IS NOT NULL "
                                "AND fehlalarme>=3 AND fehlalarme>treffer", (r["regel"],))
        self.db.commit()
        return cur.rowcount

    def funde(self, scope: str | None = None, lauf: int | None = None, status: str | None = None) -> list[sqlite3.Row]:
        sql, werte = "SELECT * FROM funde WHERE 1=1", []
        if scope:
            sql += " AND scope=?"
            werte.append(scope)
        if lauf is not None:
            sql += " AND letzter_lauf=?"
            werte.append(lauf)
        if status:
            sql += " AND status=?"
            werte.append(status)
        return self.db.execute(sql, werte).fetchall()

    def markiere_verschwundene_als_behoben(self, scope: str, lauf: int, pruefer: set[str]) -> int:
        """Funde, die in diesem Lauf von denselben Prüfern nicht mehr gesehen wurden,
        sind vermutlich behoben."""
        if not pruefer:
            return 0
        platz = ",".join("?" * len(pruefer))
        cur = self.db.execute(
            f"UPDATE funde SET status='behoben' WHERE scope=? AND letzter_lauf<? "
            f"AND status IN ('neu','bestaetigt') AND pruefer IN ({platz})",
            [scope, lauf, *pruefer])
        self.db.commit()
        return cur.rowcount

    # ---------- Gelernte Regeln ----------
    def regel_speichern(self, regel: dict) -> bool:
        vorhanden = self.db.execute("SELECT 1 FROM regeln WHERE id=? OR muster=?",
                                    (regel["id"], regel["muster"])).fetchone()
        if vorhanden:
            return False
        self.db.execute(
            "INSERT INTO regeln (id, sprache, muster, titel, schwere, beschreibung, behebung, cwe, herkunft, erstellt)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (regel["id"], regel.get("sprache", "*"), regel["muster"], regel.get("titel", ""),
             regel.get("schwere", "mittel"), regel.get("beschreibung", ""), regel.get("behebung", ""),
             regel.get("cwe", ""), regel.get("herkunft"), time.time()))
        self.db.commit()
        return True

    def gelernte_regeln(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM regeln WHERE aktiv=1").fetchall()

    def regel_treffer(self, regel_id: str) -> None:
        self.db.execute("UPDATE regeln SET treffer=treffer+1 WHERE id=?", (regel_id,))
        self.db.commit()

    # ---------- Technik-Statistik ----------
    def _technik_plus(self, name: str, **werte) -> None:
        self.db.execute("INSERT OR IGNORE INTO technik (name) VALUES (?)", (name,))
        for k, v in werte.items():
            self.db.execute(f"UPDATE technik SET {k}={k}+? WHERE name=?", (v, name))

    def technik_lauf(self, name: str, sekunden: float, funde: int) -> None:
        self._technik_plus(name, laeufe=1, sekunden=sekunden, funde=funde)
        self.db.commit()

    def technik_gewicht(self, name: str) -> float:
        """Wie lohnend war diese Technik bisher? Bestätigte Funde zählen viel,
        Fehlalarme ziehen ab. Neue Techniken bekommen einen neutralen Startwert."""
        r = self.db.execute("SELECT * FROM technik WHERE name=?", (name,)).fetchone()
        if r is None or r["laeufe"] == 0:
            return 1.0
        wert = (1 + r["funde"] + 3 * r["bestaetigt"] - 2 * r["fehlalarme"]) / (1 + r["laeufe"])
        return max(0.2, min(5.0, wert))

    # ---------- Abdeckung ----------
    def schon_geprueft(self, scope: str, objekt: str, art: str, hash_: str, technik: str) -> bool:
        r = self.db.execute("SELECT hash FROM abdeckung WHERE scope=? AND objekt=? AND art=? AND technik=?",
                            (scope, objekt, art, technik)).fetchone()
        return r is not None and r["hash"] == hash_

    def als_geprueft(self, scope: str, objekt: str, art: str, hash_: str, technik: str) -> None:
        self.db.execute("INSERT OR REPLACE INTO abdeckung VALUES (?,?,?,?,?,?)",
                        (scope, objekt, art, hash_, time.time(), technik))
        self.db.commit()

    # ---------- Gelernte Rate (Lastprobe) ----------
    def gelerntes_tempo(self, scope: str) -> float | None:
        r = self.db.execute("SELECT rate FROM tempo WHERE scope=?", (scope,)).fetchone()
        return float(r["rate"]) if r else None

    def merke_tempo(self, scope: str, rate: float, basis_p95: float) -> None:
        self.db.execute("INSERT OR REPLACE INTO tempo VALUES (?,?,?,?)",
                        (scope, rate, basis_p95, time.time()))
        self.db.commit()
