"""Tests für die Sicherheitsregeln von KlausHackt selbst.

Ausführen:  python -m unittest discover -s tests -v
"""

import datetime as dt
import tempfile
import time
import unittest
from pathlib import Path

from klaushackt.bericht import schreibe_berichte
from klaushackt.fund import Fund
from klaushackt.netz import Drossel, SichererClient
from klaushackt.planer import parse_dauer
from klaushackt.pruefer.geheimnisse import maskiere
from klaushackt.pruefer.ki import verallgemeinere
from klaushackt.scope import MAX_ANFRAGEN_PRO_SEKUNDE, ScopeFehler, lade_scope
from klaushackt.wissen import Wissen

GUELTIG = """
name = "test"
gueltig_bis = "2099-01-01"
[erlaubnis]
beschreibung = "Test"
bestaetigt = true
[ziele]
urls = ["https://app.example.de/shop/", "https://api.example.de/"]
ausgeschlossen = ["https://app.example.de/shop/admin"]
[regeln]
anfragen_pro_sekunde = 50
"""


def scope_aus(text: str):
    d = tempfile.mkdtemp()
    p = Path(d) / "s.toml"
    p.write_text(text, encoding="utf-8")
    return lade_scope(p)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.s = scope_aus(GUELTIG)

    def test_erlaubte_urls(self):
        self.assertTrue(self.s.url_erlaubt("https://app.example.de/shop/"))
        self.assertTrue(self.s.url_erlaubt("https://app.example.de/shop/produkt?id=1"))
        self.assertTrue(self.s.url_erlaubt("https://api.example.de/v1/x"))

    def test_verbotene_urls(self):
        for url in ["https://app.example.de/", "https://app.example.de/shopping",
                    "http://app.example.de/shop/", "https://evil.de/shop/",
                    "https://app.example.de.evil.de/shop/", "https://app.example.de:8443/shop/",
                    "https://user:pw@app.example.de/shop/", "https://app.example.de/shop/admin",
                    "https://app.example.de/shop/admin/loeschen", "file:///etc/passwd"]:
            self.assertFalse(self.s.url_erlaubt(url), url)

    def test_tempo_wird_gedeckelt(self):
        self.assertEqual(self.s.anfragen_pro_sekunde, MAX_ANFRAGEN_PRO_SEKUNDE)

    def test_nur_lesende_methoden_standard(self):
        with self.assertRaises(ScopeFehler):
            self.s.pruefe_url("https://api.example.de/x", "POST")

    def test_ohne_erlaubnis_kein_start(self):
        with self.assertRaises(ScopeFehler):
            scope_aus(GUELTIG.replace('beschreibung = "Test"\n', ""))
        with self.assertRaises(ScopeFehler):
            scope_aus(GUELTIG.replace("bestaetigt = true", "bestaetigt = false"))

    def test_abgelaufen(self):
        s = scope_aus(GUELTIG.replace("2099-01-01", "2020-01-01"))
        with self.assertRaises(ScopeFehler):
            s.pruefe_gueltig()

    def test_platzhalter_verboten(self):
        with self.assertRaises(ScopeFehler):
            scope_aus(GUELTIG.replace("https://api.example.de/", "https://*.example.de/"))


class NetzTests(unittest.TestCase):
    def test_drossel_haelt_tempo(self):
        d = Drossel(20)
        start = time.monotonic()
        for _ in range(11):
            d.warte()
        self.assertGreaterEqual(time.monotonic() - start, 0.45)

    def test_client_verweigert_fremde_ziele(self):
        s = scope_aus(GUELTIG)
        c = SichererClient(s, Path(tempfile.mkdtemp()) / "log.jsonl")
        with self.assertRaises(ScopeFehler):
            c.anfrage("https://google.com/")
        self.assertEqual(c.anzahl, 0)


class FundTests(unittest.TestCase):
    def test_fingerabdruck_ignoriert_zeilennummer(self):
        a = Fund("x", "r", "t", "hoch", "b", "a.py", 10, "eval(x)")
        b = Fund("x", "r", "t", "hoch", "b", "a.py", 99, "eval(x)  ")
        self.assertEqual(a.fingerabdruck, b.fingerabdruck)

    def test_maskiert_geheimnisse(self):
        self.assertNotIn("Sup3rGeheim", maskiere("Sup3rGeheim2026xyz"))

    def test_ungueltige_schwere(self):
        with self.assertRaises(ValueError):
            Fund("x", "r", "t", "super", "b", "a.py")


class LernTests(unittest.TestCase):
    def test_variante_wird_gefunden(self):
        import re
        muster = verallgemeinere('rows = db.execute(f"SELECT * FROM kunden WHERE id={kid}")')
        self.assertTrue(re.search(muster, 'res = conn.execute(f"DELETE FROM x WHERE a={b}")'))
        self.assertFalse(re.search(muster, 'res = conn.execute("SELECT 1", (a,))'))

    def test_fehlalarm_wird_gemerkt(self):
        w = Wissen(Path(tempfile.mkdtemp()) / "w.db")
        f = Fund("code_muster", "r", "t", "mittel", "b", "a.py", 1, "x")
        lauf = w.neuer_lauf("s", 60)
        self.assertEqual(w.speichere_fund("s", lauf, f), "neu")
        self.assertEqual(w.speichere_fund("s", lauf, f), "bekannt")
        w.markiere(f.fingerabdruck, "fehlalarm")
        self.assertTrue(w.ist_fehlalarm("s", f))


class BerichtTests(unittest.TestCase):
    def test_bericht_escaped_inhalte(self):
        d = Path(tempfile.mkdtemp())
        w = Wissen(d / "w.db")
        s = scope_aus(GUELTIG)
        lauf = w.neuer_lauf(s.name, 60)
        w.speichere_fund(s.name, lauf, Fund("web", "r", "<script>alert(1)</script>", "hoch",
                                            "<img src=x onerror=alert(1)>", "https://app.example.de/shop/", None,
                                            "<svg onload=alert(1)>"))
        w.lauf_update(lauf, ende=time.time())
        text = schreibe_berichte(w, s, lauf, d, "info", [], 0).read_text()
        self.assertNotIn("<script>alert", text)
        self.assertNotIn("<img src=x", text)
        self.assertNotIn("<svg onload", text)


class DauerTests(unittest.TestCase):
    def test_dauer(self):
        self.assertEqual(parse_dauer("2h"), 7200)
        self.assertEqual(parse_dauer("1h30m"), 5400)
        self.assertEqual(parse_dauer("90"), 5400)
        with self.assertRaises(ValueError):
            parse_dauer("zwei stunden")


if __name__ == "__main__":
    unittest.main()
