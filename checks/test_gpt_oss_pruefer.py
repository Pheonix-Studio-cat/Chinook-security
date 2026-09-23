"""Prueft den zweiten Pruefer -- vor allem die Belegpflicht.

Die Belegpflicht **ist** dieser Bot. Ohne sie waere er nur ein zweites
Modell, das dieselbe Sorte Vermutung abliefert wie das erste. Mit ihr
gilt: was nicht im Quelltext steht, kommt nicht durch.

Deshalb steht hier jeder Fall einzeln:

* der Beleg sitzt         -> Befund gilt unveraendert
* der Beleg sitzt daneben -> Zeilennummer wird korrigiert, Befund gilt
* der Beleg steht mehrfach-> Befund gilt, aber ohne Zeilennummer
* der Beleg steht nirgends-> Befund wird verworfen

Der vorletzte Fall ist der unbequeme: ein Modell, das eine Stelle nicht
eindeutig benennen kann, hat trotzdem etwas Wahres sagen koennen. Eine
falsche Zeilennummer ist schlechter als keine.

Und die Unterscheidung, die dieses Projekt schon mehrfach gerettet hat:
**eine unlesbare Antwort ist nicht dasselbe wie keine Befunde.**
"""

from __future__ import annotations

import importlib.util
import os
import unittest

WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_pfad = os.path.join(WURZEL, ".github", "gpt-oss-pruefer.py")
_spec = importlib.util.spec_from_file_location("gpt_oss_pruefer", _pfad)
bot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bot)

QUELLE = """def teile(a, b):
    return a / b


def lade(pfad):
    datei = open(pfad)
    return datei.read()


def nochmal(pfad):
    datei = open(pfad)
    return datei.read()
"""


def _befund(**mehr):
    grund = {
        "titel": "Division ohne Null-Pruefung",
        "zeile": 2,
        "beleg": "    return a / b",
        "schwere": "hoch",
        "begruendung": "Bei b == 0 fliegt eine Ausnahme.",
    }
    grund.update(mehr)
    return grund


class DerBelegSitzt(unittest.TestCase):
    def test_richtige_zeile_gilt(self):
        gilt, warum, fertig = bot.belegen(_befund(), QUELLE)
        self.assertTrue(gilt, warum)
        self.assertEqual(fertig["zeile"], 2)

    def test_leerraum_ist_kein_unterschied(self):
        """Modelle ruecken beim Abschreiben gern anders ein."""
        gilt, _w, _f = bot.belegen(_befund(beleg="return a / b"), QUELLE)
        self.assertTrue(gilt)

    def test_erste_zeile_geht_auch(self):
        gilt, _w, _f = bot.belegen(_befund(zeile=1, beleg="def teile(a, b):"), QUELLE)
        self.assertTrue(gilt)


class DerBelegSitztDaneben(unittest.TestCase):
    def test_zeilennummer_wird_korrigiert(self):
        """Falsche Nummer, echter Beleg: das ist kein Grund zu verwerfen."""
        gilt, warum, fertig = bot.belegen(_befund(zeile=99), QUELLE)
        self.assertTrue(gilt, warum)
        self.assertEqual(fertig["zeile"], 2, "haette auf 2 korrigiert werden muessen")
        self.assertIn("korrigiert", warum)

    def test_zeile_fehlt_ganz(self):
        ohne = _befund()
        del ohne["zeile"]
        gilt, _w, fertig = bot.belegen(ohne, QUELLE)
        self.assertTrue(gilt)
        self.assertEqual(fertig["zeile"], 2)

    def test_zeile_ist_kein_int(self):
        gilt, _w, fertig = bot.belegen(_befund(zeile="zwei"), QUELLE)
        self.assertTrue(gilt)
        self.assertEqual(fertig["zeile"], 2)


class DerBelegStehtMehrfach(unittest.TestCase):
    """`datei = open(pfad)` steht in Zeile 6 **und** in Zeile 11.

    Der erste Anlauf dieser Pruefung verlangte, dass dann die Zeilennummer
    immer faellt. Das war falsch gedacht: nennt das Modell Zeile 6 und
    steht der Beleg in Zeile 6, hat es die Stelle **richtig benannt** --
    dass derselbe Text weiter unten nochmal vorkommt, macht die Aussage
    nicht unbestimmt. Mehrdeutig ist es erst, wenn die genannte Zeile
    nicht passt und mehrere andere in Frage kommen.
    """

    def test_genannte_zeile_passt_also_bleibt_sie(self):
        gilt, warum, fertig = bot.belegen(
            _befund(zeile=6, beleg="datei = open(pfad)"), QUELLE
        )
        self.assertTrue(gilt, warum)
        self.assertEqual(fertig["zeile"], 6, "richtig benannt, also stehen lassen")

    def test_die_andere_stelle_genauso(self):
        gilt, _w, fertig = bot.belegen(
            _befund(zeile=11, beleg="datei = open(pfad)"), QUELLE
        )
        self.assertTrue(gilt)
        self.assertEqual(fertig["zeile"], 11)

    def test_falsche_zeile_und_mehrdeutig_heisst_ohne_nummer(self):
        """Hier ist die Stelle wirklich offen -- 6 oder 11, niemand weiss es."""
        gilt, warum, fertig = bot.belegen(
            _befund(zeile=99, beleg="datei = open(pfad)"), QUELLE
        )
        self.assertTrue(gilt, warum)
        self.assertNotIn(
            "zeile", fertig, "eine geratene Zeilennummer ist schlechter als keine"
        )
        self.assertIn("2-mal", warum)

    def test_eindeutiger_beleg_wird_korrigiert_statt_entnummert(self):
        """Gegenstueck: nur eine Stelle in Frage -> Nummer wird gesetzt."""
        gilt, _w, fertig = bot.belegen(_befund(zeile=99), QUELLE)
        self.assertEqual(fertig["zeile"], 2)
        self.assertTrue(gilt)


class DerBelegStehtNirgends(unittest.TestCase):
    def test_erfundene_zeile_wird_verworfen(self):
        # Eine harmlose Zeile, die es in QUELLE nicht gibt. Bewusst nichts,
        # was nach einem echten Fund aussieht: der Code-Bot liest diese
        # Datei mit, und eine Vorlage, die seine Regeln ausloest, ist ein
        # Fehlalarm, den niemand braucht. (Er hat es prompt gemeldet.)
        gilt, warum, _f = bot.belegen(_befund(beleg="zaehler = zaehler + 1"), QUELLE)
        self.assertFalse(gilt)
        self.assertIn("nirgends", warum)

    def test_leerer_beleg_wird_verworfen(self):
        gilt, _w, _f = bot.belegen(_befund(beleg="   "), QUELLE)
        self.assertFalse(gilt)

    def test_fehlendes_feld_wird_verworfen(self):
        ohne = _befund()
        del ohne["begruendung"]
        gilt, warum, _f = bot.belegen(ohne, QUELLE)
        self.assertFalse(gilt)
        self.assertIn("begruendung", warum)

    def test_zahl_statt_text_wird_verworfen(self):
        gilt, _w, _f = bot.belegen(_befund(titel=42), QUELLE)
        self.assertFalse(gilt)

    def test_erfundene_schwere_wird_verworfen(self):
        gilt, _w, _f = bot.belegen(_befund(schwere="katastrophal"), QUELLE)
        self.assertFalse(gilt)


class DasProtokollSagtWasPassierte(unittest.TestCase):
    def test_behalten_und_verworfen_stehen_drin(self):
        """Ein Filter, dessen Wirkung niemand sieht, ist kein Filter."""
        echt = _befund()
        erfunden = _befund(titel="Erfunden", beleg="ergebnis = rechne(x)")
        behalten, protokoll = bot.pruefe_belege([echt, erfunden], QUELLE)
        self.assertEqual(len(behalten), 1)
        self.assertEqual(len(protokoll), 2)
        self.assertTrue(any("VERWORFEN" in z and "Erfunden" in z for z in protokoll))
        self.assertTrue(any("behalten" in z for z in protokoll))

    def test_leere_liste_gibt_leeres_protokoll(self):
        self.assertEqual(bot.pruefe_belege([], QUELLE), ([], []))


class AntwortLesen(unittest.TestCase):
    def test_nacktes_json(self):
        self.assertEqual(len(bot.befunde_aus_text('[{"a": 1}]')), 1)

    def test_codeblock(self):
        self.assertEqual(
            len(bot.befunde_aus_text('Bitte:\n```json\n[{"a":1}]\n```')), 1
        )

    def test_leere_liste_ist_ein_ergebnis(self):
        self.assertEqual(bot.befunde_aus_text("[]"), [])

    def test_leere_antwort_ist_kein_ergebnis(self):
        with self.assertRaises(bot.Unbrauchbar):
            bot.befunde_aus_text("  ")

    def test_prosa_statt_json(self):
        with self.assertRaises(bot.Unbrauchbar):
            bot.befunde_aus_text("Ich habe zwei Probleme gefunden.")


class DasKontingentIstDieSchranke(unittest.TestCase):
    def test_hoechstens_so_viele_dateien(self):
        viele = [f"x{i}.py" for i in range(40)]
        self.assertEqual(len(bot.dateien_waehlen(viele)), bot.DATEIEN_JE_LAUF)

    def test_auswahl_ist_stabil(self):
        """Zwei Laeufe ueber denselben Stand muessen dieselben Dateien treffen.

        Sonst sieht jeder Lauf eine andere Haelfte des Repos, und die Issues
        gingen im Wechsel auf und zu.
        """
        viele = [f"x{i}.py" for i in range(40)]
        self.assertEqual(
            bot.dateien_waehlen(viele), bot.dateien_waehlen(list(reversed(viele)))
        )

    def test_wenige_dateien_bleiben_alle(self):
        self.assertEqual(bot.dateien_waehlen(["a.py", "b.py"]), ["a.py", "b.py"])


if __name__ == "__main__":
    unittest.main()
