"""Prueft den KI-Pruefer -- vor allem die Schranken gegen die Flut.

Der Auftrag lautete „bei jedem Fehler ein neues Issue". Woertlich umgesetzt
waere das eine Lawine, aus drei Gruenden: derselbe Code gibt dieselbe
Antwort, ein Modell findet immer etwas, und **es formuliert jedes Mal
anders**.

Am dritten ist die erste Fassung gescheitert. Sie erkannte einen Befund an
Datei + Titel wieder; das Modell nannte denselben Befund im zweiten Lauf
anders, und es standen Dubletten im Repo.

Der naheliegende Ausweg -- Titel auf **Aehnlichkeit** vergleichen -- ist
gemessen und verworfen worden: echte Dubletten lagen bei 0.59 und 0.89,
wirklich verschiedene Befunde bei bis zu 0.90. Die Bereiche ueberlappen
vollstaendig, es gibt keine Schwelle. Deshalb steht hier auch ein Test, der
genau diese beiden Faelle festhaelt -- damit niemand die Heuristik in einem
stillen Moment doch noch einbaut.

Stattdessen: **ein Issue pro Datei**, dessen Text bei jedem Lauf neu
geschrieben wird. Die Wiedererkennung ist damit exakt statt geschaetzt.

Dazu die Unterscheidung, die dieses Projekt schon mehrfach gerettet hat:
**eine unlesbare Antwort ist nicht dasselbe wie keine Befunde.**
"""

from __future__ import annotations

import importlib.util
import os
import unittest

WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_pfad = os.path.join(WURZEL, ".github", "ki-pruefer.py")
_spec = importlib.util.spec_from_file_location("ki_pruefer", _pfad)
pruefer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pruefer)


def _befund(titel="Ungepruefte Eingabe", datei="app.py", schwere="hoch", zeile=12):
    return {
        "titel": titel,
        "datei": datei,
        "zeile": zeile,
        "schwere": schwere,
        "begruendung": "Der Wert wird ohne Pruefung weitergereicht.",
    }


class AntwortLesen(unittest.TestCase):
    def test_nacktes_json(self):
        self.assertEqual(len(pruefer.befunde_aus_text('[{"titel":"A","datei":"a.py","schwere":"hoch","begruendung":"x"}]')), 1)

    def test_in_einem_codeblock(self):
        text = 'Hier ist das Ergebnis:\n```json\n[{"titel":"A","datei":"a.py","schwere":"hoch","begruendung":"x"}]\n```\nViel Erfolg!'
        self.assertEqual(len(pruefer.befunde_aus_text(text)), 1)

    def test_mit_geschwaetz_davor_und_danach(self):
        text = 'Gerne! [{"titel":"A","datei":"a.py","schwere":"mittel","begruendung":"x"}] Soll ich mehr?'
        self.assertEqual(len(pruefer.befunde_aus_text(text)), 1)

    def test_leere_liste_ist_ein_ergebnis(self):
        """Nichts gefunden ist erlaubt -- und etwas anderes als unlesbar."""
        self.assertEqual(pruefer.befunde_aus_text("[]"), [])

    def test_leere_antwort_ist_kein_ergebnis(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text("   ")

    def test_prosa_statt_json(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text("Ich habe drei Probleme gefunden, unter anderem in app.py.")

    def test_kaputtes_json(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text('[{"titel": "A",}]')

    def test_fehlendes_feld_faellt_auf(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text('[{"titel":"A","datei":"a.py","schwere":"hoch"}]')

    def test_erfundene_schwere_faellt_auf(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text('[{"titel":"A","datei":"a.py","schwere":"katastrophal","begruendung":"x"}]')


class NichtNochEinmalAehnlichkeit(unittest.TestCase):
    """Haelt fest, warum Titel-Aehnlichkeit nicht taugt.

    Ohne diesen Test sieht die Idee beim naechsten Lesen wieder klug aus.
    """

    def _aehnlich(self, a, b):
        import difflib
        import re as _re

        n = lambda s: _re.sub(r"\s+", " ", s.strip().lower())
        return difflib.SequenceMatcher(None, n(a), n(b)).ratio()

    def test_echte_dublette_kann_unaehnlich_sein(self):
        wert = self._aehnlich(
            "Nicht-String-Felder des Modells verursachen einen Absturz",
            "Nicht-stringartige Felder führen später zum Absturz",
        )
        self.assertLess(wert, 0.7, "gemessen 0.59 -- und das war dieselbe Sache")

    def test_verschiedene_befunde_koennen_sehr_aehnlich_sein(self):
        wert = self._aehnlich(
            "Nicht behandelter Fehlerfall beim Lesen",
            "Nicht behandelter Fehlerfall beim Schreiben",
        )
        self.assertGreater(wert, 0.85, "gemessen 0.90 -- und das sind zwei Fehler")


class Gruppieren(unittest.TestCase):
    def test_nach_datei_zusammengefasst(self):
        gruppen = pruefer.nach_dateien([_befund(datei="a.py"), _befund(titel="Zweites", datei="a.py")])
        self.assertEqual(list(gruppen), ["a.py"])
        self.assertEqual(len(gruppen["a.py"]), 2)

    def test_verschiedene_dateien_bleiben_getrennt(self):
        gruppen = pruefer.nach_dateien([_befund(datei="a.py"), _befund(datei="b.py")])
        self.assertEqual(sorted(gruppen), ["a.py", "b.py"])

    def test_niedrig_faellt_raus(self):
        self.assertEqual(pruefer.nach_dateien([_befund(schwere="niedrig")]), {})

    def test_schweres_steht_oben(self):
        gruppen = pruefer.nach_dateien(
            [_befund(titel="mittel", schwere="mittel"), _befund(titel="hoch", schwere="hoch")]
        )
        self.assertEqual([b["titel"] for b in gruppen["app.py"]], ["hoch", "mittel"])


class Wiedererkennung(unittest.TestCase):
    def test_marke_ueberlebt_den_weg_durch_ein_issue(self):
        text = pruefer.issue_text("src/a.py", [_befund()], "o/r", "u")
        self.assertEqual(pruefer.dateien_aus_issues([{"body": text}]), {"src/a.py": {"body": text}})

    def test_umformulierter_titel_aendert_nichts(self):
        """Der Fall, an dem die erste Fassung gescheitert ist."""
        erst = pruefer.issue_text("a.py", [_befund(titel="Nicht-String-Felder stuerzen ab")], "o/r", "u")
        bestehend = pruefer.dateien_aus_issues([{"body": erst, "number": 7}])
        gefunden = pruefer.nach_dateien([_befund(titel="Nicht-stringartige Felder brechen spaeter", datei="a.py")])
        anlegen, aktualisieren, _s, _z = pruefer.plan(gefunden, bestehend, ["a.py"])
        self.assertEqual(anlegen, [], "haette ein zweites Issue angelegt -- genau der alte Fehler")
        self.assertEqual(aktualisieren, ["a.py"])

    def test_issue_ohne_marke_stoert_nicht(self):
        self.assertEqual(pruefer.dateien_aus_issues([{"body": "von Hand"}]), {})

    def test_issue_ganz_ohne_text(self):
        self.assertEqual(pruefer.dateien_aus_issues([{"body": None}]), {})


class DerPlan(unittest.TestCase):
    def test_neue_datei_wird_angelegt(self):
        anlegen, akt, zu, _z = pruefer.plan(pruefer.nach_dateien([_befund(datei="a.py")]), {}, ["a.py"])
        self.assertEqual((anlegen, akt, zu), (["a.py"], [], []))

    def test_bekannte_datei_wird_aktualisiert(self):
        anlegen, akt, zu, _z = pruefer.plan(
            pruefer.nach_dateien([_befund(datei="a.py")]), {"a.py": {"number": 1}}, ["a.py"]
        )
        self.assertEqual((anlegen, akt, zu), ([], ["a.py"], []))

    def test_saubere_datei_wird_geschlossen(self):
        anlegen, akt, zu, _z = pruefer.plan({}, {"a.py": {"number": 1}}, ["a.py"])
        self.assertEqual((anlegen, akt, zu), ([], [], ["a.py"]))

    def test_nicht_angesehene_datei_wird_nie_geschlossen(self):
        """Sonst raeumte jeder Push die Issues aller unberuehrten Dateien ab."""
        anlegen, akt, zu, _z = pruefer.plan({}, {"b.py": {"number": 2}}, ["a.py"])
        self.assertEqual(zu, [], "b.py wurde gar nicht angesehen und geht diesen Lauf nichts an")

    def test_obergrenze_gilt_nur_fuers_anlegen(self):
        viele = pruefer.nach_dateien([_befund(datei=f"d{i}.py") for i in range(12)])
        anlegen, _a, _z2, zurueck = pruefer.plan(viele, {}, list(viele))
        self.assertEqual(len(anlegen), pruefer.GRENZE)
        self.assertEqual(zurueck, 12 - pruefer.GRENZE)

    def test_aktualisieren_kennt_keine_obergrenze(self):
        """Aktualisieren kann keine Flut ausloesen -- die Zahl bleibt gleich."""
        viele = pruefer.nach_dateien([_befund(datei=f"d{i}.py") for i in range(12)])
        bestehend = {f"d{i}.py": {"number": i} for i in range(12)}
        _a, aktualisieren, _z, zurueck = pruefer.plan(viele, bestehend, list(viele))
        self.assertEqual(len(aktualisieren), 12)
        self.assertEqual(zurueck, 0)


class Kennzeichnung(unittest.TestCase):
    def test_der_warnhinweis_steht_drin(self):
        self.assertIn("Niemand hat das geprüft", pruefer.issue_text("a.py", [_befund()], "o/r", "u"))

    def test_schliessen_ist_ausdruecklich_erlaubt(self):
        self.assertIn("schliessen", pruefer.issue_text("a.py", [_befund()], "o/r", "u"))

    def test_es_steht_drin_dass_der_text_ersetzt_wird(self):
        """Sonst schreibt jemand Notizen hinein, die der naechste Lauf loescht."""
        text = pruefer.issue_text("a.py", [_befund()], "o/r", "u")
        self.assertIn("neu geschrieben", text)
        self.assertIn("Kommentar", text)

    def test_alle_befunde_der_datei_stehen_drin(self):
        text = pruefer.issue_text("a.py", [_befund(titel="Erstes"), _befund(titel="Zweites")], "o/r", "u")
        self.assertIn("Erstes", text)
        self.assertIn("Zweites", text)

    def test_ohne_zeile_kein_leeres_zeile(self):
        befund = _befund()
        del befund["zeile"]
        self.assertNotIn("Zeile", pruefer.issue_text("a.py", [befund], "o/r", "u"))


class NichtTextFelder(unittest.TestCase):
    """Vom Pruefer an sich selbst gefunden (Issue #15/#18)."""

    def test_zahl_statt_titel(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text('[{"titel":42,"datei":"a.py","schwere":"hoch","begruendung":"x"}]')

    def test_liste_statt_begruendung(self):
        with self.assertRaises(pruefer.Unbrauchbar):
            pruefer.befunde_aus_text('[{"titel":"A","datei":"a.py","schwere":"hoch","begruendung":["x"]}]')


if __name__ == "__main__":
    unittest.main()
