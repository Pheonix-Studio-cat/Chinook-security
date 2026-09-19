"""Prueft den KI-Pruefer -- vor allem die drei Schranken gegen die Flut.

Der Auftrag lautete „bei jedem Fehler ein neues Issue". Woertlich umgesetzt
waere das eine Lawine: derselbe Code gibt dieselbe Antwort, und ein Modell,
das nach Fehlern gefragt wird, findet auch dort welche, wo keine sind.

Die drei Schranken sind damit **das Wesentliche an diesem Bot**, nicht
Beiwerk -- und deshalb stehen sie hier einzeln unter Beobachtung:
Wiedererkennung, Obergrenze, Kennzeichnung.

Dazu die Unterscheidung, die dieses Projekt schon mehrfach gerettet hat:
**eine unlesbare Antwort ist nicht dasselbe wie keine Befunde.** Das erste
ist ein Fehlschlag, das zweite ein Ergebnis. Wer beides gleich behandelt,
baut einen Bot, der bei jedem Modellfehler „alles in Ordnung" meldet.
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


class Wiedererkennung(unittest.TestCase):
    def test_gleicher_befund_gleicher_abdruck(self):
        self.assertEqual(pruefer.fingerabdruck(_befund()), pruefer.fingerabdruck(_befund()))

    def test_verschobene_zeile_bleibt_derselbe_befund(self):
        """Sonst waere jede eingefuegte Zeile weiter oben ein neues Issue."""
        self.assertEqual(
            pruefer.fingerabdruck(_befund(zeile=12)),
            pruefer.fingerabdruck(_befund(zeile=340)),
        )

    def test_grossschreibung_und_leerraum_aendern_nichts(self):
        self.assertEqual(
            pruefer.fingerabdruck(_befund(titel="Ungepruefte  Eingabe")),
            pruefer.fingerabdruck(_befund(titel="ungepruefte eingabe")),
        )

    def test_andere_datei_ist_ein_anderer_befund(self):
        self.assertNotEqual(
            pruefer.fingerabdruck(_befund(datei="a.py")),
            pruefer.fingerabdruck(_befund(datei="b.py")),
        )

    def test_abdruck_ueberlebt_den_weg_durch_ein_issue(self):
        """Der ganze Zweck: aus dem eigenen Issue-Text wieder herauslesbar."""
        befund = _befund()
        text = pruefer.issue_text(befund, "o/r", "https://example.invalid/1")
        gelesen = pruefer.abdruecke_aus_issues([{"body": text}])
        self.assertEqual(gelesen, {pruefer.fingerabdruck(befund)})

    def test_issue_ohne_marke_stoert_nicht(self):
        self.assertEqual(pruefer.abdruecke_aus_issues([{"body": "von Hand geschrieben"}]), set())

    def test_issue_ganz_ohne_text(self):
        self.assertEqual(pruefer.abdruecke_aus_issues([{"body": None}]), set())


class Schranken(unittest.TestCase):
    def test_bekannter_befund_wird_nicht_erneut_gemeldet(self):
        befund = _befund()
        neu, alt, _ = pruefer.auswaehlen([befund], {pruefer.fingerabdruck(befund)})
        self.assertEqual(neu, [])
        self.assertEqual(len(alt), 1)

    def test_unbekannter_befund_wird_gemeldet(self):
        neu, alt, _ = pruefer.auswaehlen([_befund()], set())
        self.assertEqual(len(neu), 1)
        self.assertEqual(alt, [])

    def test_obergrenze_haelt(self):
        viele = [_befund(titel=f"Befund {i}") for i in range(20)]
        neu, _alt, zurueck = pruefer.auswaehlen(viele, set())
        self.assertEqual(len(neu), pruefer.GRENZE)
        self.assertEqual(zurueck, 20 - pruefer.GRENZE)

    def test_schweres_zuerst_wenn_die_grenze_greift(self):
        """Die Obergrenze darf nicht ausgerechnet das Wichtige abschneiden."""
        viele = [_befund(titel=f"mittel {i}", schwere="mittel") for i in range(10)]
        viele.append(_befund(titel="das Schwere", schwere="hoch"))
        neu, _alt, _z = pruefer.auswaehlen(viele, set())
        self.assertIn("das Schwere", [b["titel"] for b in neu])

    def test_niedrig_wird_gar_nicht_gemeldet(self):
        neu, alt, zurueck = pruefer.auswaehlen([_befund(schwere="niedrig")], set())
        self.assertEqual((neu, alt, zurueck), ([], [], 0))


class Kennzeichnung(unittest.TestCase):
    def test_der_warnhinweis_steht_drin(self):
        text = pruefer.issue_text(_befund(), "o/r", "https://example.invalid/1")
        self.assertIn("Niemand hat das geprüft", text)

    def test_schliessen_ist_ausdruecklich_erlaubt(self):
        """Sonst sammeln sich falsche Befunde an, weil niemand sie zuzumachen wagt."""
        text = pruefer.issue_text(_befund(), "o/r", "https://example.invalid/1")
        self.assertIn("schliessen", text)

    def test_ort_und_lauf_stehen_drin(self):
        text = pruefer.issue_text(_befund(datei="src/x.py", zeile=7), "o/r", "https://example.invalid/42")
        self.assertIn("src/x.py", text)
        self.assertIn("Zeile 7", text)
        self.assertIn("https://example.invalid/42", text)

    def test_ohne_zeile_kein_leeres_zeile(self):
        befund = _befund()
        del befund["zeile"]
        self.assertNotIn("Zeile", pruefer.issue_text(befund, "o/r", "u"))


if __name__ == "__main__":
    unittest.main()
