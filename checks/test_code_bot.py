"""Pruefungen fuer den Code-Bot."""

import os
import tempfile
import unittest

from chinook import findings as fmt
from chinook.code_bot import RULES, run, scan_text
from checks import fixtures


class RegelTest(unittest.TestCase):
    def test_jede_regel_hat_eine_probe(self):
        proben = fixtures.code_proben()
        self.assertEqual({r.name for r in RULES}, set(proben))

    def test_jede_regel_findet_ihren_kaputten_fall(self):
        for name, probe in fixtures.code_proben().items():
            with self.subTest(regel=name):
                treffer = scan_text(probe["kaputt"], f"x{probe['suffix']}")
                self.assertIn(name, [f.rule for f in treffer])

    def test_die_saubere_gegenzeile_ergibt_nichts(self):
        for name, probe in fixtures.code_proben().items():
            with self.subTest(regel=name):
                self.assertEqual(scan_text(probe["sauber"], f"x{probe['suffix']}"), [])

    def test_kaputt_und_sauber_unterscheiden_sich(self):
        for name, probe in fixtures.code_proben().items():
            with self.subTest(regel=name):
                self.assertNotEqual(probe["kaputt"], probe["sauber"])

    def test_jede_regel_ist_vollstaendig_beschrieben(self):
        for rule in RULES:
            with self.subTest(regel=rule.name):
                self.assertIn(rule.severity, fmt.SEVERITIES)
                self.assertIn(rule.confidence, fmt.CONFIDENCES)
                self.assertTrue(rule.explanation.strip())
                self.assertTrue(rule.remediation.strip())
                self.assertTrue(rule.suffixes)


class DateitypTest(unittest.TestCase):
    def test_eine_regel_greift_nur_bei_ihrer_endung(self):
        probe = fixtures.code_proben()["python-subprocess-shell"]
        self.assertTrue(scan_text(probe["kaputt"], "a.py"))
        self.assertEqual(scan_text(probe["kaputt"], "a.js"), [])

    def test_kommentarzeilen_werden_uebersprungen(self):
        probe = fixtures.code_proben()["python-eval-exec"]
        self.assertEqual(scan_text("# " + probe["kaputt"], "a.py"), [])
        self.assertEqual(scan_text("// " + fixtures.code_proben()["js-eval"]["kaputt"], "a.js"), [])


class BaumTest(unittest.TestCase):
    def test_findet_die_probe_im_verzeichnis(self):
        proben = fixtures.code_proben()
        with tempfile.TemporaryDirectory() as ordner:
            for name, probe in proben.items():
                fixtures.schreibe_code_datei(ordner, name, probe)
            gefunden = {f.rule for f in run(ordner)}
            self.assertEqual(gefunden, set(proben))

    def test_beachtet_ausschluesse(self):
        probe = fixtures.code_proben()["python-eval-exec"]
        with tempfile.TemporaryDirectory() as ordner:
            unter = os.path.join(ordner, "drittanbieter")
            os.makedirs(unter)
            fixtures.schreibe_code_datei(unter, "a", probe)
            self.assertTrue(run(ordner))
            self.assertEqual(run(ordner, excludes=["drittanbieter"]), [])


class EigenesRepoTest(unittest.TestCase):
    """Der Code-Bot laeuft ohne Ausnahmeliste ueber sein eigenes Repo.

    Das geht nur, weil die Proben als JSON liegen und die Regeltexte selbst
    kein Muster ausschreiben, das sie suchen. Beides ist Absicht.
    """

    def test_das_eigene_repo_ist_sauber(self):
        wurzel = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        treffer = [f"{f.path}:{f.line} {f.rule}" for f in run(wurzel)]
        self.assertEqual(treffer, [], "der Code-Bot findet etwas im eigenen Repo")


if __name__ == "__main__":
    unittest.main()
