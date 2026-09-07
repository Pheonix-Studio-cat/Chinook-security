"""Pruefungen fuer den Secret-Bot.

Jede Regel wird gegen einen absichtlich kaputten Fall gefahren **und** gegen
einen sauberen. Eine Regel, die nur gegen sauberen Code gelaufen ist, hat
nichts bewiesen.
"""

import json
import os
import tempfile
import unittest

from chinook import findings as fmt
from chinook.secret_bot import RULES, is_placeholder, run, scan_text, scan_tree
from checks import fixtures


class RegelTest(unittest.TestCase):
    def test_jede_regel_findet_ihren_kaputten_fall(self):
        for rule in RULES:
            with self.subTest(regel=rule.name):
                zeile = fixtures.secret_line(rule.name)
                treffer = scan_text(zeile, "src/konfiguration.py")
                self.assertTrue(
                    any(f.rule == rule.name for f in treffer),
                    f"Regel {rule.name} hat ihren eigenen kaputten Fall nicht gefunden",
                )

    def test_jede_regel_hat_ein_gegenmittel(self):
        for rule in RULES:
            with self.subTest(regel=rule.name):
                self.assertTrue(rule.remediation.strip())
                self.assertIn(rule.severity, fmt.SEVERITIES)
                self.assertIn(rule.confidence, fmt.CONFIDENCES)

    def test_sauberer_text_ergibt_nichts(self):
        self.assertEqual(scan_text(fixtures.CLEAN_FILE, "src/konfiguration.py"), [])

    def test_kaputt_und_sauber_unterscheiden_sich_wirklich(self):
        # Ohne diese Zusicherung koennte ein Fixture-Paar identisch sein und
        # beide Pruefungen waeren gruen, ohne etwas zu zeigen.
        for rule in RULES:
            with self.subTest(regel=rule.name):
                self.assertNotIn(fixtures.secret_line(rule.name), fixtures.CLEAN_FILE)

    def test_zeilennummer_stimmt(self):
        text = "erste Zeile\nzweite Zeile\n" + fixtures.secret_line("github-token")
        treffer = scan_text(text, "a.py")
        self.assertEqual(treffer[0].line, 3)


class PlatzhalterTest(unittest.TestCase):
    def test_erkennt_platzhalter(self):
        for wert in ("changeme", "your-token-here", "${GEHEIM}", "xxxxxxxxxxxx", "aaaaaaaaaaaa"):
            with self.subTest(wert=wert):
                self.assertTrue(is_placeholder(wert))

    def test_haelt_echte_werte_nicht_fuer_platzhalter(self):
        self.assertFalse(is_placeholder(fixtures.FAKE["assigned-credential"]))


class KeinLeckTest(unittest.TestCase):
    """Die wichtigste Pruefung des Bots: der Fund darf nirgends auftauchen."""

    def test_kein_wert_in_json_oder_sarif(self):
        for rule in RULES:
            if rule.name == "private-key-block":
                continue  # der Fund ist hier die Kopfzeile selbst, kein Wert
            with self.subTest(regel=rule.name):
                wert = fixtures.FAKE[rule.name]
                treffer = scan_text(fixtures.secret_line(rule.name), "src/konfiguration.py")
                als_json = json.dumps(fmt.report("secret-bot", treffer), ensure_ascii=False)
                als_sarif = json.dumps(fmt.to_sarif("secret-bot", treffer), ensure_ascii=False)
                self.assertNotIn(wert, als_json)
                self.assertNotIn(wert, als_sarif)

    def test_kein_wert_in_der_terminalausgabe(self):
        from chinook import cli

        with tempfile.TemporaryDirectory() as ordner:
            fixtures.write_broken_tree(ordner, "github-token")
            import contextlib
            import io

            puffer = io.StringIO()
            with contextlib.redirect_stdout(puffer), contextlib.redirect_stderr(puffer):
                code = cli.main(["secret-bot", "--path", ordner, "--fail-on", "critical"])
            self.assertEqual(code, 1)
            self.assertNotIn(fixtures.FAKE["github-token"], puffer.getvalue())


class BaumTest(unittest.TestCase):
    def test_findet_den_fund_im_verzeichnis(self):
        with tempfile.TemporaryDirectory() as ordner:
            fixtures.write_broken_tree(ordner, "aws-access-key-id")
            treffer = scan_tree(ordner)
            self.assertEqual([f.rule for f in treffer], ["aws-access-key-id"])
            self.assertEqual(treffer[0].path, "src/konfiguration.py")

    def test_beachtet_ausschluesse(self):
        with tempfile.TemporaryDirectory() as ordner:
            fixtures.write_broken_tree(ordner, "aws-access-key-id")
            self.assertEqual(scan_tree(ordner, excludes=["src"]), [])

    def test_ueberspringt_binaerdateien(self):
        with tempfile.TemporaryDirectory() as ordner:
            with open(os.path.join(ordner, "bild.bin"), "wb") as handle:
                handle.write(b"\x00\x01" + fixtures.FAKE["github-token"].encode())
            self.assertEqual(scan_tree(ordner), [])


class HistoryTest(unittest.TestCase):
    def test_findet_was_nur_noch_in_der_history_steht(self):
        with fixtures.make_repo_with_deleted_secret("aws-access-key-id") as ordner:
            self.assertEqual(scan_tree(ordner), [], "der Arbeitsbaum sollte sauber sein")
            treffer = run(ordner, history=True)
            self.assertTrue(
                any(f.rule == "aws-access-key-id" for f in treffer),
                "der Fund aus der History wurde nicht gemeldet",
            )

    def test_ohne_schalter_bleibt_die_history_ungeprueft(self):
        with fixtures.make_repo_with_deleted_secret("aws-access-key-id") as ordner:
            self.assertEqual(run(ordner, history=False), [])

    def test_kein_wert_aus_der_history_in_der_ausgabe(self):
        with fixtures.make_repo_with_deleted_secret("github-token") as ordner:
            treffer = run(ordner, history=True)
            als_json = json.dumps(fmt.report("secret-bot", treffer), ensure_ascii=False)
            self.assertNotIn(fixtures.FAKE["github-token"], als_json)


class EigenesRepoTest(unittest.TestCase):
    def test_das_eigene_repo_ist_sauber(self):
        wurzel = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        treffer = scan_tree(wurzel)
        self.assertEqual(
            [f"{f.path}:{f.line} {f.rule}" for f in treffer],
            [],
            "der Secret-Bot findet etwas im eigenen Repo",
        )


if __name__ == "__main__":
    unittest.main()
