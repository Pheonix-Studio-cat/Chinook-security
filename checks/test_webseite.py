"""Pruefungen fuer die Website.

Zwei Sorten. Die erste: steht auf der Seite, was drauf stehen soll. Die zweite,
wichtigere: **beschreibt die Seite, was die Bots wirklich tun** -- eine
Regeltabelle, die driften darf, driftet.
"""

import html
import json
import os
import pathlib
import tempfile
import unittest

from chinook import code_bot, dependency_bot, license_bot, secret_bot, workflow_bot
from webseite import build

WURZEL = pathlib.Path(__file__).resolve().parent.parent
ALLE = (secret_bot, workflow_bot, dependency_bot, code_bot, license_bot)


def seite(gegenprobe=None) -> str:
    return build.baue(gegenprobe)


class RegelnAufDerSeiteTest(unittest.TestCase):
    def test_jede_regel_steht_auf_der_seite(self):
        text = seite()
        for modul in ALLE:
            for regel in modul.regeln():
                with self.subTest(bot=modul.BOT, regel=regel["name"]):
                    self.assertIn(regel["name"], text)
                    self.assertIn(html.escape(regel["titel"], quote=False), text)

    def test_die_zahl_der_regeln_stimmt(self):
        gesamt = sum(len(modul.regeln()) for modul in ALLE)
        self.assertIn(f'<span class="zahl">{gesamt}</span>', seite())

    def test_jede_regel_ist_vollstaendig_beschrieben(self):
        for modul in ALLE:
            for regel in modul.regeln():
                with self.subTest(bot=modul.BOT, regel=regel["name"]):
                    self.assertTrue(regel["titel"].strip())
                    self.assertTrue(regel["was"].strip())
                    self.assertIn(regel["schwere"], build.SCHWERE_TEXT)


class KeineDriftTest(unittest.TestCase):
    """Die Regeltabellen muessen den Regeln entsprechen, die die Bots melden."""

    def test_secret_bot(self):
        self.assertEqual(
            {r["name"] for r in secret_bot.regeln()}, {r.name for r in secret_bot.RULES}
        )

    def test_code_bot(self):
        self.assertEqual(
            {r["name"] for r in code_bot.regeln()}, {r.name for r in code_bot.RULES}
        )

    def test_workflow_bot(self):
        gesehen = set()
        kaputt = WURZEL / "fixtures" / "workflows" / "broken"
        for datei in sorted(kaputt.glob("*.yml")):
            gesehen |= {
                f.rule for f in workflow_bot.scan_workflow(datei.read_text(encoding="utf-8"), "w.yml")
            }
        self.assertEqual({r["name"] for r in workflow_bot.regeln()}, gesehen)

    def test_dependency_bot(self):
        with tempfile.TemporaryDirectory() as ordner:
            pfad = os.path.join(ordner, "requirements.txt")
            with open(pfad, "w", encoding="utf-8") as handle:
                handle.write("alpha==1.0\nbeta>=2.0\n")
            with open(pfad, encoding="utf-8") as handle:
                text = handle.read()
            deps, lose = dependency_bot.parse_requirements(text, "requirements.txt")
        gesehen = {f.rule for f in lose} | {
            f.rule for f in dependency_bot.to_findings(deps, {0: ["GHSA-x"]})
        }
        self.assertEqual({r["name"] for r in dependency_bot.regeln()}, gesehen)

    def test_license_bot(self):
        mit = "MIT License\n\nPermission is hereby granted, free of charge, to any person\n"
        apache = "                Apache License\n           Version 2.0, January 2004\n"
        faelle = (
            {},  # gar nichts -> license-file-missing
            {"LICENSE": mit, "package.json": json.dumps({"name": "x"})},
            {"LICENSE": mit, "package.json": json.dumps({"license": "SEE LICENSE IN FEHLT.md"})},
            {"LICENSE": apache, "package.json": json.dumps({"license": "MIT"})},
            {"LICENSE": mit, "package.json": json.dumps({"license": "Eigen-1.0"})},
        )
        gesehen = set()
        for dateien in faelle:
            with tempfile.TemporaryDirectory() as ordner:
                for name, inhalt in dateien.items():
                    with open(os.path.join(ordner, name), "w", encoding="utf-8") as handle:
                        handle.write(inhalt)
                gesehen |= {f.rule for f in license_bot.run(ordner)}
        self.assertEqual({r["name"] for r in license_bot.regeln()}, gesehen)


class GegenprobeAufDerSeiteTest(unittest.TestCase):
    def test_ohne_ergebnis_wird_nichts_behauptet(self):
        text = seite(None)
        self.assertIn("kein Ergebnis vor", text)
        self.assertNotIn("Mutationen gefangen", text)

    def test_mit_ergebnis_stehen_die_zahlen_da(self):
        text = seite(
            {
                "grundlauf": "gruen",
                "gesamt": 25,
                "gefangen": 25,
                "mutationen": [
                    {"name": "beispiel", "trifft": "etwas", "gefangen": True},
                ],
            }
        )
        self.assertIn("25 von 25 Mutationen gefangen", text)
        self.assertIn("gefangen</span>", text)

    def test_eine_entkommene_mutation_wird_nicht_versteckt(self):
        text = seite(
            {
                "grundlauf": "gruen",
                "gesamt": 2,
                "gefangen": 1,
                "mutationen": [
                    {"name": "gut", "trifft": "a", "gefangen": True},
                    {"name": "schlecht", "trifft": "b", "gefangen": False},
                ],
            }
        )
        self.assertIn("1 von 2 Mutationen gefangen", text)
        self.assertIn("ENTKOMMEN", text)

    def test_ein_roter_grundlauf_wird_gesagt(self):
        text = seite({"grundlauf": "rot", "gesamt": 25, "gefangen": 0, "mutationen": []})
        self.assertIn("nicht gruen", text)


class KeineFremdenRessourcenTest(unittest.TestCase):
    """Eine Seite, die ein Sicherheitswerkzeug beschreibt, laedt nichts nach."""

    def test_kein_fremdes_stylesheet_und_kein_skript(self):
        text = seite()
        self.assertNotIn("<script", text)
        self.assertNotIn('rel="stylesheet"', text)
        self.assertNotIn("@import", text)

    def test_nur_verweise_auf_das_eigene_repo(self):
        import re

        for adresse in re.findall(r'(?:src|href)="(https?://[^"]+)"', seite()):
            with self.subTest(adresse=adresse):
                self.assertTrue(adresse.startswith(build.REPO), adresse)


class EscapingTest(unittest.TestCase):
    def test_spitze_klammern_werden_maskiert(self):
        gefaehrlich = {
            "grundlauf": "gruen",
            "gesamt": 1,
            "gefangen": 1,
            "mutationen": [
                {"name": "<script>alarm()</script>", "trifft": "a & b", "gefangen": True}
            ],
        }
        text = seite(gefaehrlich)
        self.assertNotIn("<script>alarm()</script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("a &amp; b", text)


class BauTest(unittest.TestCase):
    def test_schreibt_die_datei(self):
        with tempfile.TemporaryDirectory() as ordner:
            build.main(["--out", ordner])
            ziel = pathlib.Path(ordner) / "index.html"
            self.assertTrue(ziel.is_file())
            inhalt = ziel.read_text(encoding="utf-8")
        self.assertTrue(inhalt.startswith("<!doctype html>"))
        self.assertIn('<html lang="de">', inhalt)
        self.assertIn("viewport", inhalt)

    def test_eine_fehlende_gegenprobe_ist_kein_fehler(self):
        with tempfile.TemporaryDirectory() as ordner:
            code = build.main(["--out", ordner, "--gegenprobe", os.path.join(ordner, "gibt-es-nicht.json")])
        self.assertEqual(code, 0)

    def test_zaehlt_die_pruefungen(self):
        self.assertGreater(build.zaehle_pruefungen(), 100)


if __name__ == "__main__":
    unittest.main()
