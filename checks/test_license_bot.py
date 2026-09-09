"""Pruefungen fuer den Lizenz-Bot.

Die wichtigste davon ist `KeineRechtsaussageTest`: der Bot darf nie
**feststellen**, unter welcher Lizenz etwas steht.
"""

import json
import os
import tempfile
import unittest

from chinook.license_bot import BEKANNTE_KENNUNGEN, familie, kennung_familie, run

MIT_TEXT = (
    "MIT License\n\nCopyright (c) 2026 Beispiel\n\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
)
APACHE_TEXT = "                                 Apache License\n                           Version 2.0, January 2004\n"
GPL_TEXT = "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"


def repo(**dateien):
    ordner = tempfile.TemporaryDirectory()
    for name, inhalt in dateien.items():
        pfad = os.path.join(ordner.name, name.replace("__", "."))
        with open(pfad, "w", encoding="utf-8") as handle:
            handle.write(inhalt)
    return ordner


def regeln(pfad: str) -> list:
    return [f.rule for f in run(pfad)]


class LizenzdateiTest(unittest.TestCase):
    def test_fehlende_lizenzdatei_wird_gemeldet(self):
        with repo() as ordner:
            self.assertIn("license-file-missing", regeln(ordner))

    def test_vorhandene_lizenzdatei_wird_nicht_gemeldet(self):
        with repo(LICENSE=MIT_TEXT) as ordner:
            self.assertNotIn("license-file-missing", regeln(ordner))


class FamilieTest(unittest.TestCase):
    def test_erkennt_die_groben_familien(self):
        self.assertEqual(familie(MIT_TEXT), "MIT")
        self.assertEqual(familie(APACHE_TEXT), "Apache-2.0")
        self.assertEqual(familie(GPL_TEXT), "GPL-3.0")

    def test_unbekannter_text_ergibt_none(self):
        self.assertIsNone(familie("Diese Datei sagt nichts ueber Lizenzen."))

    def test_kennung_und_text_landen_in_derselben_familie(self):
        self.assertEqual(kennung_familie("MIT"), familie(MIT_TEXT))
        self.assertEqual(kennung_familie("Apache-2.0"), familie(APACHE_TEXT))


class PackageJsonTest(unittest.TestCase):
    def test_fehlende_erklaerung_wird_gemeldet(self):
        with repo(LICENSE=MIT_TEXT, package__json=json.dumps({"name": "x"})) as ordner:
            self.assertIn("license-undeclared", regeln(ordner))

    def test_passende_erklaerung_ergibt_nichts(self):
        with repo(LICENSE=MIT_TEXT, package__json=json.dumps({"license": "MIT"})) as ordner:
            self.assertEqual(regeln(ordner), [])

    def test_widerspruch_wird_gemeldet(self):
        with repo(LICENSE=APACHE_TEXT, package__json=json.dumps({"license": "MIT"})) as ordner:
            self.assertIn("license-mismatch", regeln(ordner))

    def test_unbekannte_kennung_ist_nur_ein_hinweis(self):
        with repo(LICENSE=MIT_TEXT, package__json=json.dumps({"license": "Meine-Eigene-1.0"})) as ordner:
            treffer = run(ordner)
            self.assertEqual([f.rule for f in treffer], ["license-unrecognised"])
            self.assertEqual(treffer[0].severity, "info")

    def test_verweis_auf_eine_fehlende_datei(self):
        # Genau der Fall, der in einem anderen Projekt zweimal uebersehen wurde:
        # ein Verweis, der ins Leere zeigt.
        with repo(LICENSE=MIT_TEXT, package__json=json.dumps({"license": "SEE LICENSE IN NUTZUNG.md"})) as ordner:
            self.assertIn("license-link-broken", regeln(ordner))

    def test_verweis_auf_eine_vorhandene_datei(self):
        with repo(
            LICENSE=MIT_TEXT,
            NUTZUNG__md="Bedingungen.",
            package__json=json.dumps({"license": "SEE LICENSE IN NUTZUNG.md"}),
        ) as ordner:
            self.assertEqual(regeln(ordner), [])


class PyprojectTest(unittest.TestCase):
    def test_erkennt_die_einfache_form(self):
        with repo(LICENSE=APACHE_TEXT, pyproject__toml='[project]\nname = "x"\nlicense = "MIT"\n') as ordner:
            self.assertIn("license-mismatch", regeln(ordner))

    def test_erkennt_die_tabellenform(self):
        with repo(LICENSE=APACHE_TEXT, pyproject__toml='[project]\nlicense = {text = "MIT"}\n') as ordner:
            self.assertIn("license-mismatch", regeln(ordner))

    def test_verweis_auf_eine_fehlende_datei(self):
        with repo(LICENSE=MIT_TEXT, pyproject__toml='[project]\nlicense = {file = "FEHLT.txt"}\n') as ordner:
            self.assertIn("license-link-broken", regeln(ordner))

    def test_projekt_ohne_lizenzfeld(self):
        with repo(LICENSE=MIT_TEXT, pyproject__toml='[project]\nname = "x"\n') as ordner:
            self.assertIn("license-undeclared", regeln(ordner))


class KeineRechtsaussageTest(unittest.TestCase):
    """Der Bot ordnet ein, er entscheidet nicht."""

    def test_kein_befund_behauptet_eine_lizenz(self):
        with repo(LICENSE=APACHE_TEXT, package__json=json.dumps({"license": "Eigen-1.0"})) as ordner:
            for befund in run(ordner):
                with self.subTest(regel=befund.rule):
                    text = f"{befund.title} {befund.explanation}".lower()
                    for behauptung in ("steht unter der lizenz", "ist lizenziert unter", "gilt die lizenz"):
                        self.assertNotIn(behauptung, text)

    def test_unsichere_faelle_verlangen_eine_pruefung(self):
        with repo(LICENSE=APACHE_TEXT, package__json=json.dumps({"license": "MIT"})) as ordner:
            treffer = run(ordner)
            self.assertTrue(treffer)
            for befund in treffer:
                self.assertIn("License status requires verification", befund.explanation)


class EigenesRepoTest(unittest.TestCase):
    def test_das_eigene_repo_ist_sauber(self):
        wurzel = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertEqual([f"{f.path} {f.rule}" for f in run(wurzel)], [])

    def test_die_kennungsliste_ist_nicht_leer(self):
        self.assertIn("MIT", BEKANNTE_KENNUNGEN)
        self.assertIn("Apache-2.0", BEKANNTE_KENNUNGEN)


if __name__ == "__main__":
    unittest.main()
