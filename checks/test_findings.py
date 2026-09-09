"""Pruefungen fuer das gemeinsame Befund-Format."""

import json
import unittest

from chinook.findings import (
    Finding,
    SEVERITIES,
    exceeds,
    redact,
    report,
    sort_findings,
    to_sarif,
)


def beispiel(**overrides) -> Finding:
    werte = dict(
        bot="secret-bot",
        rule="github-token",
        title="GitHub-Token im Quelltext",
        severity="critical",
        confidence="high",
        path="src/konfiguration.py",
        line=4,
        explanation="Erklaerung",
        remediation="Gegenmittel",
        evidence=redact("x" * 40, kind="github-token"),
    )
    werte.update(overrides)
    return Finding(**werte)


class RedaktionTest(unittest.TestCase):
    def test_gibt_kein_zeichen_des_werts_zurueck(self):
        wert = "ghp_geheimnis_das_niemand_sehen_darf"
        ausgabe = redact(wert)
        for zeichen in set(wert):
            if zeichen.isalnum():
                self.assertNotIn(wert[:4], ausgabe)
                break
        self.assertNotIn(wert, ausgabe)
        self.assertIn(str(len(wert)), ausgabe)

    def test_kennt_keinen_hash_des_werts(self):
        # Ein Hash waere bei einem schwachen Passwort ein Orakel.
        import hashlib

        wert = "hunter2"
        ausgabe = redact(wert)
        self.assertNotIn(hashlib.sha256(wert.encode()).hexdigest()[:8], ausgabe)


class FindingTest(unittest.TestCase):
    def test_lehnt_unbekannten_schweregrad_ab(self):
        with self.assertRaises(ValueError):
            beispiel(severity="katastrophal")

    def test_lehnt_unbekannte_zuversicht_ab(self):
        with self.assertRaises(ValueError):
            beispiel(confidence="gefuehlt")

    def test_lehnt_zeile_null_ab(self):
        with self.assertRaises(ValueError):
            beispiel(line=0)

    def test_fingerabdruck_ist_stabil_und_ohne_wert(self):
        a = beispiel()
        b = beispiel(evidence="etwas ganz anderes")
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertNotEqual(a.fingerprint, beispiel(line=9).fingerprint)

    def test_ist_unveraenderlich(self):
        with self.assertRaises(Exception):
            beispiel().severity = "low"


class BerichtTest(unittest.TestCase):
    def test_sortiert_nach_schwere(self):
        leicht = beispiel(severity="info", rule="a")
        schwer = beispiel(severity="critical", rule="b")
        self.assertEqual([f.rule for f in sort_findings([leicht, schwer])], ["b", "a"])

    def test_zaehlt_je_schweregrad(self):
        ergebnis = report("secret-bot", [beispiel(), beispiel(severity="low", line=7)])
        self.assertEqual(ergebnis["summary"]["total"], 2)
        self.assertEqual(ergebnis["summary"]["by_severity"]["critical"], 1)
        self.assertEqual(ergebnis["summary"]["by_severity"]["low"], 1)
        self.assertEqual(set(ergebnis["summary"]["by_severity"]), set(SEVERITIES))

    def test_ist_gueltiges_json(self):
        json.dumps(report("secret-bot", [beispiel()]))


class SarifTest(unittest.TestCase):
    def test_hat_die_pflichtfelder(self):
        sarif = to_sarif("secret-bot", [beispiel()])
        self.assertEqual(sarif["version"], "2.1.0")
        lauf = sarif["runs"][0]
        self.assertEqual(lauf["tool"]["driver"]["name"], "chinook-secret-bot")
        ergebnis = lauf["results"][0]
        self.assertEqual(ergebnis["ruleId"], "secret-bot/github-token")
        self.assertEqual(ergebnis["level"], "error")
        ort = ergebnis["locations"][0]["physicalLocation"]
        self.assertEqual(ort["artifactLocation"]["uri"], "src/konfiguration.py")
        self.assertEqual(ort["region"]["startLine"], 4)

    def test_fuehrt_jede_regel_nur_einmal(self):
        sarif = to_sarif("secret-bot", [beispiel(), beispiel(line=9)])
        self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(sarif["runs"][0]["results"]), 2)


class SchwelleTest(unittest.TestCase):
    def test_schlaegt_ab_der_schwelle_an(self):
        self.assertTrue(exceeds([beispiel(severity="high")], "high"))
        self.assertTrue(exceeds([beispiel(severity="critical")], "high"))
        self.assertFalse(exceeds([beispiel(severity="medium")], "high"))

    def test_never_schlaegt_nie_an(self):
        self.assertFalse(exceeds([beispiel(severity="critical")], "never"))

    def test_lehnt_unbekannte_schwelle_ab(self):
        with self.assertRaises(ValueError):
            exceeds([], "sehr-schlimm")


if __name__ == "__main__":
    unittest.main()


class SchemaTest(unittest.TestCase):
    """Das Schema und der Code duerfen nicht auseinanderlaufen.

    Kein `jsonschema` -- die Zusicherungen, auf die es ankommt, sind mit der
    Standardbibliothek pruefbar, und eine Abhaengigkeit weniger ist eine
    Lieferkette weniger.
    """

    @classmethod
    def setUpClass(cls):
        import pathlib

        wurzel = pathlib.Path(__file__).resolve().parent.parent
        with open(wurzel / "schema" / "finding.schema.json", encoding="utf-8") as handle:
            cls.schema = json.load(handle)

    def test_bericht_hat_alle_pflichtfelder(self):
        ergebnis = report("secret-bot", [beispiel()])
        for feld in self.schema["required"]:
            self.assertIn(feld, ergebnis)

    def test_befund_hat_alle_pflichtfelder(self):
        eintrag = report("secret-bot", [beispiel()])["findings"][0]
        befund_schema = self.schema["properties"]["findings"]["items"]
        for feld in befund_schema["required"]:
            self.assertIn(feld, eintrag)
        self.assertEqual(set(eintrag), set(befund_schema["properties"]))

    def test_schweregrade_stimmen_ueberein(self):
        befund_schema = self.schema["properties"]["findings"]["items"]["properties"]
        self.assertEqual(set(befund_schema["severity"]["enum"]), set(SEVERITIES))

    def test_bericht_hat_keine_unbekannten_felder(self):
        ergebnis = report("secret-bot", [beispiel()])
        self.assertEqual(set(ergebnis) - set(self.schema["properties"]), set())
