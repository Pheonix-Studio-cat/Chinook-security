"""Pruefungen fuer den Workflow-Bot.

Die Fixtures liegen als Dateien unter `fixtures/workflows/` -- sie enthalten
keine Geheimnisse, nur kaputte Workflows, und sind ausserhalb von
`.github/workflows/`, damit GitHub sie nicht ausfuehrt.
"""

import os
import pathlib
import unittest

from chinook import findings as fmt
from chinook.workflow_bot import is_pinned, run, scan_workflow, untrusted_in

WURZEL = pathlib.Path(__file__).resolve().parent.parent
KAPUTT = WURZEL / "fixtures" / "workflows" / "broken"
SAUBER = WURZEL / "fixtures" / "workflows" / "clean"

# Fixture -> Regel, die dort greifen muss.
ERWARTET = {
    "unpinned.yml": "unpinned-action",
    "injection.yml": "script-injection",
    "github-script.yml": "script-injection",
    "pr-target.yml": "pull-request-target-checkout",
    "write-all.yml": "permissions-write-all",
}


def regeln(datei: pathlib.Path) -> set[str]:
    rel = str(datei.relative_to(WURZEL))
    return {f.rule for f in scan_workflow(datei.read_text(encoding="utf-8"), rel)}


class FixtureTest(unittest.TestCase):
    def test_jedes_kaputte_fixture_wird_gefunden(self):
        for name, regel in ERWARTET.items():
            with self.subTest(fixture=name):
                datei = KAPUTT / name
                self.assertTrue(datei.exists(), f"{name} fehlt")
                self.assertIn(regel, regeln(datei))

    def test_jede_regel_hat_ein_fixture(self):
        # Sonst waechst die Regelliste, und die Gegenprobe merkt es nicht.
        alle = set()
        for datei in sorted(KAPUTT.glob("*.yml")):
            alle |= regeln(datei)
        alle |= {"permissions-missing"}
        bekannte = {
            "unpinned-action",
            "script-injection",
            "pull-request-target-checkout",
            "permissions-write-all",
            "permissions-missing",
        }
        self.assertEqual(alle, bekannte)

    def test_das_saubere_fixture_ergibt_nichts(self):
        for datei in sorted(SAUBER.glob("*.yml")):
            with self.subTest(fixture=datei.name):
                self.assertEqual(regeln(datei), set())

    def test_kaputt_und_sauber_sind_nicht_dieselbe_datei(self):
        sauber = (SAUBER / "sauber.yml").read_text(encoding="utf-8")
        for name in ERWARTET:
            with self.subTest(fixture=name):
                self.assertNotEqual((KAPUTT / name).read_text(encoding="utf-8"), sauber)


class FestlegungTest(unittest.TestCase):
    def test_nur_ein_voller_sha_gilt_als_festgelegt(self):
        self.assertTrue(is_pinned("0123456789abcdef0123456789abcdef01234567"))
        self.assertFalse(is_pinned("v4"))
        self.assertFalse(is_pinned("main"))
        self.assertFalse(is_pinned("0123456"))
        self.assertFalse(is_pinned(""))

    def test_eigene_actions_werden_nicht_gemeldet(self):
        self.assertEqual(scan_workflow("permissions:\n  contents: read\nuses: ./actions/x\n", "w.yml"), [])

    def test_fremde_action_wiegt_schwerer_als_eine_von_github(self):
        text = "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: {ref}\n"
        fremd = scan_workflow(text.format(ref="some-org/some-action@v3"), "w.yml")
        eigen = scan_workflow(text.format(ref="actions/checkout@v4"), "w.yml")
        self.assertEqual(fremd[0].severity, "medium")
        self.assertEqual(eigen[0].severity, "info")


class InjektionTest(unittest.TestCase):
    def test_erkennt_unvertrauten_kontext(self):
        self.assertEqual(untrusted_in("github.event.issue.title"), "github.event.issue.title")
        self.assertEqual(untrusted_in(" github.head_ref "), "github.head_ref")
        self.assertIsNone(untrusted_in("github.repository"))
        self.assertIsNone(untrusted_in("secrets.GITHUB_TOKEN"))

    def test_meldet_nur_innerhalb_von_run(self):
        vorlage = (
            "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
            "      - name: x\n        env:\n          T: ${{{{ github.event.issue.title }}}}\n"
            "        run: {befehl}\n"
        )
        sicher = scan_workflow(vorlage.format(befehl='echo "$T"'), "w.yml")
        unsicher = scan_workflow(
            vorlage.format(befehl='echo "${{ github.event.issue.title }}"'), "w.yml"
        )
        self.assertEqual([f.rule for f in sicher], [])
        self.assertEqual([f.rule for f in unsicher], ["script-injection"])

    def test_erkennt_auch_github_script(self):
        """`script:` ist JavaScript und wird ausgefuehrt wie `run:` eine Shell."""
        text = (
            "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
            "      - uses: actions/github-script@0123456789abcdef0123456789abcdef01234567\n"
            "        with:\n"
            "          script: |\n"
            '            const t = "${{ github.event.issue.title }}";\n'
        )
        self.assertEqual([f.rule for f in scan_workflow(text, "w.yml")], ["script-injection"])

    def test_ein_wert_in_with_ist_kein_befund(self):
        """Ein Wert, der als Eingabe uebergeben wird, ist nicht von sich aus
        gefaehrlich -- die Regel greift nur, wo etwas ausgefuehrt wird."""
        text = (
            "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
            "      - uses: fremd/action@0123456789abcdef0123456789abcdef01234567\n"
            "        with:\n"
            "          titel: ${{ github.event.issue.title }}\n"
        )
        self.assertEqual(scan_workflow(text, "w.yml"), [])

    def test_erkennt_den_mehrzeiligen_block(self):
        text = (
            "permissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
            "      - run: |\n"
            "          echo eins\n"
            "          echo ${{ github.event.comment.body }}\n"
            "      - run: echo harmlos\n"
        )
        treffer = scan_workflow(text, "w.yml")
        self.assertEqual([f.rule for f in treffer], ["script-injection"])
        self.assertEqual(treffer[0].line, 8)


class RechteTest(unittest.TestCase):
    def test_fehlende_rechte_werden_gemeldet(self):
        treffer = scan_workflow("name: x\non: push\n", "w.yml")
        self.assertEqual([f.rule for f in treffer], ["permissions-missing"])

    def test_vorhandene_rechte_werden_nicht_gemeldet(self):
        treffer = scan_workflow("name: x\non: push\npermissions:\n  contents: read\n", "w.yml")
        self.assertEqual(treffer, [])

    def test_rechte_nur_im_job_zaehlen_nicht_als_oberste_ebene(self):
        text = "name: x\non: push\njobs:\n  a:\n    permissions:\n      contents: read\n"
        self.assertEqual([f.rule for f in scan_workflow(text, "w.yml")], ["permissions-missing"])


class BefundTest(unittest.TestCase):
    def test_jeder_befund_ist_vollstaendig(self):
        for datei in sorted(KAPUTT.glob("*.yml")):
            rel = str(datei.relative_to(WURZEL))
            for befund in scan_workflow(datei.read_text(encoding="utf-8"), rel):
                with self.subTest(fixture=datei.name, regel=befund.rule):
                    self.assertIn(befund.severity, fmt.SEVERITIES)
                    self.assertTrue(befund.explanation.strip())
                    self.assertTrue(befund.remediation.strip())
                    self.assertGreaterEqual(befund.line, 1)


class EigenesRepoTest(unittest.TestCase):
    def test_die_eigenen_workflows_sind_sauber(self):
        """Ohne Nachsicht: auch kein Hinweis.

        Seit die eigenen Actions auf Commits festgelegt sind, gibt es keinen
        Grund mehr fuer eine Ausnahme. Was Chinook Security bei anderen anmahnt, haelt
        es selbst -- und ein Rueckfall faellt hier auf.
        """
        treffer = [f"{f.path}:{f.line} {f.rule}" for f in run(str(WURZEL))]
        self.assertEqual(treffer, [], "der Workflow-Bot findet etwas in den eigenen Workflows")

    def test_jede_eigene_action_ist_auf_einen_commit_festgelegt(self):
        import re

        for datei in sorted((WURZEL / ".github" / "workflows").glob("*.yml")):
            for zeile, text in enumerate(datei.read_text(encoding="utf-8").splitlines(), start=1):
                treffer = re.match(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)", text)
                if not treffer or treffer.group(1).startswith("./"):
                    continue
                with self.subTest(datei=datei.name, zeile=zeile):
                    ref = treffer.group(1).split("@", 1)[1] if "@" in treffer.group(1) else ""
                    self.assertTrue(
                        is_pinned(ref), f"{datei.name}:{zeile} zeigt auf {ref!r}"
                    )

    def test_die_fixtures_liegen_nicht_in_github_workflows(self):
        # Sonst wuerde GitHub die kaputten Workflows ausfuehren.
        verzeichnis = WURZEL / ".github" / "workflows"
        if verzeichnis.is_dir():
            for datei in verzeichnis.iterdir():
                self.assertNotIn("broken", datei.name)


if __name__ == "__main__":
    unittest.main()
