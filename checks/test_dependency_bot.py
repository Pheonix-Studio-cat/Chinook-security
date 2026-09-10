"""Pruefungen fuer den Dependency-Bot.

Gefahren wird gegen einen **Stub auf dem eigenen Rechner**, nicht gegen die
echte OSV-Adresse: aus dieser Umgebung blockiert der Egress-Proxy sie, und eine
Pruefung, die vom Netz abhaengt, ist keine Pruefung, sondern eine Wettervorhersage.
"""

import json
import os
import tempfile
import unittest

from chinook.dependency_bot import (
    PARSER,
    OsvUnavailable,
    collect,
    parse_cargo_lock,
    parse_composer_lock,
    parse_go_mod,
    parse_package_lock,
    parse_pnpm_lock,
    parse_poetry_lock,
    parse_requirements,
    parse_yarn_lock,
    query_osv,
    run,
    to_findings,
)
from checks import fixtures


class ParserTest(unittest.TestCase):
    def test_requirements_nimmt_nur_festgelegte_versionen(self):
        text = "django==2.2.0\nrequests>=2.0\n# kommentar\nflask==1.0 ; python_version < '3.9'\n"
        deps, lose = parse_requirements(text, "requirements.txt")
        self.assertEqual([(d.name, d.version) for d in deps], [("django", "2.2.0"), ("flask", "1.0")])
        self.assertEqual([f.rule for f in lose], ["dependency-unpinned"])
        self.assertEqual(lose[0].line, 2)

    def test_requirements_ueberspringt_optionen_und_urls(self):
        text = "-r andere.txt\n--index-url https://example.invalid\ngit+https://example.invalid/x.git\n"
        deps, lose = parse_requirements(text, "requirements.txt")
        self.assertEqual(deps, [])
        self.assertEqual(lose, [])

    def test_package_lock_version_3(self):
        lock = json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.20"},
                },
            }
        )
        deps, _ = parse_package_lock(lock, "package-lock.json")
        self.assertEqual([(d.name, d.version, d.ecosystem) for d in deps], [("lodash", "4.17.20", "npm")])

    def test_package_lock_version_1(self):
        lock = json.dumps(
            {
                "lockfileVersion": 1,
                "dependencies": {"lodash": {"version": "4.17.20", "dependencies": {"x": {"version": "1.0.0"}}}},
            }
        )
        deps, _ = parse_package_lock(lock, "package-lock.json")
        self.assertEqual(sorted((d.name, d.version) for d in deps), [("lodash", "4.17.20"), ("x", "1.0.0")])

    def test_go_mod_block_und_einzeln(self):
        text = "module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3 // indirect\n)\n\nrequire golang.org/x/net v0.7.0\n"
        deps, _ = parse_go_mod(text, "go.mod")
        self.assertEqual(
            [(d.name, d.version, d.line) for d in deps],
            [("github.com/foo/bar", "v1.2.3", 4), ("golang.org/x/net", "v0.7.0", 7)],
        )

    def test_kaputtes_json_wirft_nicht(self):
        self.assertEqual(parse_package_lock("{kein json", "package-lock.json"), ([], []))


class WeitereSperrdateienTest(unittest.TestCase):
    """poetry, Cargo, yarn, pnpm, composer -- je Format seine eigenen Fallen."""

    def test_poetry_lock(self):
        text = (
            '[[package]]\nname = "certifi"\nversion = "2023.7.22"\n'
            'description = "irgendwas"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "2.0.7"\n\n'
            "[metadata]\nlock-version = \"2.0\"\n"
        )
        deps, _ = parse_poetry_lock(text, "poetry.lock")
        self.assertEqual(
            [(d.name, d.version, d.ecosystem) for d in deps],
            [("certifi", "2023.7.22", "PyPI"), ("urllib3", "2.0.7", "PyPI")],
        )

    def test_poetry_metadata_ist_kein_paket(self):
        text = '[metadata]\nname = "nicht-ein-paket"\nversion = "1.0"\n'
        self.assertEqual(parse_poetry_lock(text, "poetry.lock")[0], [])

    def test_cargo_lock(self):
        text = '[[package]]\nname = "serde"\nversion = "1.0.188"\n'
        deps, _ = parse_cargo_lock(text, "Cargo.lock")
        self.assertEqual([(d.name, d.version, d.ecosystem) for d in deps], [("serde", "1.0.188", "crates.io")])

    def test_yarn_lock_format_1(self):
        deps, _ = parse_yarn_lock('lodash@^4.17.20:\n  version "4.17.21"\n', "yarn.lock")
        self.assertEqual([(d.name, d.version) for d in deps], [("lodash", "4.17.21")])

    def test_yarn_lock_berry_mit_doppelpunkt_im_schluessel(self):
        # `npm:` im Schluessel hat den ersten Entwurf zum Stolpern gebracht.
        deps, _ = parse_yarn_lock('"@scope/x@npm:^1.0.0":\n  version: 1.2.3\n', "yarn.lock")
        self.assertEqual([(d.name, d.version) for d in deps], [("@scope/x", "1.2.3")])

    def test_yarn_lock_mehrere_angaben_je_eintrag(self):
        deps, _ = parse_yarn_lock('chalk@^4.0.0, chalk@^4.1.0:\n  version "4.1.2"\n', "yarn.lock")
        self.assertEqual([(d.name, d.version) for d in deps], [("chalk", "4.1.2")])

    def test_pnpm_lock_drei_formen(self):
        text = (
            "packages:\n"
            "  /lodash@4.17.21:\n    resolution: {}\n"
            "  /alt/1.0.0:\n    resolution: {}\n"
            "  '@scope/y@2.0.0':\n    resolution: {}\n"
        )
        deps, _ = parse_pnpm_lock(text, "pnpm-lock.yaml")
        self.assertEqual(
            sorted((d.name, d.version) for d in deps),
            [("@scope/y", "2.0.0"), ("alt", "1.0.0"), ("lodash", "4.17.21")],
        )

    def test_pnpm_nur_der_paketteil(self):
        """`snapshots:` fuehrt in Format 9 dieselben Pakete ein zweites Mal.

        Diese Pruefung stand zuerst da und bewies nichts -- die Gegenprobe hat
        das aufgedeckt: die Mutation, die den Abschnittswaechter entfernt, blieb
        gruen, weil die Beispieldatei gar keine Zeile enthielt, die faelschlich
        als Paket durchgegangen waere. Jetzt enthaelt sie eine.
        """
        text = (
            "lockfileVersion: '9.0'\n\n"
            "settings:\n  autoInstallPeers: true\n\n"
            "packages:\n\n"
            "  chalk@4.1.2:\n    resolution: {integrity: sha512-x}\n\n"
            "snapshots:\n\n"
            "  chalk@4.1.2:\n    dependencies:\n      ansi-styles: 4.3.0\n"
        )
        deps, _ = parse_pnpm_lock(text, "pnpm-lock.yaml")
        self.assertEqual(
            [(d.name, d.version) for d in deps],
            [("chalk", "4.1.2")],
            "jedes Paket genau einmal -- sonst wird es doppelt abgefragt",
        )

    def test_pnpm_ohne_paketteil(self):
        text = "lockfileVersion: '6.0'\n\nsettings:\n  autoInstallPeers: true\n"
        self.assertEqual(parse_pnpm_lock(text, "pnpm-lock.yaml")[0], [])

    def test_composer_lock_mit_und_ohne_v(self):
        text = json.dumps(
            {
                "packages": [{"name": "monolog/monolog", "version": "v2.9.1"}],
                "packages-dev": [{"name": "phpunit/phpunit", "version": "10.0.0"}],
            }
        )
        deps, _ = parse_composer_lock(text, "composer.lock")
        self.assertEqual(
            sorted((d.name, d.version, d.ecosystem) for d in deps),
            [("monolog/monolog", "2.9.1", "Packagist"), ("phpunit/phpunit", "10.0.0", "Packagist")],
        )

    def test_jede_sperrdatei_hat_einen_parser(self):
        self.assertEqual(
            sorted(PARSER),
            [
                "Cargo.lock",
                "composer.lock",
                "go.mod",
                "package-lock.json",
                "pnpm-lock.yaml",
                "poetry.lock",
                "requirements.txt",
                "yarn.lock",
            ],
        )

    def test_die_oekosystem_namen_sind_die_von_osv(self):
        """Sie werden zusaetzlich gegen den echten Dienst geprueft --
        `checks/oekosystemprobe.py`, in der Selbstpruefung."""
        from checks import oekosystemprobe

        aus_der_probe = {ecosystem for ecosystem, _, _ in oekosystemprobe.PROBEN}
        aus_dem_bot = set()
        for name, parser in PARSER.items():
            if name == "requirements.txt":
                text = "alpha==1.0\n"
            elif name == "package-lock.json":
                text = json.dumps({"packages": {"node_modules/a": {"version": "1.0"}}})
            elif name == "go.mod":
                text = "require example.com/a v1.0.0\n"
            elif name in ("poetry.lock", "Cargo.lock"):
                text = '[[package]]\nname = "a"\nversion = "1.0"\n'
            elif name == "yarn.lock":
                text = 'a@^1.0.0:\n  version "1.0.0"\n'
            elif name == "pnpm-lock.yaml":
                text = "packages:\n  /a@1.0.0:\n    resolution: {}\n"
            else:
                text = json.dumps({"packages": [{"name": "a/b", "version": "1.0"}]})
            aus_dem_bot |= {d.ecosystem for d in parser(text, name)[0]}
        self.assertEqual(aus_dem_bot, aus_der_probe)


class SammelnTest(unittest.TestCase):
    def test_findet_die_sperrdatei(self):
        with tempfile.TemporaryDirectory() as ordner:
            fixtures.schreibe_requirements(ordner, ["django==2.2.0"])
            deps, _ = collect(ordner)
            self.assertEqual([(d.name, d.path) for d in deps], [("django", "requirements.txt")])

    def test_findet_jede_art_von_sperrdatei(self):
        inhalte = {
            "requirements.txt": "alpha==1.0\n",
            "poetry.lock": '[[package]]\nname = "b"\nversion = "1.0"\n',
            "Cargo.lock": '[[package]]\nname = "c"\nversion = "1.0"\n',
            "yarn.lock": 'd@^1.0.0:\n  version "1.0.0"\n',
            "pnpm-lock.yaml": "packages:\n  /e@1.0.0:\n    resolution: {}\n",
            "composer.lock": json.dumps({"packages": [{"name": "f/g", "version": "1.0"}]}),
            "go.mod": "require example.com/h v1.0.0\n",
        }
        with tempfile.TemporaryDirectory() as ordner:
            for name, inhalt in inhalte.items():
                with open(os.path.join(ordner, name), "w", encoding="utf-8") as handle:
                    handle.write(inhalt)
            deps, _ = collect(ordner)
        self.assertEqual(
            sorted({d.path for d in deps}), sorted(inhalte), "eine Sperrdatei wurde uebersehen"
        )

    def test_ueberspringt_node_modules(self):
        with tempfile.TemporaryDirectory() as ordner:
            unter = os.path.join(ordner, "node_modules", "irgendwas")
            os.makedirs(unter)
            fixtures.schreibe_requirements(unter, ["django==2.2.0"])
            self.assertEqual(collect(ordner)[0], [])


class AbfrageTest(unittest.TestCase):
    def test_meldet_die_schwachstelle(self):
        antwort = {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}, {"id": "CVE-2019-0000"}]}]}
        with fixtures.OsvStub(antwort=antwort) as stub, tempfile.TemporaryDirectory() as ordner:
            fixtures.schreibe_requirements(ordner, ["django==2.2.0"])
            treffer = run(ordner, url=stub.url, timeout=5)
        self.assertEqual([f.rule for f in treffer], ["known-vulnerability"])
        self.assertEqual(treffer[0].severity, "high")
        self.assertIn("GHSA-aaaa-bbbb-cccc", treffer[0].explanation)

    def test_schickt_die_richtige_anfrage(self):
        with fixtures.OsvStub() as stub, tempfile.TemporaryDirectory() as ordner:
            fixtures.schreibe_requirements(ordner, ["django==2.2.0"])
            run(ordner, url=stub.url, timeout=5)
            self.assertEqual(
                stub.anfragen[0]["queries"],
                [{"package": {"name": "django", "ecosystem": "PyPI"}, "version": "2.2.0"}],
            )

    def test_ohne_treffer_keine_befunde(self):
        with fixtures.OsvStub() as stub, tempfile.TemporaryDirectory() as ordner:
            fixtures.schreibe_requirements(ordner, ["django==2.2.0"])
            self.assertEqual(run(ordner, url=stub.url, timeout=5), [])

    def test_ohne_abhaengigkeiten_wird_nicht_gefragt(self):
        with fixtures.OsvStub() as stub, tempfile.TemporaryDirectory() as ordner:
            self.assertEqual(run(ordner, url=stub.url, timeout=5), [])
            self.assertEqual(stub.anfragen, [])


class UnerreichbarTest(unittest.TestCase):
    """Der wichtigste Fall: ein Abruf, der nicht durchkam, ist **kein** leeres
    Ergebnis. Er muss laut scheitern."""

    def _deps(self, ordner):
        fixtures.schreibe_requirements(ordner, ["django==2.2.0"])
        return collect(ordner)[0]

    def test_kein_server_wirft(self):
        with tempfile.TemporaryDirectory() as ordner:
            deps = self._deps(ordner)
        # Port 9 ist "discard" und nimmt nichts an.
        with self.assertRaises(OsvUnavailable):
            query_osv(deps, url="http://127.0.0.1:9/v1/querybatch", timeout=2)

    def test_serverfehler_wirft(self):
        with fixtures.OsvStub(status=500, koerper=b"{}") as stub, tempfile.TemporaryDirectory() as ordner:
            deps = self._deps(ordner)
            with self.assertRaises(OsvUnavailable):
                query_osv(deps, url=stub.url, timeout=5)

    def test_unpassende_antwort_wirft(self):
        # Zu wenige Ergebnisse: die Zuordnung waere verschoben, und Chinook
        # wuerde eine Schwachstelle dem falschen Paket zuschreiben.
        with fixtures.OsvStub(antwort={"results": []}) as stub, tempfile.TemporaryDirectory() as ordner:
            deps = self._deps(ordner)
            with self.assertRaises(OsvUnavailable):
                query_osv(deps, url=stub.url, timeout=5)

    def test_kaputte_antwort_wirft(self):
        with fixtures.OsvStub(koerper=b"kein json") as stub, tempfile.TemporaryDirectory() as ordner:
            deps = self._deps(ordner)
            with self.assertRaises(OsvUnavailable):
                query_osv(deps, url=stub.url, timeout=5)

    def test_die_kommandozeile_gibt_zwei_zurueck(self):
        import contextlib
        import io

        from chinook import cli

        with tempfile.TemporaryDirectory() as ordner:
            fixtures.schreibe_requirements(ordner, ["django==2.2.0"])
            puffer = io.StringIO()
            with contextlib.redirect_stdout(puffer), contextlib.redirect_stderr(puffer):
                code = cli.main(
                    [
                        "dependency-bot",
                        "--path",
                        ordner,
                        "--osv-url",
                        "http://127.0.0.1:9/v1/querybatch",
                        "--osv-timeout",
                        "2",
                    ]
                )
            self.assertEqual(code, 2, "ein misslungener Abruf darf nicht als bestanden gelten")
            self.assertIn("does not count as passing", puffer.getvalue())


class ZuordnungTest(unittest.TestCase):
    def test_der_befund_zeigt_auf_das_richtige_paket(self):
        with tempfile.TemporaryDirectory() as ordner:
            fixtures.schreibe_requirements(ordner, ["alpha==1.0", "beta==2.0", "gamma==3.0"])
            deps = collect(ordner)[0]
        treffer = to_findings(deps, {1: ["GHSA-nur-beta"]})
        self.assertEqual(len(treffer), 1)
        self.assertIn("beta", treffer[0].explanation)
        self.assertNotIn("alpha", treffer[0].explanation)
        self.assertEqual(treffer[0].line, 2)


if __name__ == "__main__":
    unittest.main()
