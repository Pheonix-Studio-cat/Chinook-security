"""Prueft die beiden Workflows, die ein Sprachmodell aufrufen.

Es gibt sie wegen zweier Fehler an derselben Stelle, beide erst von einem
**echten Lauf** aufgedeckt.

**Erstens** stand die erste Fassung auf v2.1.1, weil die mit dem eingebauten
`GITHUB_TOKEN` an GitHub Models geht -- kein Secret, kein zweites Konto. Der
erste echte Lauf antwortete:

    410 GitHub Models is temporarily unavailable as part of a
    scheduled retirement brownout.

**Den Dienst gibt es nicht mehr.** Genau deshalb ist die Action ab v3 auf die
Copilot-CLI umgestiegen: das war kein Versionssprung, das war der Umzug. Ich
hatte die Schnittstelle sorgfaeltig gelesen und den Dienst nicht.

**Zweitens** genuegt der Copilot-CLI der eingebaute `GITHUB_TOKEN` nicht.
Ausprobiert, nicht vermutet; die CLI antwortete:

    Error: Authentication failed
    If using a Fine-Grained PAT, ensure it has the
    'Copilot Requests' permission enabled

Deshalb drei Festlegungen, die hier festgehalten werden:

1. Wer `actions/ai-inference` benutzt, muss ihr ein Token ueber
   `COPILOT_GITHUB_TOKEN` mitgeben. Der eingebaute Token genuegt nicht.
2. Die Copilot-CLI muss vorher installiert werden -- sie ist auf den Runnern
   nicht vorhanden.
3. Der Commit, auf den festgelegt ist, steht **hier** und ist damit nicht
   still zu aendern.

Keine Abhaengigkeit, kein YAML-Parser: zeilenweise, wie der Workflow-Bot es
haelt.
"""

from __future__ import annotations

import os
import re
import unittest

WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(WURZEL, ".github", "workflows")

# Die Fassung, die die Copilot-CLI aufruft. Nachgelesen in der `action.yml`
# an genau diesem Commit, nicht aus der Erinnerung -- und der Lauf dazu ist
# bis zur Authentifizierungsmeldung der CLI gekommen, hat die Action also
# tatsaechlich benutzt.
ERLAUBTER_COMMIT = "2c43c91ae16266ca159d311430343c67a5ffa222"  # v3

BENUTZT = re.compile(r"^\s*uses:\s*actions/ai-inference@(\S+)", re.MULTILINE)

# Seit dem Umbau ruft `frag-die-ki.yml` die CLI **direkt** auf, ohne die
# Action. Wuerde nur nach der Action gesucht, fiele diese Datei still aus der
# Pruefung -- und die uebrigen Tests waeren weiter gruen, ohne sie je
# angesehen zu haben. Genau die Sorte Luecke, die hier schon zweimal Erfolg
# vorgetaeuscht hat.
RUFT_CLI = re.compile(r"copilot\s+-p\b")


def _workflows():
    for name in sorted(os.listdir(WORKFLOWS)):
        if name.endswith((".yml", ".yaml")):
            pfad = os.path.join(WORKFLOWS, name)
            with open(pfad, encoding="utf-8") as datei:
                yield name, datei.read()


def _mit_ki():
    """Jeder Workflow, der irgendwie ein Sprachmodell befragt."""
    for name, text in _workflows():
        treffer = BENUTZT.findall(text)
        if treffer or RUFT_CLI.search(text):
            yield name, text, treffer


class KiWorkflows(unittest.TestCase):
    def test_beide_wege_sind_erfasst(self):
        """Es gibt zwei: die Action und der direkte Aufruf. Beide gehoeren dazu."""
        namen = {name for name, _t, _x in _mit_ki()}
        self.assertIn("frag-die-ki.yml", namen, "der Knopf faellt aus der Pruefung")
        self.assertIn("ki-wochenbericht.yml", namen, "der Wochenbericht faellt aus der Pruefung")

    def test_es_gibt_ueberhaupt_einen(self):
        """Ohne diesen Fall pruefen die anderen Tests die leere Menge.

        Eine Schleife ueber nichts ist gruen und sagt nichts. Genau diese
        Sorte Pruefung hat in diesem Projekt schon einmal Erfolg vorgetaeuscht.
        """
        self.assertTrue(list(_mit_ki()), "kein Workflow ruft actions/ai-inference auf")

    def test_festgelegt_auf_den_geprueften_commit(self):
        for name, _text, treffer in _mit_ki():
            for fassung in treffer:
                self.assertEqual(
                    fassung,
                    ERLAUBTER_COMMIT,
                    f"{name}: actions/ai-inference steht auf {fassung}. "
                    f"Vor v3 ruft die Action GitHub Models auf -- den Dienst "
                    f"gibt es nicht mehr, er antwortet mit HTTP 410. Wer die "
                    f"Fassung wechselt, aendert hier bewusst mit.",
                )

    def test_token_wird_mitgegeben(self):
        for name, text, _treffer in _mit_ki():
            self.assertIn(
                "COPILOT_GITHUB_TOKEN",
                text,
                f"{name} ruft actions/ai-inference auf, gibt ihr aber kein "
                f"Token ueber COPILOT_GITHUB_TOKEN mit. Der eingebaute "
                f"GITHUB_TOKEN genuegt der Copilot-CLI nicht -- sie antwortet "
                f"mit 'Authentication failed'.",
            )

    def test_fehlschlag_wird_nicht_verschluckt(self):
        """Wer die CLI selbst aufruft, muss ihre Meldung auch zeigen.

        `actions/ai-inference` meldet nur "exited with code 1" und
        verschluckt die stderr der CLI. Das hat hier zwei Laeufe gekostet.
        Wer den Weg daran vorbei nimmt, gibt die Meldung aus -- sonst ist
        nichts gewonnen.
        """
        for name, text, _treffer in _mit_ki():
            if not RUFT_CLI.search(text):
                continue
            self.assertIn(
                "cat fehler.txt",
                text,
                f"{name} ruft die CLI direkt auf, gibt ihre Fehlerausgabe "
                f"aber nirgends aus. Dann ist der direkte Aufruf sinnlos.",
            )
            self.assertIn(
                "set +e",
                text,
                f"{name} wertet einen Fehlschlag aus, hebt aber das `-e` "
                f"nicht auf. GitHub startet jeden run-Block mit `bash -e`; "
                f"der Block braeche vor der Ausgabe ab.",
            )

    def test_cli_wird_installiert(self):
        """Die Copilot-CLI ist auf den Runnern nicht vorinstalliert."""
        for name, text, _treffer in _mit_ki():
            self.assertIn(
                "npm install -g @github/copilot",
                text,
                f"{name} ruft actions/ai-inference auf, installiert die "
                f"Copilot-CLI aber nicht. Ohne sie faellt der Lauf um.",
            )

    def test_der_tote_dienst_kommt_nicht_zurueck(self):
        """GitHub Models antwortet mit HTTP 410. Kein Workflow darf darauf zeigen."""
        for name, text in _workflows():
            self.assertNotIn(
                "models.github.ai",
                text,
                f"{name} zeigt auf GitHub Models. Den Dienst gibt es nicht "
                f"mehr; er antwortet mit HTTP 410.",
            )


if __name__ == "__main__":
    unittest.main()
