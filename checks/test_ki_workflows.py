"""Prueft die beiden Workflows, die ein Sprachmodell aufrufen.

Es gibt sie wegen eines Fehlers, der **plausibel ausgesehen und nie
funktioniert haette**.

Die erste Fassung stand auf `actions/ai-inference@v3` -- der neuesten Fassung,
also scheinbar der richtigen. Ab v3 ruft diese Action aber gar nicht mehr
GitHub Models auf: sie startet die Copilot-CLI, die auf dem Runner erst
installiert und mit einem **eigenen** Token angemeldet sein muss. Das Recht
`models: read` haette dort nichts mehr bewirkt. Der Workflow haette richtig
ausgesehen, und der erste Lauf waere umgefallen -- mit einer Meldung ueber die
Copilot-CLI, die niemanden auf die Versionsnummer gebracht haette.

Deshalb zwei Festlegungen, die hier festgehalten werden:

1. Wer `actions/ai-inference` benutzt, **muss** `models: read` deklarieren.
   Ohne das Recht kommt die Anfrage nicht durch.
2. Der Commit, auf den festgelegt ist, steht **hier** und ist damit nicht
   still zu aendern. Ein Sprung auf v3 ist kein Versionssprung, sondern ein
   Anbieterwechsel; er gehoert bewusst gemacht, mit dieser Datei vor Augen.

Keine Abhaengigkeit, kein YAML-Parser: zeilenweise, wie der Workflow-Bot es
haelt.
"""

from __future__ import annotations

import os
import re
import unittest

WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = os.path.join(WURZEL, ".github", "workflows")

# Die letzte Fassung von `actions/ai-inference`, die mit dem eingebauten
# `GITHUB_TOKEN` an `https://models.github.ai/inference` geht. Nachgelesen in
# der `action.yml` an genau diesem Commit, nicht aus der Erinnerung.
ERLAUBTER_COMMIT = "a7805884c80886efc241e94a5351df715968a0ad"  # v2.1.1

BENUTZT = re.compile(r"^\s*uses:\s*actions/ai-inference@(\S+)", re.MULTILINE)


def _workflows():
    for name in sorted(os.listdir(WORKFLOWS)):
        if name.endswith((".yml", ".yaml")):
            pfad = os.path.join(WORKFLOWS, name)
            with open(pfad, encoding="utf-8") as datei:
                yield name, datei.read()


def _mit_ki():
    for name, text in _workflows():
        treffer = BENUTZT.findall(text)
        if treffer:
            yield name, text, treffer


class KiWorkflows(unittest.TestCase):
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
                    f"Ab v3 ruft die Action die Copilot-CLI statt GitHub Models "
                    f"auf und braucht ein eigenes Token; `models: read` wirkt "
                    f"dann nicht mehr. Wer die Fassung wechselt, aendert hier "
                    f"bewusst mit.",
                )

    def test_models_read_ist_deklariert(self):
        for name, text, _treffer in _mit_ki():
            self.assertRegex(
                text,
                r"(?m)^\s*models:\s*read\s*(#.*)?$",
                f"{name} ruft actions/ai-inference auf, deklariert aber kein "
                f"`models: read`. In GitHub Actions wird kein Recht geerbt: "
                f"was nicht dasteht, ist `none`.",
            )

    def test_antwortlaenge_ist_gesetzt(self):
        """Der eingebaute Standard sind 200 Tokens -- das schneidet ab."""
        for name, text, _treffer in _mit_ki():
            self.assertIn(
                "max-completion-tokens",
                text,
                f"{name} setzt keine Antwortlaenge. Ohne sie antwortet die "
                f"Action mit 200 Tokens und schneidet mitten im Satz ab -- "
                f"eine Antwort, die aussieht wie eine.",
            )


if __name__ == "__main__":
    unittest.main()
