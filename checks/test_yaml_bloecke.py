"""Prueft, dass kein Block-Skalar in einer YAML-Datei still abbricht.

Diese Datei gibt es wegen eines Fehlers, der es bis in vier fremde Repos
geschafft hat.

In `actions/counterproof/action.yml` stand ein mehrzeiliges Python-Skript
innerhalb eines `run: |`-Blocks -- und seine Zeilen begannen auf **Spalte 0**.
YAML beendet einen Block-Skalar bei der ersten Zeile, die nicht tiefer
eingerueckt ist als der Schluessel. Aus `import json, sys` wurde damit ein
Schluessel auf oberster Ebene, und GitHub konnte die Datei nicht laden:

    (Line: 108, Col: 1) While scanning a simple key, could not find
    expected ':'
    Failed to load .../actions/counterproof/action.yml

**Meine Pruefung davor war wertlos.** Sie suchte nach Zeichenketten
(`"name:" in text`, `"run:" in text`) und fand sie alle -- in einer Datei, die
GitHub nicht einmal einlesen konnte. Gruen, und ohne jede Aussage.

Einen YAML-Parser gibt es in der Standardbibliothek nicht, und eine
Abhaengigkeit kommt hier nicht in Frage. Also wird nicht das ganze Format
geprueft, sondern **genau diese Fehlerklasse** -- zeilenweise, wie der
Workflow-Bot es mit Workflows haelt. Das ist weniger, als ein Parser koennte,
und deutlich mehr als nichts.

Kommentarzeilen werden uebergangen: sie duerfen in YAML auf jeder Einrueckung
stehen, und sie im ersten Anlauf zu werten hat zwei falsche Alarme in
`selfcheck.yml` erzeugt.
"""

from __future__ import annotations

import os
import re
import unittest

WURZEL = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# `schluessel: |` oder `schluessel: >-` und Verwandte. Danach beginnt ein
# Block-Skalar, dessen Inhalt tiefer eingerueckt sein muss als der Schluessel.
BLOCKSTART = re.compile(r"^(?P<einzug>\s*)(?:-\s+)?[\w.\"'-]+\s*:\s*[|>][-+]?\d*\s*(?:#.*)?$")

# Wie eine Zeile aussieht, die YAML als Struktur liest: ein Schluessel oder ein
# Listeneintrag. Eine Zeile, die den Block verlaesst und **nicht** so aussieht,
# ist der Fehler, um den es hier geht.
STRUKTURZEILE = re.compile(r"^\s*(?:-(?:\s|$)|[\w.\"'-]+\s*:(?:\s|$)|\.\.\.$|---$)")


def yaml_dateien(wurzel: str) -> list[str]:
    gefunden = []
    for ordner, unterordner, dateien in os.walk(wurzel):
        unterordner[:] = [u for u in unterordner if u not in {".git", "__pycache__", "node_modules"}]
        for datei in dateien:
            if datei.endswith((".yml", ".yaml")):
                gefunden.append(os.path.join(ordner, datei))
    return sorted(gefunden)


def abgebrochene_bloecke(text: str) -> list[tuple[int, str]]:
    """Zeilen, die einen Block-Skalar verlassen, ohne Struktur zu sein.

    Gibt (Zeilennummer, Zeile) zurueck. Leer heisst: kein Block bricht still ab.
    """
    zeilen = text.split("\n")
    fehler: list[tuple[int, str]] = []
    i = 0
    while i < len(zeilen):
        treffer = BLOCKSTART.match(zeilen[i])
        if not treffer:
            i += 1
            continue

        schluessel_einzug = len(treffer.group("einzug"))
        i += 1
        block_einzug = None

        while i < len(zeilen):
            zeile = zeilen[i]
            if not zeile.strip() or zeile.lstrip().startswith("#"):
                # Kommentare stehen in YAML auf jeder Einrueckung und sind nie
                # dieser Fehler. Sie werden uebergangen, nicht gewertet.
                i += 1
                continue
            einzug = len(zeile) - len(zeile.lstrip())

            if block_einzug is None:
                if einzug <= schluessel_einzug:
                    # Der Block ist leer -- zulaessig, und nicht dieser Fehler.
                    break
                block_einzug = einzug
                i += 1
                continue

            if einzug >= block_einzug:
                i += 1
                continue

            # Der Block endet hier. Das ist nur in Ordnung, wenn die Zeile
            # wirklich wieder Struktur ist.
            if not STRUKTURZEILE.match(zeile):
                fehler.append((i + 1, zeile))
            break
    return fehler


class KaputteBloecke(unittest.TestCase):
    """Die Gegenrichtung zuerst: faengt die Pruefung den bekannten Fall?"""

    def test_der_fehler_von_damals_wird_gefangen(self):
        kaputt = (
            "runs:\n"
            "  steps:\n"
            "    - run: |\n"
            "        echo hallo\n"
            "        werte=$(python3 -c '\n"
            "import json, sys\n"
            "print(1)\n"
            "' datei)\n"
            "        echo fertig\n"
        )
        fehler = abgebrochene_bloecke(kaputt)
        self.assertTrue(fehler, "der bekannte Fehler muss auffallen")
        self.assertEqual(fehler[0][0], 6)

    def test_ein_gesunder_block_faellt_nicht_auf(self):
        gesund = (
            "runs:\n"
            "  steps:\n"
            "    - run: |\n"
            "        echo hallo\n"
            "        echo fertig\n"
            "      shell: bash\n"
        )
        self.assertEqual(abgebrochene_bloecke(gesund), [])

    def test_leerzeilen_beenden_keinen_block(self):
        mit_leerzeile = (
            "runs:\n"
            "  steps:\n"
            "    - run: |\n"
            "        echo eins\n"
            "\n"
            "        echo zwei\n"
            "      shell: bash\n"
        )
        self.assertEqual(abgebrochene_bloecke(mit_leerzeile), [])

    def test_ein_kommentar_danach_ist_struktur_genug(self):
        """Tiefer eingerueckte Kommentare und Listen sind kein Abbruch."""
        text = (
            "steps:\n"
            "  - run: |\n"
            "      echo eins\n"
            "  - name: zwei\n"
        )
        self.assertEqual(abgebrochene_bloecke(text), [])

    def test_gefalteter_block_zaehlt_auch(self):
        kaputt = (
            "description: >-\n"
            "  Erster Satz.\n"
            "kaputt hier ohne Doppelpunkt\n"
        )
        self.assertTrue(abgebrochene_bloecke(kaputt))


class EigenesRepo(unittest.TestCase):
    def test_keine_yaml_datei_bricht_still_ab(self):
        """Jede `.yml` im Repo -- Workflows und die sechs Actions.

        Der Workflow-Bot prueft Workflows auf Sicherheit. Diese Pruefung
        prueft etwas anderes: dass GitHub die Datei ueberhaupt lesen kann.
        """
        for pfad in yaml_dateien(WURZEL):
            with open(pfad, encoding="utf-8") as griff:
                text = griff.read()
            with self.subTest(datei=os.path.relpath(pfad, WURZEL)):
                self.assertEqual(
                    abgebrochene_bloecke(text), [],
                    f"{os.path.relpath(pfad, WURZEL)}: ein Block-Skalar bricht still ab",
                )

    def test_es_gibt_ueberhaupt_yaml_zu_pruefen(self):
        """Sonst waere die Pruefung oben gruen, weil sie nichts angesehen hat."""
        self.assertGreaterEqual(len(yaml_dateien(WURZEL)), 8)


if __name__ == "__main__":
    unittest.main()
