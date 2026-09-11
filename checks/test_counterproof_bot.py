"""Pruefungen fuer den Gegenproben-Bot.

Die wichtigste Sorte Pruefung hier ist die gegen den **falschen Alarm**: eine
Mutation in einem Kommentar oder in einer Zeichenkette aendert nichts am
Verhalten, bleibt darum gruen -- und wuerde als "entkommen" gemeldet. Das
waere ein Befund ueber nichts, und ein Bot, der so etwas meldet, wird
abgeschaltet.

Die zweite Sorte ist die gegen den **stillen Erfolg**: ein Lauf, der aus
irgendeinem Grund nichts messen konnte, darf nicht wie ein sauberer Lauf
aussehen.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from chinook import counterproof_bot as cb


class Textmutationen(unittest.TestCase):
    """Was der Bot in Quelltext findet -- und was er in Ruhe laesst."""

    def test_vergleich_wird_gedreht(self):
        mutationen = cb.python_mutationen("a.py", "def f(x):\n    return x == 1\n")
        gedreht = [m for m in mutationen if m.operator == "comparison-flipped"]
        self.assertEqual(len(gedreht), 1)
        self.assertEqual(gedreht[0].wandel, "== -> !=")
        self.assertIn("x != 1", gedreht[0].neu)

    def test_und_wird_zu_oder(self):
        mutationen = cb.python_mutationen("a.py", "def f(a, b):\n    return a and b\n")
        treffer = [m for m in mutationen if m.operator == "boolean-operator-swapped"]
        self.assertEqual(len(treffer), 1)
        self.assertIn("a or b", treffer[0].neu)

    def test_return_wird_auf_true_genagelt(self):
        mutationen = cb.python_mutationen("a.py", "def darf():\n    return False\n")
        treffer = [m for m in mutationen if m.operator == "return-forced-true"]
        self.assertEqual(len(treffer), 1)
        self.assertIn("return True", treffer[0].neu)

    def test_return_true_wird_nicht_mutiert(self):
        """Eine Mutation, die nichts aendert, misst nichts."""
        mutationen = cb.python_mutationen("a.py", "def f():\n    return True\n")
        self.assertEqual([m for m in mutationen if m.operator == "return-forced-true"], [])

    def test_jede_mutation_aendert_wirklich_etwas(self):
        """Die Regel der eigenen Gegenprobe: `mutation != original`."""
        quelle = (
            "def pruefe(rolle, wert):\n"
            "    if rolle == 'admin' and not wert:\n"
            "        return False\n"
            "    return wert != 0\n"
        )
        mutationen = cb.python_mutationen("a.py", quelle)
        self.assertTrue(mutationen)
        for mutation in mutationen:
            self.assertNotEqual(mutation.neu, quelle, mutation.name)

    def test_kaputtes_python_ist_kein_befund(self):
        """Ein Syntaxfehler gehoert dem Code-Bot, nicht diesem hier."""
        self.assertEqual(cb.python_mutationen("a.py", "def f(:\n"), [])


class KeinFalscherAlarm(unittest.TestCase):
    """Nichts mutieren, was das Verhalten gar nicht bestimmt."""

    def test_js_kommentar_wird_ausgelassen(self):
        quelle = "// true && x === y\nconst a = 1;\n"
        self.assertEqual(cb.js_mutationen("a.js", quelle), [])

    def test_js_blockkommentar_wird_ausgelassen(self):
        quelle = "/*\n true && x === y\n*/\nconst a = 1;\n"
        self.assertEqual(cb.js_mutationen("a.js", quelle), [])

    def test_js_zeichenkette_wird_ausgelassen(self):
        quelle = 'const s = "a && b === c true";\n'
        self.assertEqual(cb.js_mutationen("a.js", quelle), [])

    def test_js_echter_code_wird_gefunden(self):
        """Die Gegenrichtung -- sonst bewiese der Test oben nur Blindheit."""
        quelle = 'const s = "&&";\nif (a && b) { }\n'
        mutationen = cb.js_mutationen("a.js", quelle)
        self.assertEqual([m.zeile for m in mutationen], [2])

    def test_dreifachgleich_wird_nicht_als_doppelgleich_gelesen(self):
        mutationen = cb.js_mutationen("a.js", "if (a === b) { }\n")
        self.assertEqual([m.wandel for m in mutationen], ["=== -> !=="])

    def test_pfeilfunktion_ist_kein_vergleich(self):
        self.assertEqual(cb.js_mutationen("a.js", "const f = (x) => x;\n"), [])


class Auswahl(unittest.TestCase):
    """Bestimmt, nicht zufaellig -- sonst misst jeder Lauf etwas anderes."""

    def _mutation(self, pfad, zeile, nah):
        return cb.Mutation(pfad=pfad, zeile=zeile, operator="x", wandel="a -> b",
                           neu="x", sicherheitsnah=nah)

    def test_gleiche_eingabe_gleiche_auswahl(self):
        alle = [self._mutation(f"d{i}.py", i, i % 3 == 0) for i in range(1, 40)]
        self.assertEqual(
            [m.name for m in cb.waehle(alle, 7)],
            [m.name for m in cb.waehle(list(reversed(alle)), 7)],
        )

    def test_sicherheitsnahes_kommt_zuerst(self):
        """Die Namen sind mit Absicht so gewaehlt.

        Die erste Fassung verglich `egal.py` mit `auth.py` -- und `auth.py`
        kommt auch **alphabetisch** zuerst. Die Pruefung war gruen, egal ob der
        Sicherheitsvorrang wirkte oder nicht. Die Gegenprobe hat sie gefangen
        (`security-priority-dropped` entkam). Jetzt sortiert der harmlose Pfad
        vor dem sicherheitsnahen, also kann nur der Vorrang das Ergebnis
        erklaeren.
        """
        alle = [self._mutation("aaa_harmlos.py", 1, False),
                self._mutation("zzz_auth.py", 9, True)]
        self.assertEqual(cb.waehle(alle, 1)[0].pfad, "zzz_auth.py")

    def test_budget_wird_eingehalten(self):
        alle = [self._mutation("a.py", i, False) for i in range(1, 50)]
        self.assertEqual(len(cb.waehle(alle, 5)), 5)

    def test_eine_grosse_datei_frisst_nicht_das_ganze_budget(self):
        """Sonst bleibt der Rest des Repos ungeprueft, ohne dass es auffaellt."""
        alle = [self._mutation("gross.py", i, False) for i in range(1, 30)]
        alle += [self._mutation("klein.py", 1, False)]
        self.assertIn("klein.py", {m.pfad for m in cb.waehle(alle, 4)})


class Sicherheitsnaehe(unittest.TestCase):
    def test_dateiname_zaehlt(self):
        mutationen = cb.python_mutationen("src/auth.py", "def f(x):\n    return x == 1\n")
        self.assertTrue(all(m.sicherheitsnah for m in mutationen))

    def test_funktionsname_zaehlt(self):
        mutationen = cb.python_mutationen("a.py", "def validate_token(x):\n    return x == 1\n")
        self.assertTrue(all(m.sicherheitsnah for m in mutationen))

    def test_harmloses_bleibt_harmlos(self):
        mutationen = cb.python_mutationen("a.py", "def formatiere(x):\n    return x == 1\n")
        self.assertFalse(any(m.sicherheitsnah for m in mutationen))

    def test_schweregrad_folgt_der_naehe(self):
        nah = cb.Mutation(pfad="auth.py", zeile=1, operator="x", wandel="a -> b", sicherheitsnah=True)
        fern = cb.Mutation(pfad="hilfe.py", zeile=1, operator="x", wandel="a -> b", sicherheitsnah=False)
        self.assertEqual(cb._befund(nah).severity, "high")
        self.assertEqual(cb._befund(fern).severity, "low")


class BefundVerraetNichts(unittest.TestCase):
    """Dieselbe Regel wie beim Secret-Bot: nie den gefundenen Wert."""

    def test_quellzeile_steht_nicht_im_befund(self):
        quelle = 'def pruefe(t):\n    return t == "geheimes-losungswort"\n'
        mutation = cb.python_mutationen("auth.py", quelle)[0]
        befund = cb._befund(mutation)
        alles = " ".join([
            befund.title, befund.explanation, befund.remediation,
            befund.evidence, str(befund.to_dict()),
        ])
        self.assertNotIn("geheimes-losungswort", alles)

    def test_ort_und_operator_stehen_drin(self):
        """Ohne sie waere der Befund nicht zu gebrauchen."""
        mutationen = cb.python_mutationen("auth.py", "def f(x):\n    return x == 1\n")
        mutation = next(m for m in mutationen if m.operator == "comparison-flipped")
        befund = cb._befund(mutation)
        self.assertEqual(befund.path, "auth.py")
        self.assertEqual(befund.line, 2)
        self.assertIn("comparison-flipped", befund.evidence)

    def test_kein_operator_traegt_quelltext_nach_aussen(self):
        """Die allgemeine Fassung, nicht nur der eine bekannte Fall.

        Diese Pruefung hat beim ersten Lauf einen echten Fehler gefangen:
        `return-forced-true` schrieb den urspruenglichen Rueckgabeausdruck in
        den Bericht -- also fremden Quelltext, in dem ein Geheimnis stehen
        kann. Sie steht hier als Schranke fuer **jeden** kuenftigen Operator.
        """
        marker = "GEHEIMNIS-DAS-NICHT-AUSTRETEN-DARF"
        quelle = (
            f'def pruefe_token(t, rolle):\n'
            f'    if not t == "{marker}" and rolle == "{marker}":\n'
            f'        return "{marker}"\n'
            f'    return t != "{marker}"\n'
        )
        mutationen = cb.python_mutationen("auth.py", quelle)
        self.assertTrue(mutationen, "ohne Mutationen bewiese diese Pruefung nichts")
        for mutation in mutationen:
            befund = cb._befund(mutation)
            self.assertNotIn(marker, str(befund.to_dict()), mutation.name)

        js = f'const ok = tok === "{marker}" && rolle === "{marker}";\n'
        js_mutationen = cb.js_mutationen("auth.js", js)
        self.assertTrue(js_mutationen)
        for mutation in js_mutationen:
            befund = cb._befund(mutation)
            self.assertNotIn(marker, str(befund.to_dict()), mutation.name)


class Testdateien(unittest.TestCase):
    def test_werden_erkannt(self):
        for pfad in ("tests/test_a.py", "src/a.test.js", "__tests__/b.js",
                     "spec/c.js", "a_test.py", "src/tools/jwt.test.ts"):
            self.assertTrue(cb.ist_testdatei(pfad), pfad)

    def test_normaler_code_nicht(self):
        for pfad in ("src/a.py", "lib/contest.js", "src/latest.ts", "protest/a.py"):
            self.assertFalse(cb.ist_testdatei(pfad), pfad)

    def test_finde_quellen_laesst_testdateien_wirklich_aus(self):
        """Die Erkennung zu pruefen genuegt nicht -- sie muss auch benutzt werden.

        Genau diese Luecke hat die Gegenprobe gefunden: `ist_testdatei` war
        geprueft, der Aufruf in `finde_quellen` nicht. Die Mutation
        `test-files-get-mutated` kam darum durch.
        """
        with tempfile.TemporaryDirectory() as ordner:
            os.makedirs(os.path.join(ordner, "tests"))
            for relativ in ("quelle.py", "tests/test_quelle.py", "a.test.js"):
                voll = os.path.join(ordner, relativ)
                with open(voll, "w", encoding="utf-8") as griff:
                    griff.write("x = 1\n")
            self.assertEqual(cb.finde_quellen(ordner), ["quelle.py"])


class _Laeufer:
    """Ein Testkommando, das nicht wirklich laeuft.

    Der Bot wird hier gegen sein eigenes Verhalten geprueft, nicht gegen die
    Geschwindigkeit einer echten Pruefsuite.
    """

    def __init__(self, vorlage_gruen=True, ueberlebende=()):
        self.vorlage_gruen = vorlage_gruen
        self.ueberlebende = ueberlebende
        self.aufrufe = 0

    def __call__(self, kommando, wurzel, zeitgrenze):
        self.aufrufe += 1
        if self.aufrufe == 1:
            return self.vorlage_gruen
        return (self.aufrufe - 2) in self.ueberlebende


class Lauf(unittest.TestCase):
    def setUp(self):
        self.ordner = tempfile.mkdtemp()
        self.quelle = "def darf(rolle):\n    return rolle == 'admin'\n"
        with open(os.path.join(self.ordner, "auth.py"), "w", encoding="utf-8") as griff:
            griff.write(self.quelle)

    def _inhalt(self):
        with open(os.path.join(self.ordner, "auth.py"), encoding="utf-8") as griff:
            return griff.read()

    def test_ohne_testkommando_kein_ergebnis(self):
        with self.assertRaises(cb.Unprovable):
            cb.gegenprobe(self.ordner, "", laeufer=_Laeufer())

    def test_rote_vorlage_kein_ergebnis(self):
        """Sonst ist "gefangen" nicht von "war schon kaputt" zu unterscheiden."""
        with self.assertRaises(cb.Unprovable):
            cb.gegenprobe(self.ordner, "true", laeufer=_Laeufer(vorlage_gruen=False))

    def test_ohne_quellen_kein_ergebnis(self):
        leer = tempfile.mkdtemp()
        with self.assertRaises(cb.Unprovable):
            cb.gegenprobe(leer, "true", laeufer=_Laeufer())

    def test_gefangene_mutation_ist_kein_befund(self):
        befunde, deckung = cb.gegenprobe(self.ordner, "true", laeufer=_Laeufer())
        self.assertEqual(befunde, [])
        self.assertEqual(deckung["mutations_survived"], 0)
        self.assertGreater(deckung["mutations_caught"], 0)

    def test_entkommene_mutation_wird_gemeldet(self):
        befunde, deckung = cb.gegenprobe(
            self.ordner, "true", laeufer=_Laeufer(ueberlebende=(0,))
        )
        self.assertEqual(len(befunde), 1)
        self.assertEqual(deckung["mutations_survived"], 1)

    def test_datei_wird_immer_zurueckgesetzt(self):
        cb.gegenprobe(self.ordner, "true", laeufer=_Laeufer(ueberlebende=(0, 1)))
        self.assertEqual(self._inhalt(), self.quelle)

    def test_datei_wird_auch_nach_einem_abbruch_zurueckgesetzt(self):
        """Ein Bot, der fremden Quelltext kaputt zurueecklaesst, ist unbrauchbar."""
        class Knallt(_Laeufer):
            def __call__(self, kommando, wurzel, zeitgrenze):
                self.aufrufe += 1
                if self.aufrufe == 1:
                    return True
                raise RuntimeError("mitten im Lauf abgebrochen")

        with self.assertRaises(RuntimeError):
            cb.gegenprobe(self.ordner, "true", laeufer=Knallt())
        self.assertEqual(self._inhalt(), self.quelle)

    def test_deckung_wird_berichtet(self):
        """Ein gruener Lauf ohne diese Zahlen koennte auch heissen: nichts geprueft."""
        _, deckung = cb.gegenprobe(self.ordner, "pytest", laeufer=_Laeufer())
        for schluessel in ("test_command", "source_files", "mutations_possible",
                           "mutations_run", "mutations_caught", "mutations_survived"):
            self.assertIn(schluessel, deckung)
        self.assertEqual(deckung["test_command"], "pytest")

    def test_budget_begrenzt_die_laeufe(self):
        laeufer = _Laeufer()
        cb.gegenprobe(self.ordner, "true", budget=1, laeufer=laeufer)
        self.assertEqual(laeufer.aufrufe, 2)  # Vorlage plus eine Mutation


class Zeitgrenze(unittest.TestCase):
    def test_ueberschreitung_gilt_als_gefangen(self):
        """Eine Mutation, die den Lauf haengen laesst, faellt jemandem auf."""
        self.assertFalse(cb.laufe("sleep 5", ".", zeitgrenze=1))

    def test_sauberer_lauf_ist_sauber(self):
        self.assertTrue(cb.laufe("true", ".", zeitgrenze=30))

    def test_roter_lauf_ist_rot(self):
        self.assertFalse(cb.laufe("false", ".", zeitgrenze=30))


class Regeltabelle(unittest.TestCase):
    def test_regeln_sind_da(self):
        regeln = cb.regeln()
        self.assertTrue(regeln)
        for regel in regeln:
            for schluessel in ("name", "titel", "schwere", "was"):
                self.assertIn(schluessel, regel)


if __name__ == "__main__":
    unittest.main()
