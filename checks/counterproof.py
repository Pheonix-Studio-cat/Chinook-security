"""Die Gegenprobe: prueft die Pruefungen.

Der teuerste Fehlertyp ist der, der wie Erfolg aussieht -- eine gruene Pruefung,
die nichts beweist. Dagegen hilft nur eins: den Bot absichtlich kaputt machen
und verlangen, dass die Pruefungen **rot** werden. Bleiben sie gruen, ist die
Pruefung wertlos, und dieses Skript sagt das laut.

Aufruf:  python3 -m checks.counterproof [--json datei]
Rueckgabe: 0, wenn jede Mutation gefangen wurde. Sonst 1.

Mit `--json` schreibt sie das Ergebnis maschinenlesbar mit -- das ist die
zweite Aufgabe des Aufsehers: nicht nur Befunde einordnen, sondern **die Bots
kontrollieren**. Die Website zeigt daraus, welche Pruefung gegengeprueft ist.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

WURZEL = Path(__file__).resolve().parent.parent
IGNORIEREN = shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".venv")


@dataclass(frozen=True)
class Mutation:
    """Ein absichtlicher Schaden und die Erwartung, dass er auffliegt."""

    name: str
    datei: str
    alt: str
    neu: str
    trifft: str


MUTATIONEN: tuple[Mutation, ...] = (
    Mutation(
        name="redaction-off",
        datei="chinook/findings.py",
        alt='    return f"{kind}, {len(text)} characters (value not shown)"',
        neu='    return f"{kind}: {text}"',
        trifft="the bot prints the value it found",
    ),
    Mutation(
        name="severity-check-removed",
        datei="chinook/findings.py",
        alt='        if self.severity not in SEVERITIES:',
        neu='        if False:',
        trifft="a finding may carry an invented severity",
    ),
    Mutation(
        name="threshold-never-fires",
        datei="chinook/findings.py",
        alt="    return any(severity_rank(f.severity) <= limit for f in findings)",
        neu="    return False",
        trifft="a critical finding still leaves the run green",
    ),
    Mutation(
        name="everything-is-a-placeholder",
        datei="chinook/secret_bot.py",
        alt='    """Ein Platzhalter ist kein Fund."""',
        neu='    """Ein Platzhalter ist kein Fund."""\n    return True',
        trifft="every medium-confidence find is thrown away",
    ),
    Mutation(
        name="first-rule-skipped",
        datei="chinook/secret_bot.py",
        alt="        for rule in RULES:",
        neu="        for rule in RULES[1:]:",
        trifft="a rule no longer runs",
    ),
    Mutation(
        name="history-check-off",
        datei="chinook/secret_bot.py",
        alt="def scan_history(root: str, max_commits: int = 500) -> list[Finding]:",
        neu="def scan_history(root: str, max_commits: int = 500) -> list[Finding]:\n    return []",
        trifft="a secret in the history stays undetected",
    ),
    Mutation(
        name="everything-counts-as-pinned",
        datei="chinook/workflow_bot.py",
        alt="    return bool(_SHA.match(ref))",
        neu="    return True",
        trifft="an action on a movable tag counts as pinned",
    ),
    Mutation(
        name="no-context-is-untrusted",
        datei="chinook/workflow_bot.py",
        alt="def untrusted_in(expression: str) -> str | None:",
        neu="def untrusted_in(expression: str) -> str | None:\n    return None",
        trifft="script injection is no longer detected",
    ),
    Mutation(
        name="missing-permissions-ignored",
        datei="chinook/workflow_bot.py",
        alt='    if "permissions" not in top_level_keys:',
        neu="    if False:",
        trifft="a workflow without permissions counts as clean",
    ),
    Mutation(
        name="pull-request-target-ignored",
        datei="chinook/workflow_bot.py",
        alt=r'    has_pr_target = any(re.search(r"\bpull_request_target\b", line) for line in lines)',
        neu="    has_pr_target = False",
        trifft="the workflow bot's most severe finding disappears",
    ),
    Mutation(
        name="exit-code-always-zero",
        datei="chinook/cli.py",
        alt=(
            "    if fmt.exceeds(results, args.fail_on):\n"
            "        print(\n"
            "            f\"\\nFailed: at least one finding reaches the threshold \""
        ),
        neu=(
            "    if False:\n"
            "        print(\n"
            "            f\"\\nFailed: at least one finding reaches the threshold \""
        ),
        trifft="the bot reports a find but leaves the run green",
    ),
    Mutation(
        name="osv-error-swallowed",
        datei="chinook/dependency_bot.py",
        alt='            raise OsvUnavailable(f"OSV nicht erreichbar: {type(fehler).__name__}: {fehler}") from fehler',
        neu="            continue",
        trifft="a failed query looks like a clean result",
    ),
    Mutation(
        name="osv-answer-unchecked",
        datei="chinook/dependency_bot.py",
        alt="        if not isinstance(ergebnisse, list) or len(ergebnisse) != len(teil):",
        neu="        if False:",
        trifft="a shifted answer attributes the vulnerability to the wrong package",
    ),
    Mutation(
        name="unpinned-version-counts-as-pinned",
        datei="chinook/dependency_bot.py",
        alt='        if operator in ("==", "===") and version:',
        neu="        if version:",
        trifft="a version range is queried as an exact version",
    ),
    Mutation(
        name="unproven-counts-as-passed",
        datei="chinook/cli.py",
        # Eindeutig verankert. Vorher stand hier nur `return UNBEWIESEN`,
        # und das kam schon damals dreimal in der Datei vor -- die Mutation
        # traf die erste Stelle, nicht die gemeinte. Gefangen wurde sie
        # trotzdem, aber sie mass etwas anderes, als ihr Name sagt.
        alt=(
            "            \"This run says nothing about whether vulnerabilities are present. \"\n"
            "            \"It therefore does not count as passing.\",\n"
            "            file=sys.stderr,\n"
            "        )\n"
            "        return UNBEWIESEN"
        ),
        neu=(
            "            \"This run says nothing about whether vulnerabilities are present. \"\n"
            "            \"It therefore does not count as passing.\",\n"
            "            file=sys.stderr,\n"
            "        )\n"
            "        return OK"
        ),
        trifft="a run without an answer reports success",
    ),
    Mutation(
        name="code-rule-skipped",
        datei="chinook/code_bot.py",
        alt="        for rule in RULES:",
        neu="        for rule in RULES[1:]:",
        trifft="a code rule no longer runs",
    ),
    Mutation(
        name="file-type-ignored",
        datei="chinook/code_bot.py",
        alt="            if suffix not in rule.suffixes:",
        neu="            if False:",
        trifft="Python rules fire in JavaScript and the other way round",
    ),
    Mutation(
        name="licence-text-not-recognised",
        datei="chinook/license_bot.py",
        alt='    """Grobe Familie eines Lizenztexts, oder None. Keine Rechtsaussage."""',
        neu='    """Grobe Familie eines Lizenztexts, oder None. Keine Rechtsaussage."""\n    return None',
        trifft="the disagreement between declaration and licence file disappears",
    ),
    Mutation(
        name="mismatch-ignored",
        datei="chinook/license_bot.py",
        alt="    if datei_familie and erklaerte_familie and datei_familie != erklaerte_familie:",
        neu="    if False:",
        trifft="declared licence and accompanying text may disagree",
    ),
    Mutation(
        name="dead-licence-link-ignored",
        datei="chinook/license_bot.py",
        alt="                if not os.path.isfile(os.path.join(wurzel, ziel)):",
        neu="                if False:",
        trifft="a licence reference pointing nowhere counts as fine",
    ),
    Mutation(
        name="overseer-loses-findings",
        datei="chinook/overseer.py",
        alt="    for befund in befunde:",
        neu="    for befund in bewertungen:",
        trifft="the model's answer decides which findings remain",
    ),
    Mutation(
        name="invented-fingerprint-accepted",
        datei="chinook/overseer.py",
        alt="        if fingerabdruck not in erlaubt or einschaetzung not in EINSCHAETZUNGEN:",
        neu="        if False:",
        trifft="the model may invent findings and make up ratings",
    ),
    Mutation(
        name="refusal-counts-as-result",
        datei="chinook/overseer.py",
        alt='    if antwort.get("stop_reason") == "refusal":',
        neu="    if False:",
        trifft="a refusal from the model looks like a rating",
    ),
    Mutation(
        name="reasoning-unfiltered",
        datei="chinook/overseer.py",
        alt='    text = _STEUERZEICHEN.sub(" ", text).strip()',
        neu="    text = text.strip()",
        trifft="control characters from the model answer reach the report",
    ),
    Mutation(
        name="require-has-no-effect",
        datei="chinook/cli.py",
        alt="    if not gelaufen and args.require:",
        neu="    if False:",
        trifft="--require demands a rating and accepts no answer",
    ),
    Mutation(
        name="rule-missing-from-page",
        datei="webseite/build.py",
        alt="    for regel in regeln:",
        neu="    for regel in regeln[1:]:",
        trifft="the website omits a rule the bot applies",
    ),
    Mutation(
        name="page-without-escaping",
        datei="webseite/build.py",
        alt="    return html.escape(str(text), quote=False)",
        neu="    return str(text)",
        trifft="foreign text reaches the HTML unfiltered",
    ),
    Mutation(
        name="counterproof-massaged",
        datei="webseite/build.py",
        alt='    gefangen = daten.get("gefangen", 0)',
        neu='    gefangen = daten.get("gesamt", 0)',
        trifft="the page reports every mutation as caught, escaped ones included",
    ),
    Mutation(
        name="package-block-not-recognised",
        datei="chinook/dependency_bot.py",
        alt='        if roh.strip() == "[[package]]":',
        neu="        if False:",
        trifft="poetry.lock and Cargo.lock are no longer read at all",
    ),
    Mutation(
        name="npm-name-includes-version",
        datei="chinook/dependency_bot.py",
        alt="    return spec[:trenner]",
        neu="    return spec",
        trifft="yarn and pnpm ask about a package name that does not exist",
    ),
    Mutation(
        name="pnpm-reads-whole-file",
        datei="chinook/dependency_bot.py",
        alt="        if not im_paketteil:",
        neu="        if False:",
        trifft="pnpm settings are mistaken for packages",
    ),    # --- Gegenproben-Bot: der Bot, der fremden Code bricht, wird selbst
    # gebrochen. Waere er es nicht, waere er der einzige hier, dem man auf
    # sein Wort glauben muesste.
    Mutation(
        name="mutation-report-leaks-source",
        datei="chinook/counterproof_bot.py",
        alt="            wandel=wandel or f\"{alt} -> {neu_text}\", neu=neu,",
        neu="            wandel=f\"{alt} -> {neu_text}\", neu=neu,",
        trifft="the mutation report carries the source it replaced, secrets included",
    ),
    Mutation(
        name="js-comments-get-mutated",
        datei="chinook/counterproof_bot.py",
        alt="        if in_blockkommentar:",
        neu="        if False:",
        trifft="a change inside a comment is reported as a gap in the tests",
    ),
    Mutation(
        name="js-strings-get-mutated",
        datei="chinook/counterproof_bot.py",
        alt="    raus = list(zeile)",
        neu="    return zeile",
        trifft="a change inside a string literal is reported as a gap in the tests",
    ),
    Mutation(
        name="red-baseline-accepted",
        datei="chinook/counterproof_bot.py",
        alt="    if not laeufer(testkommando, wurzel, zeitgrenze):",
        neu="    if False:",
        trifft="an already broken test suite is mutated, and every mutation counts as caught",
    ),
    Mutation(
        name="source-left-broken",
        datei="chinook/counterproof_bot.py",
        alt="                griff.write(vorlage)",
        neu="                pass",
        trifft="the bot leaves someone else's source code mutated on disk",
    ),
    Mutation(
        name="test-files-get-mutated",
        datei="chinook/counterproof_bot.py",
        alt="            if ist_testdatei(relativ):",
        neu="            if False:",
        trifft="the test suite is mutated against itself, which measures nothing",
    ),
    Mutation(
        name="security-priority-dropped",
        datei="chinook/counterproof_bot.py",
        # Zielt auf die Gruppierung, nicht auf die Sortierung. Der Vorrang
        # steht an zwei Stellen; die Sortierung allein zu mutieren aenderte
        # das Ergebnis nicht, weil die Gruppierung ihn weiter durchsetzte --
        # eine Mutation, die den Text aendert und das Verhalten nicht. Sie
        # kam durch, und das lag an ihr, nicht an der Pruefung.
        alt='        nach_datei.setdefault((not mutation.sicherheitsnah, mutation.pfad), []).append(mutation)',
        neu='        nach_datei.setdefault((mutation.pfad,), []).append(mutation)',
        trifft="the budget is spent away from security-relevant code",
    ),
    Mutation(
        name="one-file-eats-the-budget",
        datei="chinook/counterproof_bot.py",
        # Die erste Fassung hing nur Bedingungen an, die ohnehin wahr waren --
        # eine Mutation, die den Text aendert und das Verhalten nicht. Sie kam
        # durch, und das lag an ihr, nicht an der Pruefung.
        alt="        for schluessel in sorted(nach_datei):",
        neu="        for schluessel in sorted(nach_datei)[:1]:",
        trifft="a single large file uses up the whole budget and the rest goes unchecked",
    ),
    Mutation(
        name="timeout-counts-as-passing",
        datei="chinook/counterproof_bot.py",
        alt="    except subprocess.TimeoutExpired:\n        return False",
        neu="    except subprocess.TimeoutExpired:\n        return True",
        trifft="a mutation that hangs the test run is reported as an untested behaviour",
    ),
    Mutation(
        name="severity-heuristic-flattened",
        datei="chinook/counterproof_bot.py",
        alt='        severity="high" if nah else "low",',
        neu='        severity="low",',
        trifft="a surviving mutation in security-relevant code is rated as low",
    ),
    # --- Die Website darf nicht von der Quelle abweichen. Beide Zahlen hier
    # standen bis zum sechsten Bot von Hand da und konnten still veralten.
    Mutation(
        name="bot-count-written-by-hand",
        datei="webseite/build.py",
        alt='        (str(len(BOTS)), "bots"),',
        neu='        ("5", "bots"),',
        trifft="the page states a bot count that no longer matches the source",
    ),
    Mutation(
        name="bot-missing-from-page",
        datei="webseite/build.py",
        alt="BOTS = (\n    (\n        counterproof_bot,",
        neu="BOTS = (\n    (\n        secret_bot,",
        trifft="a whole bot disappears from the page without a check going red",
    ),
    # --- Die YAML-Pruefung. Ihre Vorgaengerin suchte nur nach Zeichenketten
    # und war gruen an einer Datei, die GitHub nicht laden konnte.
    Mutation(
        name="broken-yaml-block-accepted",
        datei="checks/test_yaml_bloecke.py",
        alt="            if not STRUKTURZEILE.match(zeile):\n                fehler.append((i + 1, zeile))",
        neu="            if False:\n                fehler.append((i + 1, zeile))",
        trifft="an action file GitHub cannot even load counts as fine",
    ),
    Mutation(
        name="yaml-check-sees-nothing",
        datei="checks/test_yaml_bloecke.py",
        alt='            if datei.endswith((".yml", ".yaml")):',
        neu='            if False:',
        trifft="the YAML check passes because it looked at no file at all",
    ),
)


def suite_laeuft(pfad: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "checks", "-t", ".", "-q"],
        cwd=pfad,
        capture_output=True,
        text=True,
    )


def kopie() -> tempfile.TemporaryDirectory:
    handle = tempfile.TemporaryDirectory()
    ziel = Path(handle.name) / "repo"
    shutil.copytree(WURZEL, ziel, ignore=IGNORIEREN)
    return handle


def _ziel(handle: tempfile.TemporaryDirectory) -> Path:
    return Path(handle.name) / "repo"


def grundlauf() -> tuple[bool, str]:
    """Ohne Schaden muss die Suite gruen sein -- sonst faengt sie nachher alles
    aus dem falschen Grund."""
    handle = kopie()
    try:
        ergebnis = suite_laeuft(_ziel(handle))
        return ergebnis.returncode == 0, ergebnis.stderr[-2000:]
    finally:
        handle.cleanup()


def pruefe(mutation: Mutation) -> tuple[bool, str]:
    """Wahr, wenn die Mutation gefangen wurde."""
    handle = kopie()
    try:
        ziel = _ziel(handle)
        datei = ziel / mutation.datei
        original = datei.read_text(encoding="utf-8")
        treffer = original.count(mutation.alt)
        if treffer == 0:
            return False, "der zu mutierende Text steht nicht in der Datei"
        if treffer > 1:
            # Mehrdeutig ist so schlimm wie gar nicht gefunden: `replace(.., 1)`
            # nimmt dann irgendeine Stelle, und die Mutation prueft etwas
            # anderes, als ihr Name sagt. Beim sechsten Bot ist genau das
            # passiert -- eine neue Funktion in `cli.py` hat zwei bestehende
            # Mutationen still auf sich gezogen.
            return False, f"der zu mutierende Text steht {treffer}-mal in der Datei"
        veraendert = original.replace(mutation.alt, mutation.neu, 1)
        # Ohne diese Zusicherung kann eine Mutation nichts aendern und die
        # Gegenprobe faellt trotzdem ein Urteil.
        if veraendert == original:
            return False, "die Mutation hat die Datei nicht veraendert"
        datei.write_text(veraendert, encoding="utf-8")
        ergebnis = suite_laeuft(ziel)
        if ergebnis.returncode == 0:
            return False, "die Pruefungen blieben gruen"
        return True, ""
    finally:
        handle.cleanup()


def _schreibe(pfad: str, nutzlast: dict) -> None:
    ziel = Path(pfad)
    if ziel.parent != Path(""):
        ziel.parent.mkdir(parents=True, exist_ok=True)
    ziel.write_text(json.dumps(nutzlast, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    zerleger = argparse.ArgumentParser(
        prog="checks.counterproof",
        description="Macht die Bots absichtlich kaputt und verlangt rote Pruefungen.",
    )
    zerleger.add_argument("--json", dest="json_out", default="", help="Ergebnis als JSON")
    args = zerleger.parse_args(argv)

    print("Gegenprobe: jede Mutation muss die Pruefungen rot machen.\n")
    ergebnis = {
        "schema_version": "1",
        "bot": "counterproof",
        "grundlauf": "",
        "gesamt": len(MUTATIONEN),
        "gefangen": 0,
        "mutationen": [],
    }

    gruen, meldung = grundlauf()
    ergebnis["grundlauf"] = "gruen" if gruen else "rot"
    if not gruen:
        print("Grundlauf ist bereits rot -- die Gegenprobe sagt so nichts aus.")
        print(meldung)
        if args.json_out:
            _schreibe(args.json_out, ergebnis)
        return 1
    print("Grundlauf gruen.\n")

    entkommen = []
    for mutation in MUTATIONEN:
        gefangen, warum = pruefe(mutation)
        zeichen = "gefangen " if gefangen else "ENTKOMMEN"
        print(f"  [{zeichen}] {mutation.name}: {mutation.trifft}")
        if not gefangen:
            print(f"              -> {warum}")
            entkommen.append(mutation)
        ergebnis["mutationen"].append(
            {
                "name": mutation.name,
                "datei": mutation.datei,
                "trifft": mutation.trifft,
                "gefangen": gefangen,
                "grund": "" if gefangen else warum,
            }
        )
    ergebnis["gefangen"] = ergebnis["gesamt"] - len(entkommen)
    if args.json_out:
        _schreibe(args.json_out, ergebnis)

    print()
    if entkommen:
        print(
            f"{len(entkommen)} von {len(MUTATIONEN)} Mutationen sind entkommen. "
            "Die zugehoerigen Pruefungen beweisen nichts."
        )
        return 1
    print(f"Alle {len(MUTATIONEN)} Mutationen gefangen.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
