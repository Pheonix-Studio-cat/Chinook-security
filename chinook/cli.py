"""Ein Einstiegspunkt fuer alle Bots: `python3 -m chinook.cli <bot> ...`

Die Ausgabe ist Englisch -- sie landet in fremden Action-Logs -- und sie
enthaelt nie einen gefundenen Wert.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import findings as fmt
from . import (
    code_bot,
    counterproof_bot,
    dependency_bot,
    license_bot,
    overseer,
    secret_bot,
    workflow_bot,
)

BOTS = {
    "secret-bot": secret_bot,
    "workflow-bot": workflow_bot,
    "dependency-bot": dependency_bot,
    "code-bot": code_bot,
    "license-bot": license_bot,
}

# Rueckgabewerte: 0 sauber, 1 Befunde ab der Schwelle, 2 der Lauf konnte nichts
# feststellen. Die 2 ist der Grund, warum es sie gibt -- ein Abruf, der nicht
# durchkam, ist kein leeres Ergebnis.
OK, BEFUNDE, UNBEWIESEN = 0, 1, 2

_SEVERITY_LABEL = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}


def _split(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chinook",
        description="Chinook Security -- security bots for GitHub repositories.",
    )
    parser.add_argument(
        "bot",
        choices=sorted([*BOTS, "overseer", "counterproof-bot"]),
        help="which bot to run (or `overseer` to triage findings)",
    )
    parser.add_argument("--path", default=".", help="root of the repository to check")
    parser.add_argument("--exclude", default="", help="paths to skip, comma-separated")
    parser.add_argument(
        "--history",
        action="store_true",
        help="also scan the git history (secret-bot only)",
    )
    parser.add_argument("--json", dest="json_out", default="", help="write the report as JSON to this file")
    parser.add_argument("--sarif", dest="sarif_out", default="", help="write the report as SARIF to this file")
    parser.add_argument(
        "--osv-url",
        default=dependency_bot.OSV_URL,
        help="OSV query URL (dependency-bot only; for tests)",
    )
    parser.add_argument(
        "--osv-timeout",
        type=int,
        default=dependency_bot.TIMEOUT,
        help="OSV query timeout in seconds (dependency-bot only)",
    )
    parser.add_argument(
        "--report",
        dest="reports",
        action="append",
        default=[],
        help="a finding report for the overseer to triage (repeatable)",
    )
    parser.add_argument(
        "--api-url",
        default=overseer.API_URL,
        help="Messages API URL (overseer only; for tests)",
    )
    parser.add_argument(
        "--model", default=overseer.MODEL, help="model for the overseer"
    )
    parser.add_argument(
        "--require",
        action="store_true",
        help="exit with 2 if the overseer could not run",
    )
    parser.add_argument(
        "--no-fallbacks",
        action="store_true",
        help="ask without server-side model fallback (overseer only)",
    )
    parser.add_argument(
        "--test-command",
        default="",
        help="the command that runs your tests (counterproof-bot only, required)",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=20,
        help="how many mutations to run (counterproof-bot only, default: 20)",
    )
    parser.add_argument(
        "--test-timeout",
        type=int,
        default=600,
        help="seconds one test run may take (counterproof-bot only)",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=(*fmt.SEVERITIES, "never"),
        help="severity at which the run fails (default: high)",
    )
    return parser


def _write(path: str, payload: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(fmt.dumps(payload))
        handle.write("\n")


def _aufseher(args) -> int:
    """Der Aufseher faellt kein Urteil -- er ordnet ein.

    Deshalb beendet er sich mit 0, auch wenn er nicht laufen konnte: die
    Befunde der Bots stehen unveraendert, und deren Rueckgabewerte haben das
    Urteil bereits gefaellt. Wer das anders haben will, nimmt `--require`.
    """
    if not args.reports:
        print("overseer: --report is missing (at least one findings report)", file=sys.stderr)
        return UNBEWIESEN

    ergebnis, gelaufen = overseer.run(
        args.reports,
        url=args.api_url,
        modell=args.model,
        fallbacks=not args.no_fallbacks,
    )
    if args.json_out:
        _write(args.json_out, ergebnis)

    stand = ergebnis["overseer"]
    print(f"overseer: {stand['status']}")
    if stand["reason"]:
        print(f"  {stand['reason']}")
    if gelaufen:
        print(f"  {stand['triaged']} of {ergebnis['summary']['total']} finding(s) triaged")
        print(f"  model: {stand['model']}")
        for befund in ergebnis["findings"]:
            triage = befund.get("triage")
            if triage:
                ort = befund.get("location", {})
                print(
                    f"  [{triage['rating']}] {ort.get('path')}:{ort.get('line')} "
                    f"{befund.get('rule')}"
                )
    if not gelaufen and args.require:
        print(
            "\nFailed: --require demands a triage, and there is none.",
            file=sys.stderr,
        )
        return UNBEWIESEN
    return OK


def _gegenprobe(args) -> int:
    """Der Gegenproben-Bot hat eine andere Form als die uebrigen.

    Er meldet nicht nur, was er fand, sondern auch **wie viel er gemessen
    hat**. Ein gruener Lauf ohne diese Zahlen waere genau die Sorte Erfolg,
    gegen die dieser Bot gebaut ist: er koennte bedeuten, dass nichts
    entkommen ist -- oder dass nichts geprueft wurde.
    """
    try:
        results, coverage = counterproof_bot.gegenprobe(
            args.path,
            args.test_command,
            budget=args.budget,
            zeitgrenze=args.test_timeout,
            ausschluss=tuple(_split(args.exclude)),
        )
    except counterproof_bot.Unprovable as fehler:
        print(
            f"counterproof-bot: nothing could be proved -- {fehler}\n"
            "This run says nothing about whether your tests would catch a change. "
            "It therefore does not count as passing.",
            file=sys.stderr,
        )
        return UNBEWIESEN

    report = fmt.report(
        "counterproof-bot",
        results,
        target={"path": os.path.abspath(args.path), **coverage},
    )
    if args.json_out:
        _write(args.json_out, report)
    if args.sarif_out:
        _write(args.sarif_out, fmt.to_sarif("counterproof-bot", results))

    print(
        f"counterproof-bot: {coverage['mutations_caught']} of "
        f"{coverage['mutations_run']} mutations caught"
    )
    print(
        f"  {coverage['source_files']} source file(s), "
        f"{coverage['mutations_possible']} mutation(s) possible"
    )
    for finding in fmt.sort_findings(results):
        print(
            f"  [{_SEVERITY_LABEL[finding.severity]}] {finding.path}:{finding.line} "
            f"survived -- {finding.evidence}"
        )

    if fmt.exceeds(results, args.fail_on):
        print(
            f"\nFailed: at least one surviving mutation reaches the threshold "
            f"'{_SEVERITY_LABEL.get(args.fail_on, args.fail_on)}'.",
            file=sys.stderr,
        )
        return BEFUNDE
    return OK


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.bot == "overseer":
        return _aufseher(args)
    if args.bot == "counterproof-bot":
        return _gegenprobe(args)
    module = BOTS[args.bot]
    excludes = _split(args.exclude)

    try:
        if args.bot == "secret-bot":
            results = module.run(args.path, excludes, history=args.history)
        elif args.bot == "dependency-bot":
            results = module.run(
                args.path, excludes, url=args.osv_url, timeout=args.osv_timeout
            )
        else:
            results = module.run(args.path, excludes)
    except dependency_bot.OsvUnavailable as fehler:
        print(
            f"{args.bot}: the query failed -- {fehler}\n"
            "This run says nothing about whether vulnerabilities are present. "
            "It therefore does not count as passing.",
            file=sys.stderr,
        )
        return UNBEWIESEN

    report = fmt.report(args.bot, results, target={"path": os.path.abspath(args.path)})
    if args.json_out:
        _write(args.json_out, report)
    if args.sarif_out:
        _write(args.sarif_out, fmt.to_sarif(args.bot, results))

    print(f"{args.bot}: {report['summary']['total']} finding(s)")
    for level in fmt.SEVERITIES:
        count = report["summary"]["by_severity"][level]
        if count:
            print(f"  {_SEVERITY_LABEL[level]}: {count}")
    for finding in fmt.sort_findings(results):
        print(
            f"  [{_SEVERITY_LABEL[finding.severity]}] {finding.path}:{finding.line} "
            f"{finding.rule} -- {finding.title}"
        )

    if fmt.exceeds(results, args.fail_on):
        print(
            f"\nFailed: at least one finding reaches the threshold "
            f"'{_SEVERITY_LABEL.get(args.fail_on, args.fail_on)}'.",
            file=sys.stderr,
        )
        return BEFUNDE
    return OK


if __name__ == "__main__":
    raise SystemExit(main())
