"""Ein Einstiegspunkt fuer alle Bots: `python3 -m chinook.cli <bot> ...`

Die Ausgabe ist Deutsch und enthaelt nie einen gefundenen Wert.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import findings as fmt
from . import code_bot, dependency_bot, license_bot, overseer, secret_bot, workflow_bot

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
        description="Chinook -- Sicherheits-Bots fuer GitHub-Repos.",
    )
    parser.add_argument(
        "bot",
        choices=sorted([*BOTS, "overseer"]),
        help="welcher Bot laufen soll (oder `overseer` zum Einordnen)",
    )
    parser.add_argument("--path", default=".", help="Wurzel des zu pruefenden Repos")
    parser.add_argument("--exclude", default="", help="Pfade, kommagetrennt")
    parser.add_argument(
        "--history",
        action="store_true",
        help="zusaetzlich die Git-History pruefen (nur secret-bot)",
    )
    parser.add_argument("--json", dest="json_out", default="", help="Bericht als JSON")
    parser.add_argument("--sarif", dest="sarif_out", default="", help="Bericht als SARIF")
    parser.add_argument(
        "--osv-url",
        default=dependency_bot.OSV_URL,
        help="Adresse der OSV-Abfrage (nur dependency-bot; fuer Pruefungen)",
    )
    parser.add_argument(
        "--osv-timeout",
        type=int,
        default=dependency_bot.TIMEOUT,
        help="Zeitgrenze der OSV-Abfrage in Sekunden (nur dependency-bot)",
    )
    parser.add_argument(
        "--report",
        dest="reports",
        action="append",
        default=[],
        help="Befundbericht, den der Aufseher einordnen soll (mehrfach moeglich)",
    )
    parser.add_argument(
        "--api-url",
        default=overseer.API_URL,
        help="Adresse der Messages-API (nur overseer; fuer Pruefungen)",
    )
    parser.add_argument(
        "--model", default=overseer.MODEL, help="Modell fuer den Aufseher"
    )
    parser.add_argument(
        "--require",
        action="store_true",
        help="den Lauf mit 2 beenden, wenn der Aufseher nicht laufen konnte",
    )
    parser.add_argument(
        "--no-fallbacks",
        action="store_true",
        help="ohne serverseitigen Modell-Rueckfall anfragen (nur overseer)",
    )
    parser.add_argument(
        "--fail-on",
        default="high",
        choices=(*fmt.SEVERITIES, "never"),
        help="ab welchem Schweregrad der Lauf fehlschlaegt (Standard: high)",
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


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.bot == "overseer":
        return _aufseher(args)
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
