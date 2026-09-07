"""Ein Einstiegspunkt fuer alle Bots: `python3 -m chinook.cli <bot> ...`

Die Ausgabe ist Deutsch und enthaelt nie einen gefundenen Wert.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import findings as fmt
from . import secret_bot, workflow_bot

BOTS = {
    "secret-bot": secret_bot,
    "workflow-bot": workflow_bot,
}

_SEVERITY_LABEL = {
    "critical": "kritisch",
    "high": "hoch",
    "medium": "mittel",
    "low": "niedrig",
    "info": "Hinweis",
}


def _split(value: str) -> list[str]:
    return [part.strip() for part in value.split(",") if part.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chinook",
        description="Chinook -- Sicherheits-Bots fuer GitHub-Repos.",
    )
    parser.add_argument("bot", choices=sorted(BOTS), help="welcher Bot laufen soll")
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


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    module = BOTS[args.bot]
    excludes = _split(args.exclude)

    if args.bot == "secret-bot":
        results = module.run(args.path, excludes, history=args.history)
    else:
        results = module.run(args.path, excludes)

    report = fmt.report(args.bot, results, target={"path": os.path.abspath(args.path)})
    if args.json_out:
        _write(args.json_out, report)
    if args.sarif_out:
        _write(args.sarif_out, fmt.to_sarif(args.bot, results))

    print(f"{args.bot}: {report['summary']['total']} Befund(e)")
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
            f"\nFehlgeschlagen: mindestens ein Befund erreicht die Schwelle "
            f"'{_SEVERITY_LABEL.get(args.fail_on, args.fail_on)}'.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
