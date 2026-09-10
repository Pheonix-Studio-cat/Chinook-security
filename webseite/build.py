"""Baut die Chinook-Website -- eine einzige statische HTML-Datei.

**Die Seite wird erzeugt, nicht gepflegt.** Jede Regel, die hier steht, kommt
aus dem Bot, der sie anwendet (`regeln()`). Eine von Hand gepflegte Liste
wuerde driften, und die Seite behauptete dann etwas, das kein Bot tut.
`checks/test_webseite.py` prueft, dass jede Regel auf der Seite steht.

Keine externe Datei: kein Stylesheet, keine Schrift, kein Skript von woanders.
Eine Seite, die ein Sicherheitswerkzeug beschreibt, laedt nichts nach.

Aufruf:  python3 -m webseite.build [--out webseite/out] [--gegenprobe gegenprobe.json]
"""

from __future__ import annotations

import argparse
import html
import json
import pathlib
import re

from chinook import (
    __version__,
    code_bot,
    dependency_bot,
    findings,
    license_bot,
    overseer,
    secret_bot,
    workflow_bot,
)

WURZEL = pathlib.Path(__file__).resolve().parent.parent
REPO = "https://github.com/Pheonix-Studio-cat/Chinook-security"

BOTS = (
    (
        secret_bot,
        "Secret bot",
        "Working tree <em>and</em> git history. A secret in an old commit is not gone "
        "just because the current file is clean.",
    ),
    (
        workflow_bot,
        "Workflow bot",
        "The GitHub Actions themselves &mdash; the route by which somebody reaches a "
        "repository&rsquo;s secrets.",
    ),
    (
        dependency_bot,
        "Dependency bot",
        "Eight lockfile formats against OSV.dev. If the query does not get through, the "
        "run ends with <b>2</b>: &bdquo;proves nothing&ldquo;, not &bdquo;clean&ldquo;.",
    ),
    (
        code_bot,
        "Code bot",
        "Patterns in the source. It sees <em>that</em> a dangerous spot is there &mdash; "
        "not <em>whether</em> anything foreign arrives at it.",
    ),
    (
        license_bot,
        "Licence bot",
        "What is missing and what disagrees. It never states which licence something is "
        "under.",
    ),
)

SCHWERE_TEXT = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
}

STIL = """
:root {
  color-scheme: light dark;
  --grund: #fbfaf8;
  --karte: #ffffff;
  --rand: #e4e0d8;
  --text: #1b1a18;
  --leise: #5f5b54;
  --akzent: #7a4b1e;
  --kritisch: #a3271c;
  --hoch: #b4531a;
  --mittel: #8a6d13;
  --leicht: #4a6b45;
  --code-grund: #f2efe9;
}
@media (prefers-color-scheme: dark) {
  :root {
    --grund: #16161a;
    --karte: #1e1e24;
    --rand: #33333c;
    --text: #ece9e4;
    --leise: #a5a099;
    --akzent: #e0a06a;
    --kritisch: #f08076;
    --hoch: #eda06a;
    --mittel: #d9c05f;
    --leicht: #90c188;
    --code-grund: #121216;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--grund);
  color: var(--text);
  font: 16px/1.65 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  -webkit-text-size-adjust: 100%;
}
.huelle { max-width: 54rem; margin: 0 auto; padding: 2.5rem 1.25rem 5rem; }
header { border-bottom: 2px solid var(--rand); padding-bottom: 1.75rem; margin-bottom: 2.5rem; }
h1 { font-size: 2.4rem; line-height: 1.15; margin: 0 0 .5rem; letter-spacing: -.02em; }
h1 .unter { display: block; font-size: 1rem; font-weight: 400; color: var(--leise); margin-top: .6rem; }
h2 { font-size: 1.5rem; margin: 3rem 0 .75rem; letter-spacing: -.01em; }
h3 { font-size: 1.1rem; margin: 2rem 0 .35rem; }
p { margin: .75rem 0; }
a { color: var(--akzent); }
.leise { color: var(--leise); }
.karten { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); margin: 1.5rem 0; }
.kachel { background: var(--karte); border: 1px solid var(--rand); border-radius: .6rem; padding: .9rem 1rem; }
.kachel .zahl { font-size: 1.9rem; font-weight: 650; line-height: 1.1; display: block; }
.kachel .wofuer { font-size: .82rem; color: var(--leise); }
pre {
  background: var(--code-grund); border: 1px solid var(--rand); border-radius: .6rem;
  padding: 1rem; overflow-x: auto; font-size: .85rem; line-height: 1.5;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .88em; }
p code, li code, td code { background: var(--code-grund); padding: .1em .35em; border-radius: .3em; }
.tabellenhuelle { overflow-x: auto; margin: 1rem 0; }
table { border-collapse: collapse; width: 100%; min-width: 32rem; font-size: .93rem; }
th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid var(--rand); vertical-align: top; }
th { font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; color: var(--leise); font-weight: 600; }
.marke { font-size: .74rem; font-weight: 650; text-transform: uppercase; letter-spacing: .04em; white-space: nowrap; }
.s-critical { color: var(--kritisch); }
.s-high { color: var(--hoch); }
.s-medium { color: var(--mittel); }
.s-low, .s-info { color: var(--leicht); }
.merksatz {
  border-left: 3px solid var(--akzent); background: var(--karte);
  padding: .9rem 1.1rem; margin: 1.5rem 0; border-radius: 0 .5rem .5rem 0;
}
.merksatz p:first-child { margin-top: 0; }
.merksatz p:last-child { margin-bottom: 0; }
.gefangen { color: var(--leicht); font-weight: 650; }
.entkommen { color: var(--kritisch); font-weight: 650; }
footer { margin-top: 4rem; padding-top: 1.5rem; border-top: 1px solid var(--rand); color: var(--leise); font-size: .88rem; }
"""


def e(text) -> str:
    return html.escape(str(text), quote=False)


def marke(schwere: str) -> str:
    return (
        f'<span class="marke s-{e(schwere)}">'
        f"{e(SCHWERE_TEXT.get(schwere, schwere))}</span>"
    )


def zaehle_pruefungen() -> int:
    anzahl = 0
    for datei in sorted((WURZEL / "checks").glob("test_*.py")):
        anzahl += len(re.findall(r"^\s+def test_", datei.read_text(encoding="utf-8"), re.M))
    return anzahl


def lies_gegenprobe(pfad: str | None) -> dict | None:
    if not pfad:
        return None
    datei = pathlib.Path(pfad)
    if not datei.is_file():
        return None
    with open(datei, encoding="utf-8") as handle:
        return json.load(handle)


def regeltabelle(regeln, mit_sprache: bool = False) -> str:
    kopf = "<tr><th>Rule</th>" + ("<th>Language</th>" if mit_sprache else "") + (
        "<th>Severity</th><th>What it means</th></tr>"
    )
    zeilen = []
    for regel in regeln:
        sprache = f"<td>{e(regel.get('sprache', ''))}</td>" if mit_sprache else ""
        zeilen.append(
            "<tr>"
            f"<td><code>{e(regel['name'])}</code><br><span class=\"leise\">{e(regel['titel'])}</span></td>"
            f"{sprache}"
            f"<td>{marke(regel['schwere'])}</td>"
            f"<td>{e(regel['was'])}</td>"
            "</tr>"
        )
    return (
        '<div class="tabellenhuelle"><table>'
        + kopf
        + "".join(zeilen)
        + "</table></div>"
    )


def abschnitt_gegenprobe(daten: dict | None) -> str:
    if daten is None:
        return (
            "<p><strong>No result is available for this version.</strong> "
            "The page therefore claims nothing about the state of the counterproof. "
            "It runs on every pull request; the result appears here as soon as it is "
            "handed along.</p>"
        )
    gesamt = daten.get("gesamt", 0)
    gefangen = daten.get("gefangen", 0)
    grundlauf = daten.get("grundlauf", "unbekannt")
    zustand = {"gruen": "green", "rot": "red"}.get(grundlauf, grundlauf)
    kopfzeile = (
        f"<p><strong>{gefangen} of {gesamt} mutations caught.</strong> "
        f"Baseline run: {e(zustand)}.</p>"
    )
    if grundlauf != "gruen":
        kopfzeile += (
            "<p>The baseline run was not green &mdash; in that case the counterproof "
            "says <em>nothing</em>.</p>"
        )
    zeilen = []
    for mutation in daten.get("mutationen", []):
        zustand_m = (
            '<span class="gefangen">caught</span>'
            if mutation.get("gefangen")
            else '<span class="entkommen">ESCAPED</span>'
        )
        zeilen.append(
            "<tr>"
            f"<td><code>{e(mutation.get('name', ''))}</code></td>"
            f"<td>{zustand_m}</td>"
            f"<td>{e(mutation.get('trifft', ''))}</td>"
            "</tr>"
        )
    tabelle = (
        '<div class="tabellenhuelle"><table>'
        "<tr><th>Mutation</th><th>Result</th><th>What it breaks</th></tr>"
        + "".join(zeilen)
        + "</table></div>"
        if zeilen
        else ""
    )
    return kopfzeile + tabelle


def baue(gegenprobe: dict | None = None) -> str:
    regelzahl = sum(len(modul.regeln()) for modul, _, _ in BOTS)
    mutationen = gegenprobe.get("gesamt") if gegenprobe else None

    kacheln = [
        ("5", "bots"),
        (str(regelzahl), "rules"),
        (str(zaehle_pruefungen()), "checks"),
        (str(mutationen) if mutationen else "\u2013", "mutations"),
        ("0", "dependencies"),
    ]
    kachel_html = "".join(
        f'<div class="kachel"><span class="zahl">{e(z)}</span>'
        f'<span class="wofuer">{e(w)}</span></div>'
        for z, w in kacheln
    )

    bot_html = []
    for modul, name, beschreibung in BOTS:
        bot_html.append(
            f"<h3>{e(name)}</h3><p>{beschreibung}</p>"
            + regeltabelle(modul.regeln(), mit_sprache=(modul is code_bot))
        )

    einschaetzungen = ", ".join(f"<code>{e(x)}</code>" for x in overseer.EINSCHAETZUNGEN)
    with open(WURZEL / "schema" / "finding.schema.json", encoding="utf-8") as handle:
        schema = json.load(handle)
    felder = list(schema["properties"]["findings"]["items"]["properties"])

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chinook &mdash; security bots as GitHub Actions</title>
<meta name="description" content="Open-source security bots as GitHub Actions, with an AI layer that keeps the bots honest. Every check is counter-proved.">
<style>{STIL}</style>
</head>
<body>
<div class="huelle">

<header>
<h1>Chinook
<span class="unter">Security bots as GitHub Actions &mdash; and an AI layer that keeps
the bots honest. Open source, MIT, version {e(__version__)}.</span></h1>
</header>

<div class="karten">{kachel_html}</div>

<div class="merksatz">
<p>A security tool that runs green without checking anything is worse than none:
it creates trust that carries nothing.</p>
<p>That is why the <strong>counterproof</strong> is not an extra in Chinook but the
core &mdash; every rule is run against a deliberately broken case, and every check
against a deliberately broken bot.</p>
</div>

<h2>Installing</h2>
<p>Into the repository you want checked, as <code>.github/workflows/chinook.yml</code>:</p>
<pre><code>name: Chinook
on: [pull_request]

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # only needed for the history check

      - uses: Pheonix-Studio-cat/Chinook-security/actions/secret-bot@main
        with:
          history: "true"
      - uses: Pheonix-Studio-cat/Chinook-security/actions/workflow-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/dependency-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/code-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/license-bot@main</code></pre>
<p><code>@main</code> is for trying it out. For day-to-day use, pin a commit SHA
&mdash; exactly what the workflow bot demands of every other action.</p>

<h3>Exit codes</h3>
<div class="tabellenhuelle"><table>
<tr><th>Value</th><th>Meaning</th></tr>
<tr><td><code>0</code></td><td>nothing found that reaches the threshold</td></tr>
<tr><td><code>1</code></td><td>findings at or above the threshold</td></tr>
<tr><td><code>2</code></td><td><strong>the run could not determine anything</strong> &mdash;
e.g. OSV was unreachable</td></tr>
</table></div>
<p>The <code>2</code> is the reason it exists: a request that did not get through
is not an empty result. It does not count as passing.</p>

<h2>The bots</h2>
{"".join(bot_html)}

<h2>The overseer</h2>
<p>The AI layer. It rates every finding &mdash; {einschaetzungen} &mdash; and gives a
sentence or two of reasoning.</p>
<div class="merksatz">
<p><strong>No finding gets lost.</strong> The model&rsquo;s answer can only attach a
<code>triage</code> field to a finding. It cannot remove one, change a severity, or
invent one.</p>
<p>And that is in the code, not in the prompt: the result list is built from the
<em>findings</em>, never from the answer. A guarantee that hangs on a model&rsquo;s
obedience is not one.</p>
</div>
<div class="tabellenhuelle"><table>
<tr><th>Property</th><th>Why</th></tr>
<tr><td>It does not spend someone else&rsquo;s money</td>
<td>The key comes from <code>CHINOOK_AI_TOKEN</code> in the repository of whoever runs
it. Chinook holds none.</td></tr>
<tr><td>It is optional</td>
<td>Without a key everything else keeps running. A scanner that fails because a model
did not answer is worse than none.</td></tr>
<tr><td>No tools, no write access</td>
<td>It inevitably reads foreign text. A model with tools reading such text is prompt
injection with write access.</td></tr>
</table></div>

<h2>The counterproof</h2>
<p>It copies the repository, breaks the bots <strong>on purpose</strong> &mdash;
redaction switched off, a rule skipped, the network error swallowed, the overseer
dropping findings &mdash; and demands that the checks go <strong>red</strong> as a
result. If they stay green, the check is worthless, and the counterproof says so.</p>
{abschnitt_gegenprobe(gegenprobe)}

<h2>The finding format</h2>
<p>Every bot emits the same thing &mdash; as JSON and as SARIF for GitHub&rsquo;s
security view. Without it neither the overseer nor this page could be built, because
both read findings and not tool output.</p>
<p>Fields per finding: {", ".join(f"<code>{e(f)}</code>" for f in felder)}.</p>
<p><code>evidence</code> describes a find without reproducing it &mdash; no prefix, no
hash, only rule and length. A prefix would be a leak for a password, a hash an oracle
for a weak one, and in a public repository anyone can read the action log.</p>

<h2>What Chinook does not promise</h2>
<ul>
<li><strong>Completeness.</strong> No finding does not mean &bdquo;secure&ldquo;, it
means &bdquo;these rules found nothing&ldquo;.</li>
<li><strong>No false positives.</strong> Several rules run at medium confidence and
are sometimes wrong.</li>
<li><strong>No detection rates.</strong> There are no percentages here, because there
is no measurement backing them.</li>
<li><strong>No legal advice</strong> and no severity rating of its own.</li>
</ul>
<p>The limits in detail are in
<a href="{REPO}/blob/main/docs/grenzen.md"><code>docs/grenzen.md</code></a> (German)
&mdash; that file matters more than a feature list.</p>

<footer>
<p>Chinook &mdash; <a href="{REPO}">{REPO.replace("https://", "")}</a> &middot;
MIT &middot; PH&Ouml;NIX STUDIO.
This page is generated from the source, not maintained by hand: every rule above
comes from the bot that applies it.</p>
</footer>

</div>
</body>
</html>
"""


def main(argv=None) -> int:
    zerleger = argparse.ArgumentParser(prog="webseite.build", description="Baut die Chinook-Website.")
    zerleger.add_argument("--out", default=str(WURZEL / "webseite" / "out"), help="Ausgabeverzeichnis")
    zerleger.add_argument(
        "--gegenprobe", default="", help="JSON-Ergebnis von checks.counterproof"
    )
    args = zerleger.parse_args(argv)

    ziel = pathlib.Path(args.out)
    ziel.mkdir(parents=True, exist_ok=True)
    seite = baue(lies_gegenprobe(args.gegenprobe))
    (ziel / "index.html").write_text(seite, encoding="utf-8")
    print(f"webseite: {ziel / 'index.html'} ({len(seite)} Zeichen)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
