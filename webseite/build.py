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
        "Secret-Bot",
        "Geheimnisse im Arbeitsbaum und in der Git-History. Ein Befund traegt nie "
        "den gefundenen Wert -- nur Regel, Ort und Laenge.",
    ),
    (
        workflow_bot,
        "Workflow-Bot",
        "Die GitHub Actions selbst. Zeilenbasiert, ohne YAML-Parser -- der Preis "
        "der Abhaengigkeitsfreiheit, benannt statt verschwiegen.",
    ),
    (
        dependency_bot,
        "Dependency-Bot",
        "Sperrdateien gegen OSV.dev. Kommt die Abfrage nicht durch, endet der Lauf "
        "mit 2: „der Lauf beweist nichts“, nicht „sauber“.",
    ),
    (
        code_bot,
        "Code-Bot",
        "Muster im Quelltext. Musterbasiert ohne Datenflussanalyse: er sieht, "
        "<em>dass</em> eine gefaehrliche Stelle da ist, nicht <em>ob</em> an ihr "
        "etwas Fremdes ankommt.",
    ),
    (
        license_bot,
        "Lizenz-Bot",
        "Was an Lizenzangaben fehlt und was auseinandergeht. Er stellt nie fest, "
        "unter welcher Lizenz etwas steht -- das ist eine Frage an einen Menschen.",
    ),
)

SCHWERE_TEXT = {
    "critical": "kritisch",
    "high": "hoch",
    "medium": "mittel",
    "low": "niedrig",
    "info": "Hinweis",
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
    kopf = "<tr><th>Regel</th>" + ("<th>Sprache</th>" if mit_sprache else "") + (
        "<th>Schwere</th><th>Was sie bedeutet</th></tr>"
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
            "<p><strong>Fuer diese Fassung liegt kein Ergebnis vor.</strong> "
            "Die Seite behauptet deshalb nichts ueber den Stand der Gegenprobe. "
            "Sie wird bei jedem Pull Request gefahren; das Ergebnis erscheint "
            "hier, sobald es mitgeliefert wird.</p>"
        )
    gesamt = daten.get("gesamt", 0)
    gefangen = daten.get("gefangen", 0)
    grundlauf = daten.get("grundlauf", "unbekannt")
    kopfzeile = (
        f"<p><strong>{gefangen} von {gesamt} Mutationen gefangen.</strong> "
        f"Grundlauf: {e(grundlauf)}.</p>"
    )
    if grundlauf != "gruen":
        kopfzeile += (
            "<p>Der Grundlauf war nicht gruen -- die Gegenprobe sagt in diesem "
            "Fall <em>nichts</em> aus.</p>"
        )
    zeilen = []
    for mutation in daten.get("mutationen", []):
        zustand = (
            '<span class="gefangen">gefangen</span>'
            if mutation.get("gefangen")
            else '<span class="entkommen">ENTKOMMEN</span>'
        )
        zeilen.append(
            "<tr>"
            f"<td><code>{e(mutation.get('name', ''))}</code></td>"
            f"<td>{zustand}</td>"
            f"<td>{e(mutation.get('trifft', ''))}</td>"
            "</tr>"
        )
    tabelle = (
        '<div class="tabellenhuelle"><table>'
        "<tr><th>Mutation</th><th>Ergebnis</th><th>Was sie kaputt macht</th></tr>"
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
        ("5", "Bots"),
        (str(regelzahl), "Regeln"),
        (str(zaehle_pruefungen()), "Pruefungen"),
        (str(mutationen) if mutationen else "–", "Mutationen"),
        ("0", "Abhaengigkeiten"),
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
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chinook &mdash; Sicherheits-Bots als GitHub Actions</title>
<meta name="description" content="Open-Source-Sicherheits-Bots als GitHub Actions, mit einer KI-Schicht, die die Bots kontrolliert. Jede Pruefung ist gegengeprueft.">
<style>{STIL}</style>
</head>
<body>
<div class="huelle">

<header>
<h1>Chinook
<span class="unter">Sicherheits-Bots als GitHub Actions &mdash; und eine KI-Schicht,
die die Bots kontrolliert. Open Source, MIT, Fassung {e(__version__)}.</span></h1>
</header>

<div class="karten">{kachel_html}</div>

<div class="merksatz">
<p>Ein Sicherheitswerkzeug, das gr&uuml;n l&auml;uft, ohne etwas zu pr&uuml;fen, ist schlimmer
als keins: es erzeugt Vertrauen, das nichts tr&auml;gt.</p>
<p>Deshalb ist in Chinook die <strong>Gegenprobe</strong> kein Zusatz, sondern der
Kern &mdash; jede Regel wird gegen einen absichtlich kaputten Fall gefahren, und jede
Pr&uuml;fung gegen einen absichtlich kaputten Bot.</p>
</div>

<h2>Einbauen</h2>
<p>In das zu pr&uuml;fende Repo, als <code>.github/workflows/chinook.yml</code>:</p>
<pre><code>name: Chinook
on: [pull_request]

permissions:
  contents: read

jobs:
  sicherheit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # nur n&ouml;tig f&uuml;r die History-Pr&uuml;fung

      - uses: Pheonix-Studio-cat/Chinook-security/actions/secret-bot@main
        with:
          history: "true"
      - uses: Pheonix-Studio-cat/Chinook-security/actions/workflow-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/dependency-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/code-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/license-bot@main</code></pre>
<p><code>@main</code> ist zum Ausprobieren. F&uuml;r den Dauerbetrieb auf einen
Commit-SHA festlegen &mdash; genau das, was der Workflow-Bot bei jeder anderen
Action anmahnt.</p>

<h3>R&uuml;ckgabewerte</h3>
<div class="tabellenhuelle"><table>
<tr><th>Wert</th><th>Bedeutung</th></tr>
<tr><td><code>0</code></td><td>nichts gefunden, das die Schwelle erreicht</td></tr>
<tr><td><code>1</code></td><td>Befunde ab der Schwelle</td></tr>
<tr><td><code>2</code></td><td><strong>der Lauf konnte nichts feststellen</strong> &mdash;
z.&nbsp;B. OSV war nicht erreichbar</td></tr>
</table></div>
<p>Die <code>2</code> ist der Grund, warum es sie gibt: ein Abruf, der nicht
durchkam, ist kein leeres Ergebnis. Er gilt nicht als bestanden.</p>

<h2>Die Bots</h2>
{"".join(bot_html)}

<h2>Der Aufseher</h2>
<p>Die KI-Schicht. Sie ordnet jeden Befund ein &mdash; {einschaetzungen} &mdash;
und liefert ein, zwei S&auml;tze Begr&uuml;ndung.</p>
<div class="merksatz">
<p><strong>Kein Befund geht verloren.</strong> Die Antwort des Modells kann nur ein
Feld <code>triage</code> an einen Befund h&auml;ngen. Sie kann keinen entfernen,
keinen Schweregrad &auml;ndern und keinen erfinden.</p>
<p>Und das steht im Code, nicht im Prompt: die Ergebnisliste entsteht aus den
<em>Befunden</em>, nie aus der Antwort. Eine Zusicherung, die an der Folgsamkeit
eines Modells h&auml;ngt, ist keine.</p>
</div>
<div class="tabellenhuelle"><table>
<tr><th>Eigenschaft</th><th>Warum</th></tr>
<tr><td>Er zahlt nicht auf ein fremdes Konto</td>
<td>Der Schl&uuml;ssel kommt aus <code>CHINOOK_AI_TOKEN</code> im Repo dessen, der ihn
einsetzt. Chinook h&auml;lt keinen.</td></tr>
<tr><td>Er ist freiwillig</td>
<td>Ohne Schl&uuml;ssel l&auml;uft alles andere weiter. Ein Scanner, der ausf&auml;llt, weil
ein Modell nicht antwortet, ist schlechter als keiner.</td></tr>
<tr><td>Keine Werkzeuge, keine Schreibrechte</td>
<td>Er liest zwangsl&auml;ufig fremden Text. Ein Modell mit Werkzeugen, das solchen
Text liest, ist Prompt Injection mit Schreibzugriff.</td></tr>
</table></div>

<h2>Die Gegenprobe</h2>
<p>Sie kopiert das Repo, macht die Bots <strong>absichtlich kaputt</strong> &mdash;
Redaktion abgeschaltet, eine Regel &uuml;bersprungen, der Netzfehler verschluckt,
der Aufseher l&auml;sst Befunde fallen &mdash; und verlangt, dass die Pr&uuml;fungen
daraufhin <strong>rot</strong> werden. Bleiben sie gr&uuml;n, ist die Pr&uuml;fung
wertlos, und die Gegenprobe sagt das laut.</p>
{abschnitt_gegenprobe(gegenprobe)}

<h2>Das Befund-Format</h2>
<p>Alle Bots geben dasselbe aus &mdash; als JSON und als SARIF f&uuml;r GitHubs
Security-Ansicht. Ohne das w&auml;ren weder der Aufseher noch diese Seite baubar,
weil beide Befunde lesen und nicht Werkzeugausgaben.</p>
<p>Felder je Befund: {", ".join(f"<code>{e(f)}</code>" for f in felder)}.</p>
<p><code>evidence</code> beschreibt einen Fund, ohne ihn wiederzugeben &mdash; kein
Pr&auml;fix, kein Hash, nur Regel und L&auml;nge. Ein Pr&auml;fix w&auml;re bei einem Passwort
ein Leck, ein Hash bei einem schwachen Passwort ein Orakel, und das Action-Log
eines &ouml;ffentlichen Repos liest jeder.</p>

<h2>Was Chinook nicht verspricht</h2>
<ul>
<li><strong>Vollst&auml;ndigkeit.</strong> Kein Befund hei&szlig;t nicht &bdquo;sicher&ldquo;, sondern
&bdquo;diese Regeln haben nichts gefunden&ldquo;.</li>
<li><strong>Keine Falschmeldungen.</strong> Mehrere Regeln laufen mit mittlerer
Zuversicht und liegen gelegentlich daneben.</li>
<li><strong>Keine Erkennungsraten.</strong> Es gibt hier keine Prozentzahlen, weil es
keine Messung gibt, die sie belegt.</li>
<li><strong>Keine Rechtsauskunft</strong> und <strong>keine eigene Einstufung von
Schwachstellen.</strong></li>
</ul>
<p>Die Grenzen im Einzelnen stehen in
<a href="{REPO}/blob/main/docs/grenzen.md"><code>docs/grenzen.md</code></a> &mdash;
diese Datei ist wichtiger als eine Merkmalsliste.</p>

<footer>
<p>Chinook &mdash; <a href="{REPO}">{REPO.replace("https://", "")}</a> &middot;
MIT &middot; PH&Ouml;NIX STUDIO.
Diese Seite wird aus dem Quelltext erzeugt, nicht von Hand gepflegt: jede Regel
oben kommt aus dem Bot, der sie anwendet.</p>
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
