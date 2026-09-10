# Chinook

**Sicherheits-Bots als GitHub Actions — und eine KI-Schicht, die die Bots
kontrolliert.** Open Source, MIT.

Ein Sicherheitswerkzeug, das grün läuft, ohne etwas zu prüfen, ist schlimmer
als keins: es erzeugt Vertrauen, das nichts trägt. Deshalb ist in Chinook die
**Gegenprobe** kein Zusatz, sondern der Kern — jede Regel wird gegen einen
absichtlich kaputten Fall gefahren, und jede Prüfung wird gegen einen
absichtlich kaputten Bot gefahren. Was dabei grün bleibt, gilt als wertlos und
wird gemeldet.

---

## Stand

**Alle fünf Etappen sind gebaut:** das gemeinsame Befund-Format, fünf Bots, die
Gegenprobe, je eine composite action pro Bot, der **Aufseher**, der die Befunde
einordnet und die Bots kontrolliert, die **Website** und der **Wochenlauf**.

| Teil | Zustand |
| --- | --- |
| Befund-Format (JSON + SARIF) | ✅ `chinook/findings.py`, `schema/finding.schema.json` |
| **Secret-Bot** | ✅ Arbeitsbaum und Git-History |
| **Workflow-Bot** | ✅ die Actions selbst |
| **Dependency-Bot** | ✅ Sperrdateien gegen OSV.dev |
| **Code-Bot** | ✅ 12 Muster in Python, JavaScript, Shell |
| **Lizenz-Bot** | ✅ was fehlt und was auseinandergeht |
| Composite Action je Bot | ✅ auch aus fremden Repos nachgewiesen |
| **Aufseher** (KI-Schicht) | ✅ ordnet ein, entfernt nie |
| Gegenprobe | ✅ 25 Mutationen, alle gefangen |
| **Website** | ✅ aus dem Quelltext erzeugt, GitHub Pages |
| **Wochenlauf** | ✅ montags, auch ohne Commit |

**146 Prüfungen, alle grün. 25 Mutationen, alle gefangen.**

**Keine Abhängigkeiten.** Nur die Python-Standardbibliothek. Ein
Sicherheitswerkzeug mit dreihundert transitiven Paketen ist selbst eine
Angriffsfläche, und ein Lockfile will gepflegt werden.

---

## Einbauen

In das zu prüfende Repo, als `.github/workflows/chinook.yml`:

```yaml
name: Chinook
on: [pull_request]

permissions:
  contents: read

jobs:
  sicherheit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # nur nötig für die History-Prüfung

      - uses: Pheonix-Studio-cat/Chinook-security/actions/secret-bot@main
        with:
          history: "true"
      - uses: Pheonix-Studio-cat/Chinook-security/actions/workflow-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/dependency-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/code-bot@main
      - uses: Pheonix-Studio-cat/Chinook-security/actions/license-bot@main
```

Der **Aufseher** kommt als eigener Schritt dazu, wenn man ihn will:

```yaml
      - uses: Pheonix-Studio-cat/Chinook-security/actions/overseer@main
        env:
          CHINOOK_AI_TOKEN: ${{ secrets.CHINOOK_AI_TOKEN }}
        with:
          reports: chinook-secret-bot.json,chinook-code-bot.json
```

Ohne das Secret wird er **übersprungen**, und der Lauf bleibt grün — die
Befunde der Bots stehen dann unverändert da. Das ist Absicht, siehe unten.

> ⚠️ `@main` ist zum Ausprobieren. Für den Dauerbetrieb auf einen Commit-SHA
> festlegen — genau das, was der Workflow-Bot bei jeder anderen Action
> anmahnt. Sobald es einen `v1`-Tag gibt, steht er hier.

**Warum composite actions und keine aufrufbaren Workflows?** Ein aufrufbarer
Workflow (`uses: …/secret-bot.yml@v1`) wäre eine Zeile statt vier. Er müsste
aber wissen, welche Fassung von Chinook er nachladen soll — und dafür gibt es
keinen brauchbaren Wert: `github.job_workflow_sha` war in allen drei geprüften
Fällen leer (lokaler Aufruf, Aufruf über den vollen Pfad im selben Repo, Aufruf
aus einem fremden Repo). Ohne den Wert bliebe nur ein fest verdrahteter Ref,
der dann nicht mehr dem `@…` des Aufrufers entspricht: der Bot käme aus einer
anderen Fassung, als der Nutzer festgelegt hat, und niemand würde es merken.

Eine composite action hat das Problem nicht. Sie findet ihren eigenen Quelltext
über `github.action_path`, und der liegt in **genau** der Fassung hinter dem
`@`. Vier Zeilen mehr, dafür stimmt die Fassung. Nachgewiesen: das
Gedächtnis-Repo des Projektinhabers bindet den Secret-Bot so ein, aus einem
anderen — und privaten — Repo heraus.

### Rückgabewerte

| Wert | Bedeutung |
| --- | --- |
| `0` | nichts gefunden, das die Schwelle erreicht |
| `1` | Befunde ab der Schwelle |
| `2` | **der Lauf konnte nichts feststellen** — z. B. OSV war nicht erreichbar |

Die `2` ist der Grund, warum es sie gibt: ein Abruf, der nicht durchkam, ist
kein leeres Ergebnis. Er gilt nicht als bestanden.

### Die Bots einzeln

| Eingabe | Bedeutung |
| --- | --- |
| `path` | Wurzel des zu prüfenden Verzeichnisses (Standard `.`) |
| `exclude` | Pfade, kommagetrennt |
| `history` | **nur Secret-Bot:** auch die Git-History prüfen, braucht `fetch-depth: 0` |
| `fail-on` | ab welchem Schweregrad der Schritt fehlschlägt (Standard `high`, Lizenz-Bot `medium`) |
| `report` | Pfad des JSON-Berichts |
| `sarif` | Pfad des SARIF-Berichts, leer = keiner |

Jeder Bot gibt `report` und `total` als Output zurück.

Wer die Befunde in GitHubs Security-Ansicht sehen will, lädt die SARIF-Datei
mit `github/codeql-action/upload-sarif` hoch. Das braucht
`security-events: write` — dieses Recht gehört **in den einzelnen Job**, nicht
an den Anfang der Datei.

---

## Was die Bots finden

### Secret-Bot

Neun Regeln: AWS Access Key ID, GitHub-Token, Hugging-Face-Token, Anthropic-,
OpenAI-, Slack- und Google-Schlüssel, private Schlüsselblöcke, und Zugangsdaten,
die einer Variablen zugewiesen werden. Die letzte Regel läuft mit mittlerer
Zuversicht und lässt erkennbare Platzhalter (`changeme`, `${VAR}`,
`your-key-here`) durch.

**Er prüft auch die History.** Ein Geheimnis, das in einem alten Commit steht,
ist nicht weg, nur weil die aktuelle Datei sauber ist — und genau das lässt ein
reiner Diff-Scan durch.

> 🔒 **Ein Befund enthält nie den Fund.** Gemeldet werden Regel, Ort und Länge,
> sonst nichts — kein Präfix, kein Hash. Bei einem öffentlichen Repo liest jeder
> das Action-Log; ein Secret-Bot, der den gefundenen Schlüssel ausdruckt, wäre
> selbst das Leck. Eine Prüfung hält das fest, und die Gegenprobe zeigt, dass
> sie anschlägt, wenn die Redaktion abgeschaltet wird.

### Workflow-Bot

| Regel | Schwere | Was sie bedeutet |
| --- | --- | --- |
| `pull-request-target-checkout` | kritisch | `pull_request_target` läuft mit den Secrets des Ziel-Repos. Wer darin den PR-Kopf auscheckt, führt fremden Code mit diesen Secrets aus. |
| `script-injection` | hoch | Ein Titel oder Kommentar wird vor der Ausführung in ein `run:`- oder `script:`-Skript eingesetzt. Ein Backtick darin ist dann ein Befehl. |
| `permissions-write-all` | hoch | Jeder Schritt erbt alle Schreibrechte, auch eine Fremd-Action. |
| `unpinned-action` | mittel (bei `actions/*`: Hinweis) | Ein Tag lässt sich verschieben. Dann ändert sich, was hier mit den Rechten dieses Repos läuft. |
| `permissions-missing` | mittel | Ohne `permissions:` gelten die Standardrechte des Repos — an anderer Stelle eingestellt, änderbar, ohne dass diese Datei sich ändert. |

**Bewusst zeilenbasiert, ohne YAML-Parser** — das ist der Preis dafür, keine
Abhängigkeit zu haben. Für Anker und mehrzeilige Flow-Maps ist das zu grob; das
steht so auch in `docs/`, statt verschwiegen zu werden.

### Dependency-Bot

Liest die **Sperrdateien**, nicht die Wunschlisten. Was er findet, fragt er bei
**OSV.dev** an — der offenen Schwachstellendatenbank, ohne Schlüssel und ohne
Anmeldung.

| Datei | Ökosystem |
| --- | --- |
| `requirements.txt` (nur `==`), `poetry.lock` | PyPI |
| `package-lock.json` (Format 1 wie 2/3), `yarn.lock` (v1 und Berry), `pnpm-lock.yaml` | npm |
| `go.mod` | Go |
| `Cargo.lock` | crates.io |
| `composer.lock` | Packagist |

Ein falsch geschriebener Ökosystem-Name fände **nichts** — und nichts sähe aus
wie „sauber". Deshalb prüft `checks/oekosystemprobe.py` in der Selbstprüfung
gegen den echten Dienst, ob OSV die Namen kennt. Sie arbeitet im Unterschied:
erst fragt sie mit einem erfundenen Ökosystem; erst wenn OSV *das* zurückweist,
ist „nicht zurückgewiesen" ein Beleg.

Zwei Regeln: `known-vulnerability` (hoch) und `dependency-unpinned` (niedrig,
nur bei `requirements.txt` ohne `==`).

> 🔴 **Ein fehlgeschlagener Abruf ist kein leeres Ergebnis.** Kommt die Abfrage
> nicht durch, oder passt die Antwort nicht zur Anfrage, endet der Lauf mit
> Rückgabewert **2** — nicht mit einem grünen Haken. Wer nicht fragen konnte,
> weiß nichts.

**Chinook stuft nicht selbst ein.** Jede bekannte Schwachstelle ist „hoch", und
im Befund stehen die Advisory-Kennungen. Eine Zahl aus einem CVSS-Vektor
abzuleiten, den wir nicht geholt haben, wäre eine erfundene Angabe; das
Einordnen ist Aufgabe des Aufsehers (Etappe 3).

### Code-Bot

Zwölf Muster, nach Dateiendung getrennt:

| Sprache | Was gesucht wird |
| --- | --- |
| Python | ausgeführter Text (`eval`/`exec`), Shell-Aufrufe mit eingesetzten Werten, `pickle`, unsicheres YAML, abgeschaltete TLS-Prüfung, `mktemp` |
| JavaScript / TypeScript | ausgeführter Text, `exec` mit zusammengesetztem Befehl, `innerHTML`, abgeschaltete TLS-Prüfung |
| Shell | Heruntergeladenes direkt ausführen (`curl …` in eine Shell gepipet), `eval` |

Musterbasiert, **ohne Datenflussanalyse**: er sieht, *dass* eine gefährliche
Stelle da ist, nicht *ob* an ihr etwas Fremdes ankommt. Regeln mit mittlerer
Zuversicht sind entsprechend gekennzeichnet.

### Lizenz-Bot

| Regel | Schwere | Was sie bedeutet |
| --- | --- | --- |
| `license-file-missing` | mittel | keine Lizenzdatei im Wurzelverzeichnis |
| `license-undeclared` | mittel | `package.json` oder `pyproject.toml` ohne Lizenzangabe |
| `license-link-broken` | mittel | die Angabe verweist auf eine Datei, die es nicht gibt |
| `license-mismatch` | mittel | Erklärung und beiliegender Text gehen auseinander |
| `license-unrecognised` | Hinweis | keine bekannte SPDX-Kennung — *License status requires verification* |

> ⚖️ **Er stellt keine Rechtstatsache fest.** Er sagt nie, unter welcher Lizenz
> etwas steht — nur was erklärt ist, was fehlt und was auseinandergeht. Alles
> Weitere ist eine Frage an einen Menschen. Eine Prüfung hält fest, dass kein
> Befund eine Lizenz behauptet.

---

## Der Aufseher

Die KI-Schicht. Sie hat zwei Aufgaben, und die zweite ist die eigentliche.

**Befunde einordnen.** Zu jedem Befund eine von vier Einschätzungen —
`bestaetigt`, `vermutlich-echt`, `vermutlich-rauschen`, `unklar` — plus ein, zwei
Sätze Begründung. Ohne Triage erstickt jeder Scanner-Rollout an Falschmeldungen.

**Die Bots kontrollieren.** `python3 -m checks.counterproof --json …` schreibt
das Ergebnis der Gegenprobe maschinenlesbar: welcher Bot absichtlich kaputt
gemacht wurde, und ob die Prüfungen daraufhin rot wurden. Ein Bot, der gegen ein
kaputtes Fixture grün bleibt, ist kaputt — und das steht dann da.

### Drei Eigenschaften, die feststanden, bevor eine Zeile davon existierte

| | |
| --- | --- |
| **Er zahlt nicht auf ein fremdes Konto** | Der Schlüssel kommt aus `CHINOOK_AI_TOKEN` im Repo dessen, der ihn einsetzt. Chinook hält keinen. |
| **Er ist freiwillig** | Ohne Schlüssel läuft alles andere weiter. Ein Scanner, der ausfällt, weil ein Modell nicht antwortet, ist schlechter als keiner. |
| **Er hat keine Werkzeuge und keine Schreibrechte** | Er liest zwangsläufig fremden Text — Pfade aus einem Fork, Paketnamen. Ein Modell mit Werkzeugen, das solchen Text liest, ist Prompt Injection mit Schreibzugriff. |

### Und die Zusicherung, an der alles hängt

> 🔒 **Kein Befund geht verloren.** Die Antwort des Modells kann nur ein Feld
> `triage` an einen Befund hängen. Sie kann keinen entfernen, keinen
> Schweregrad ändern und keinen erfinden.

Technisch: die Ergebnisliste wird aus den **Befunden** aufgebaut, nie aus der
Antwort. Was das Modell zu einem unbekannten Fingerabdruck sagt, fällt weg; eine
Einschätzung außerhalb der vier erlaubten fällt weg; die Begründung wird von
Steuerzeichen befreit und gekürzt. Sechs Prüfungen fahren genau diese Angriffe,
und fünf Mutationen halten sie fest.

Wegräumen bleibt eine Menschenentscheidung.

### Wenn er nicht laufen kann

| Fall | Was passiert |
| --- | --- |
| kein Schlüssel | `uebersprungen`, Rückgabewert `0` |
| Anfrage scheitert / Modell lehnt ab | `fehlgeschlagen`, Rückgabewert `0` |
| dasselbe mit `--require` | Rückgabewert `2` |

Warum hier `0` und nicht `2` wie beim Dependency-Bot? Weil der Aufseher **kein
Urteil fällt**. Die Bots haben ihres schon gefällt, und ihre Befunde stehen
unverändert im Bericht. Wer ohne Einordnung nicht weitermachen will, nimmt
`--require`.

Der Aufruf geht an die Anthropic-Messages-API, Standardmodell `claude-opus-5`.
Anderes Modell mit `--model`; andere Adresse mit `--api-url`. Andere Anbieter
sprechen eine andere Request-Form — das steht in `docs/grenzen.md`.

---

## Die Website

Statisch, eine einzige HTML-Datei, **aus dem Quelltext erzeugt**:

```
python3 -m webseite.build --gegenprobe chinook-gegenprobe.json
```

Jede Regel, die auf der Seite steht, kommt aus dem Bot, der sie anwendet
(`regeln()`). Eine von Hand gepflegte Liste würde driften, und die Seite
behauptete dann etwas, das kein Bot tut. Eine Prüfung hält fest, dass jede
Regel auf der Seite steht — und eine zweite, dass die Regeltabellen **genau**
den Regeln entsprechen, die die Bots gegen ihre Fixtures melden.

Die Seite lädt **nichts nach**: kein Stylesheet, keine Schrift, kein Skript von
woanders. Eine Seite, die ein Sicherheitswerkzeug beschreibt, holt keinen Code
von fremden Adressen. Auch das ist geprüft.

Und sie zeigt den **Stand der Gegenprobe** — welche Mutation gefangen wurde und
welche nicht. Liegt kein Ergebnis vor, sagt sie das, statt etwas zu behaupten.
Der Bau läuft bei jedem Merge auf `main` und einmal wöchentlich.

Veröffentlicht wird über den Branch **`gh-pages`**, nicht über
`actions/deploy-pages`: das hätte eine Einstellung im Repo vorausgesetzt, die
niemand im Quelltext sieht. Das Anlegen des Branches hat GitHub Pages dagegen
von selbst aktiviert. Jeder Lauf schreibt einen einzelnen Commit ohne
Vorgeschichte — der Branch ist erzeugter Inhalt, kein Ort zum Bearbeiten.

Die Seite liegt unter
`https://pheonix-studio-cat.github.io/Chinook-security/`.

## Der Wochenlauf

Montags: Prüfungen, Gegenprobe und alle fünf Bots über das eigene Repo, ohne
dass jemand etwas committen muss. Er fängt, was sich **ohne Commit** ändert —
ein neues Advisory bei OSV, eine geänderte Voreinstellung bei GitHub Actions,
ein Werkzeug, das anders antwortet als letzte Woche.

## Die Gegenprobe

```
python3 -m checks.counterproof [--json gegenprobe.json]
```

Sie kopiert das Repo, macht die Bots **absichtlich kaputt** — Redaktion
abgeschaltet, eine Regel übersprungen, `is_pinned` gibt immer `True` zurück,
der OSV-Fehler wird verschluckt, der Aufseher lässt Befunde fallen — und
verlangt, dass die Prüfungen daraufhin **rot** werden. Fünfundzwanzig
Mutationen, alle gefangen. Jede Mutation prüft vorher,
dass sie die Datei überhaupt verändert hat; ohne das könnte eine wirkungslose
Mutation ein Urteil fällen.

Der Grund für den ganzen Aufwand steht oben: *eine Prüfung, die nie gegen einen
absichtlich kaputten Zustand gelaufen ist, ist keine Prüfung.*

---

## Aufbau

```
chinook/            die Bots, nur Standardbibliothek
  findings.py       das gemeinsame Befund-Format, JSON und SARIF
  secret_bot.py  workflow_bot.py  dependency_bot.py  code_bot.py  license_bot.py
  overseer.py       der Aufseher — ordnet ein, entfernt nie
  cli.py            python3 -m chinook.cli <bot> …
actions/            je ein composite action pro Bot
.github/workflows/  die Selbstprüfung
webseite/build.py   erzeugt die Seite aus den Regeln der Bots
checks/             Prüfungen und die Gegenprobe
fixtures/workflows/ absichtlich kaputte Workflows — außerhalb von
                    .github/workflows, damit GitHub sie nicht ausführt
fixtures/code/      die Code-Proben als JSON — nicht als .py/.js/.sh, sonst
                    meldete der Code-Bot seine eigenen Fixtures
schema/             das Befund-Schema als JSON Schema
docs/               Regeln im Einzelnen, Grenzen, Entscheidungen
```

Die Fixtures für Geheimnisse werden **zur Laufzeit erzeugt**
(`checks/fixtures.py`), nicht als Datei abgelegt: ein formatgültiges Token im
Repo wird von GitHubs Push-Protection blockiert und von Scannern gemeldet.

---

## Was offen ist

- **`v1` taggen**, damit Nutzer `@v1` schreiben können statt `@main` oder eines
  Commit-SHA.
- **Der Aufseher ist nie gegen ein echtes Modell gelaufen.** Die Prüfungen
  fahren gegen einen Stub — richtig so, geprüft wird, was Chinook mit der
  Antwort macht. Ob ein echtes Modell brauchbare Einschätzungen liefert, ist
  offen.
- **Lizenzen der Abhängigkeiten** für den Lizenz-Bot — er sieht bisher nur das
  Repo selbst, nicht das, was es einbindet.
- **Behobene Versionen im Befund.** Die OSV-Sammelabfrage liefert nur
  Kennungen; eine behobene Version bräuchte einen zweiten Abruf je Advisory.

---

## Lizenz

MIT, siehe [`LICENSE`](LICENSE). Sicherheitslücken bitte nach
[`SECURITY.md`](SECURITY.md) melden.
