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

Gebaut sind Etappe 1 und 2: das gemeinsame Befund-Format, **fünf Bots**, die
Gegenprobe, und aufrufbare Workflows für den Einbau mit einer Zeile.

| Teil | Zustand |
| --- | --- |
| Befund-Format (JSON + SARIF) | ✅ `chinook/findings.py`, `schema/finding.schema.json` |
| **Secret-Bot** | ✅ Arbeitsbaum und Git-History |
| **Workflow-Bot** | ✅ die Actions selbst |
| **Dependency-Bot** | ✅ Sperrdateien gegen OSV.dev |
| **Code-Bot** | ✅ 12 Muster in Python, JavaScript, Shell |
| **Lizenz-Bot** | ✅ was fehlt und was auseinandergeht |
| Aufrufbare Workflows | ✅ eine Zeile je Bot |
| Gegenprobe | ✅ 20 Mutationen, alle gefangen |
| Aufseher (KI-Schicht) | ⏳ Etappe 3 |
| Website | ⏳ Etappe 4 |

**98 Prüfungen, alle grün. 20 Mutationen, alle gefangen.**

**Keine Abhängigkeiten.** Nur die Python-Standardbibliothek. Ein
Sicherheitswerkzeug mit dreihundert transitiven Paketen ist selbst eine
Angriffsfläche, und ein Lockfile will gepflegt werden.

---

## Einbauen

In das zu prüfende Repo, als `.github/workflows/chinook.yml`. Jeder Bot ist
**ein aufrufbarer Workflow** — eine Zeile, kein eigener Checkout:

```yaml
name: Chinook
on: [pull_request]

jobs:
  geheimnisse:
    uses: Pheonix-Studio-cat/Chinook-security/.github/workflows/secret-bot.yml@main
  workflows:
    uses: Pheonix-Studio-cat/Chinook-security/.github/workflows/workflow-bot.yml@main
  abhaengigkeiten:
    uses: Pheonix-Studio-cat/Chinook-security/.github/workflows/dependency-bot.yml@main
  quelltext:
    uses: Pheonix-Studio-cat/Chinook-security/.github/workflows/code-bot.yml@main
  lizenzen:
    uses: Pheonix-Studio-cat/Chinook-security/.github/workflows/license-bot.yml@main
```

Der aufrufbare Workflow holt Chinook in **genau der Fassung**, die hinter dem
`@` steht — über `github.job_workflow_sha`. Ist die leer, bricht er ab, statt
stillschweigend irgendeine Fassung zu holen.

Wer die Bots als einzelne Schritte in einem eigenen Job braucht, nimmt
stattdessen die composite actions:

```yaml
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # nur nötig für die History-Prüfung
      - uses: Pheonix-Studio-cat/Chinook-security/actions/secret-bot@main
        with:
          history: "true"
```

> ⚠️ `@main` ist zum Ausprobieren. Für den Dauerbetrieb auf einen Commit-SHA
> festlegen — genau das, was der Workflow-Bot bei jeder anderen Action
> anmahnt. Sobald es einen `v1`-Tag gibt, steht er hier.

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
| `script-injection` | hoch | Ein Titel oder Kommentar wird vor der Ausführung in ein `run:`-Skript eingesetzt. Ein Backtick darin ist dann ein Befehl. |
| `permissions-write-all` | hoch | Jeder Schritt erbt alle Schreibrechte, auch eine Fremd-Action. |
| `unpinned-action` | mittel (bei `actions/*`: Hinweis) | Ein Tag lässt sich verschieben. Dann ändert sich, was hier mit den Rechten dieses Repos läuft. |
| `permissions-missing` | mittel | Ohne `permissions:` gelten die Standardrechte des Repos — an anderer Stelle eingestellt, änderbar, ohne dass diese Datei sich ändert. |

**Bewusst zeilenbasiert, ohne YAML-Parser** — das ist der Preis dafür, keine
Abhängigkeit zu haben. Für Anker und mehrzeilige Flow-Maps ist das zu grob; das
steht so auch in `docs/`, statt verschwiegen zu werden.

### Dependency-Bot

Liest die **Sperrdateien**, nicht die Wunschlisten: `requirements.txt` (nur
`==`), `package-lock.json` (Format 1 wie 2/3) und `go.mod`. Was er findet,
fragt er bei **OSV.dev** an — der offenen Schwachstellendatenbank, ohne
Schlüssel und ohne Anmeldung.

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

## Die Gegenprobe

```
python3 -m checks.counterproof
```

Sie kopiert das Repo, macht die Bots **absichtlich kaputt** — Redaktion
abgeschaltet, eine Regel übersprungen, `is_pinned` gibt immer `True` zurück,
der OSV-Fehler wird verschluckt — und verlangt, dass die Prüfungen daraufhin
**rot** werden. Zwanzig Mutationen, alle gefangen. Jede Mutation prüft vorher,
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
  cli.py            python3 -m chinook.cli <bot> …
actions/            je ein composite action pro Bot
.github/workflows/  je ein aufrufbarer Workflow pro Bot, dazu die Selbstprüfung
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

## Was noch nicht da ist

Der Aufseher (Etappe 3) und die Website (Etappe 4). Der Aufseher wird drei
Eigenschaften haben, die jetzt schon feststehen:

- **Er zahlt nicht auf ein fremdes Konto.** Der Modellschlüssel kommt aus dem
  Repo-Secret dessen, der ihn einsetzt.
- **Er ist optional.** Fehlt der Schlüssel, laufen die Bots trotzdem.
- **Er hat keine Schreibrechte und keine Werkzeuge.** Er liest zwangsläufig
  fremden PR-Text; alles andere wäre Prompt Injection mit Schreibzugriff. Er
  darf einen Befund einordnen, aber nie löschen — Wegräumen ist eine
  Menschenentscheidung.

---

## Lizenz

MIT, siehe [`LICENSE`](LICENSE). Sicherheitslücken bitte nach
[`SECURITY.md`](SECURITY.md) melden.
