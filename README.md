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

Gebaut ist Etappe 1: das gemeinsame Befund-Format, zwei Bots, die Gegenprobe.

| Teil | Zustand |
| --- | --- |
| Befund-Format (JSON + SARIF) | ✅ `chinook/findings.py`, `schema/finding.schema.json` |
| **Secret-Bot** | ✅ Arbeitsbaum und Git-History |
| **Workflow-Bot** | ✅ die Actions selbst |
| Gegenprobe | ✅ 11 Mutationen, alle gefangen |
| Dependency-, Code-, Lizenz-Bot | ⏳ Etappe 2 |
| Aufseher (KI-Schicht) | ⏳ Etappe 3 |
| Website | ⏳ Etappe 4 |

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
```

> ⚠️ `@main` ist zum Ausprobieren. Für den Dauerbetrieb auf einen Commit-SHA
> festlegen — genau das, was der Workflow-Bot bei jeder anderen Action
> anmahnt. Sobald es einen `v1`-Tag gibt, steht er hier.

### Die Bots einzeln

| Eingabe | Secret-Bot | Workflow-Bot | Bedeutung |
| --- | --- | --- | --- |
| `path` | ✅ | ✅ | Wurzel des zu prüfenden Verzeichnisses (Standard `.`) |
| `exclude` | ✅ | ✅ | Pfade, kommagetrennt |
| `history` | ✅ | — | auch die Git-History prüfen, braucht `fetch-depth: 0` |
| `fail-on` | ✅ | ✅ | ab welchem Schweregrad der Schritt fehlschlägt (Standard `high`) |
| `report` | ✅ | ✅ | Pfad des JSON-Berichts |
| `sarif` | ✅ | ✅ | Pfad des SARIF-Berichts, leer = keiner |

Beide geben `report` und `total` als Output zurück.

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

---

## Die Gegenprobe

```
python3 -m checks.counterproof
```

Sie kopiert das Repo, macht den Bot **absichtlich kaputt** — Redaktion
abgeschaltet, eine Regel übersprungen, `is_pinned` gibt immer `True` zurück —
und verlangt, dass die Prüfungen daraufhin **rot** werden. Elf Mutationen,
alle gefangen. Jede Mutation prüft vorher, dass sie die Datei überhaupt
verändert hat; ohne das könnte eine wirkungslose Mutation ein Urteil fällen.

Der Grund für den ganzen Aufwand steht oben: *eine Prüfung, die nie gegen einen
absichtlich kaputten Zustand gelaufen ist, ist keine Prüfung.*

---

## Aufbau

```
chinook/            die Bots, nur Standardbibliothek
  findings.py       das gemeinsame Befund-Format, JSON und SARIF
  secret_bot.py
  workflow_bot.py
  cli.py            python3 -m chinook.cli <bot> …
actions/            je ein composite action pro Bot
checks/             Prüfungen und die Gegenprobe
fixtures/workflows/ absichtlich kaputte Workflows — außerhalb von
                    .github/workflows, damit GitHub sie nicht ausführt
schema/             das Befund-Schema als JSON Schema
docs/               Regeln im Einzelnen, Grenzen, Entscheidungen
```

Die Fixtures für Geheimnisse werden **zur Laufzeit erzeugt**
(`checks/fixtures.py`), nicht als Datei abgelegt: ein formatgültiges Token im
Repo wird von GitHubs Push-Protection blockiert und von Scannern gemeldet.

---

## Was noch nicht da ist

Dependency-, Code- und Lizenz-Bot (Etappe 2), der Aufseher (Etappe 3) und die
Website (Etappe 4). Der Aufseher wird drei Eigenschaften haben, die jetzt schon
feststehen:

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
