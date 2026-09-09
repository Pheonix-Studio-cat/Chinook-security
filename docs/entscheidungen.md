# Entscheidungen

Was entschieden ist **und warum**. Ohne das „warum" wird es beim nächsten Mal
neu verhandelt.

---

## Keine Abhängigkeiten, nur Standardbibliothek

Ein Sicherheitswerkzeug mit dreihundert transitiven Paketen ist selbst eine
Angriffsfläche — und es läuft in fremden Repos, mit deren Rechten. Dazu kommt:
ein Lockfile will gepflegt werden, und der Projektinhaber arbeitet vom iPad
ohne Kommandozeile.

Der Preis ist benannt, nicht verschwiegen: der Workflow-Bot liest Zeilen statt
YAML-Struktur. Die Grenze steht in `grenzen.md`.

---

## Ein Befund trägt nie den gefundenen Wert

Kein Präfix, kein Hash, nur Regel und Länge.

- Ein Präfix wäre bei einem Passwort ein echtes Leck.
- Ein Hash wäre bei einem schwachen Passwort ein Orakel.
- Das Action-Log eines öffentlichen Repos liest jeder.

Ein Secret-Bot, der den Fund ausdruckt, ist selbst das Leck. Die Zusage hängt
an `findings.redact()` und ist mit der Mutation `redaktion-abgeschaltet`
gegengeprüft.

---

## Composite actions statt aufrufbarer Workflows — mit Beleg

Ein aufrufbarer Workflow wäre für den Nutzer eine Zeile statt vier. Er scheitert
an einer einfachen Frage: **welche Fassung von Chinook lädt er nach?**

`actions/checkout` holt in einem aufrufbaren Workflow das Repo des *Aufrufers*,
nicht das eigene. Der Wert dafür wäre `github.job_workflow_sha` — der Commit
genau der Workflow-Datei, die aufgerufen wurde. Er war in **allen drei
geprüften Fällen leer**:

| Fall | `job_workflow_sha` |
| --- | --- |
| `uses: ./.github/workflows/license-bot.yml` (lokal) | leer |
| `uses: Pheonix-Studio-cat/Chinook-security/…@<sha>` aus demselben Repo | leer |
| Aufruf aus einem **anderen** Repo | leer |

Der dritte Fall ist der entscheidende, und er ließ sich nur von aussen prüfen:
das Gedächtnis-Repo des Projektinhabers hat den Workflow aufgerufen, und der
Schritt „Fassung feststellen" brach ab.

Ohne den Wert bliebe ein **fest verdrahteter Ref**. Dann käme der Bot aus einer
anderen Fassung als der, die der Nutzer mit `@…` festgelegt hat — grün, und
falsch, und niemand merkt es. Genau die Sorte stiller Fehler, gegen die dieses
Projekt gebaut ist. Also: keine aufrufbaren Workflows.

Eine composite action hat das Problem nicht: `github.action_path` zeigt auf den
Quelltext in genau der Fassung hinter dem `@`. Vier Zeilen statt einer, dafür
stimmt die Fassung. Nachgewiesen aus einem fremden — und privaten — Repo.

**Der Wächter war die Arbeit wert.** Ein leerer `ref` hätte `actions/checkout`
stillschweigend den Standard-Branch holen lassen. Stattdessen brach der Lauf ab
und sagte, warum. Ohne diese fünf Zeilen wäre die Bauart als „funktioniert"
durchgegangen.

---

## Rückgabewert 2: „der Lauf beweist nichts"

`0` sauber, `1` Befunde — und `2`, wenn der Lauf nichts feststellen konnte.

Der Fall, für den es die `2` gibt: der Dependency-Bot fragt OSV.dev. Kommt die
Abfrage nicht durch, oder passt die Antwort nicht zur Anfrage, dann **weiß**
der Bot nichts. Ein leeres Ergebnis daraus zu machen, wäre genau die Prüfung,
die grün ist und nichts beweist.

Zwei Mutationen halten das fest: eine verschluckt den Netzfehler, eine gibt
statt der `2` eine `0` zurück. Beide werden gefangen.

---

## Chinook stuft Schwachstellen nicht selbst ein

Jede bekannte Schwachstelle ist `high`. Kein CVSS, keine eigene Zahl.

Die Sammelabfrage bei OSV gibt nur Kennungen zurück, keine Vektoren. Aus dem,
was wir nicht geholt haben, eine Schwere abzuleiten, wäre eine erfundene
Angabe. Das Einordnen — was in **diesem** Repo tatsächlich erreichbar ist —
ist die Aufgabe des Aufsehers in Etappe 3, und dort mit einem Menschen
dahinter.

---

## Der Lizenz-Bot stellt keine Rechtstatsache fest

Er sagt nie, unter welcher Lizenz etwas steht. Er sagt, was **erklärt** ist, wo
**nichts** erklärt ist, und wo Erklärung und beiliegende Datei
**auseinandergehen**. Unklares heißt *License status requires verification*.

Die Texterkennung ist ausdrücklich eine Heuristik und dient **nur** dazu, einen
Widerspruch zu melden — nie dazu, eine Lizenz zu behaupten. Eine Prüfung geht
die Befunde durch und stellt sicher, dass keiner eine Lizenz behauptet.

---

## Die Code-Proben liegen als JSON

Aus demselben Grund, aus dem die Secret-Fixtures zur Laufzeit entstehen: eine
`.py`-Datei mit `eval(eingabe)` würde der Code-Bot beim Lauf über sein eigenes
Repo melden. Als JSON wird sie nicht gescannt, ist aber trotzdem im Repo
lesbar und im Diff nachvollziehbar.

Dasselbe gilt für die Regeltexte selbst: kein Titel und keine Erklärung
schreibt ein Muster aus, das die Regel sucht. Der erste Entwurf tat es, und der
Bot meldete sich prompt selbst — sieben Treffer in der eigenen Regeltabelle.

---

## Der Aufseher zahlt nicht auf ein fremdes Konto

Der Modellschlüssel kommt aus dem Repo-Secret dessen, der den Bot einsetzt —
nicht aus einem Schlüssel dieses Projekts. Eine öffentliche Action, die auf ein
fremdes Guthaben rechnet, ist eine offene Brieftasche.

Daraus folgt: **der Aufseher ist optional.** Fehlt der Schlüssel, laufen die
Bots trotzdem. Ein Scanner, der ausfällt, weil ein Modell nicht antwortet, ist
schlechter als keiner.

---

## Der Aufseher bekommt keine Werkzeuge und keine Schreibrechte

Er liest zwangsläufig fremden Text: PR-Titel, Kommentare, Paketnamen, Quelltext
aus einem Fork. Alles davon kann eine Anweisung enthalten. Ein Modell mit
Schreibrechten, das solchen Text liest, ist Prompt Injection mit Schreibzugriff.

Also: Befunde hinein, Einordnung heraus. Und er darf einen Befund **einordnen,
aber nie löschen** — Wegräumen ist eine Menschenentscheidung.

---

## Secret-Fixtures werden zur Laufzeit erzeugt

Ein formatgültiges Token als Datei im Repo wird von GitHubs Push-Protection
blockiert, von Scannern gemeldet, und wer die Datei kopiert, verteilt etwas,
das wie ein Schlüssel aussieht. Deshalb setzt `checks/fixtures.py` die Werte
aus Teilen zusammen und legt sie nur im Temp-Verzeichnis des Laufs ab.

Dasselbe gilt im Quelltext selbst: sogar die Kopfzeile eines privaten
RSA-Schlüssels steht dort zerlegt, sonst fände der Secret-Bot sein eigenes
Fixture-Modul. Diese Datei enthält sie deshalb auch nicht ausgeschrieben —
der Bot hat es beim ersten Entwurf sofort gemeldet.

---

## Kaputte Workflows liegen außerhalb von `.github/workflows/`

Sonst führt GitHub sie aus. Eine Prüfung hält das fest.

---

## Der eigene `actions/checkout` ist noch nicht auf einen SHA festgelegt

Der Workflow-Bot meldet das an den eigenen Workflows — inzwischen elfmal, als
Hinweis, weil `actions/*` GitHub selbst gehört. Es bleibt trotzdem offen: der SHA wird
eingetragen, sobald er verifiziert vorliegt. Einen SHA zu erfinden, damit die
eigene Prüfung schöner aussieht, ist keine Option.
