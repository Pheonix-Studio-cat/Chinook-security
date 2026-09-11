# Entscheidungen

Was entschieden ist **und warum**. Ohne das „warum" wird es beim nächsten Mal
neu verhandelt.

---

## Englisch für alles, was nach aussen geht

**Entschieden am 2026-09-10, vom Projektinhaber.** Vorher war alles deutsch —
richtig, solange das Repo privat war, und falsch, seit es öffentlich ist.

Die Trennlinie verläuft nicht zwischen „Code" und „Doku", sondern zwischen
**wer es liest**:

| englisch | deutsch |
| --- | --- |
| `README.md`, die Website | `docs/`, `SECURITY.md`, `CONTRIBUTING.md` |
| Befundtexte, Kommandozeilen-Ausgabe, Berichte | Kommentare im Quelltext |
| Feldnamen und Werte in JSON, Regel- und Mutationsnamen | Commit-Meldungen, PR-Texte |

Was in ein fremdes Repo wandert oder in einem fremden Action-Log landet, ist
englisch. Was nur der Projektinhaber und ich lesen, bleibt deutsch — dort ist
Deutsch das Praktischere, und eine Übersetzung um ihrer selbst willen erzeugt
nur Diff-Rauschen.

**Wo die Regel bewusst endet:** die Namen interner Funktionen (`baue`,
`verbinde`, `regeln`), die CSS-Variablen und Klassennamen der Website
(`--kritisch`, `.gefangen`) und die Variablennamen in den Skripten bleiben
deutsch. Sie sind weder Ausgabe noch Schnittstelle — sie umzubenennen wäre ein
grosser Diff ohne einen einzigen Leser, dem es hilft.

**Ein Bruch am Ausgabeformat gehört dazu.** Die Werte des Aufsehers heissen
jetzt `confirmed`, `probably-real`, `probably-noise`, `unclear`; die Zustände
`triaged`, `skipped`, `failed`; der Berichtsschlüssel `overseer` statt
`aufseher`. Bei Fassung 0.1.0 und ohne fremde Nutzer ist das der richtige
Zeitpunkt — später wäre es einer mit Zuschauern.

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
an einer einfachen Frage: **welche Fassung von Chinook Security lädt er nach?**

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

## Chinook Security stuft Schwachstellen nicht selbst ein

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

## Veroeffentlicht wird ueber `gh-pages`, nicht ueber `actions/deploy-pages`

Der erste Entwurf benutzte `actions/upload-pages-artifact` und
`actions/deploy-pages`. Das setzt voraus, dass im Repo unter *Settings → Pages*
als Quelle **GitHub Actions** eingestellt ist — und genau das war es nicht. Zwei
Läufe scheiterten deshalb an derselben Stelle: `bauen` grün,
`veroeffentlichen` rot.

Die Einstellung liess sich aus dieser Sitzung nicht setzen; der Proxy lässt den
Pages-Pfad der GitHub-API nicht durch (`HTTP 403`), und das Token hat keine
Verwaltungsrechte. Beides gemessen, nicht vermutet.

**Was stattdessen funktioniert hat:** einen Branch `gh-pages` anlegen und
pushen. GitHub hat Pages daraufhin **von selbst aktiviert** — `has_pages` sprang
von `false` auf `true`, festgestellt über die Repo-API vor und nach dem Push.

Der Workflow benutzt jetzt diesen Weg. Er hängt damit an keiner Einstellung, die
jemand vergessen oder umstellen kann, und er braucht keine der beiden
Pages-Actions.

Jeder Lauf schreibt **einen einzelnen Commit ohne Vorgeschichte** und setzt den
Branch mit `--force`: der Inhalt ist erzeugt, eine Historie darauf wäre Ballast,
und ein fester Ausgangspunkt macht den Lauf wiederholbar. Gepusht wird über die
Zugangsdaten, die `actions/checkout` bereits eingerichtet hat — kein Token in
einer Adresse, die in einem Protokoll landen könnte. Nur dieser eine Job
bekommt `contents: write`.

**Was das über den ersten Entwurf sagt:** die Bauart war nicht falsch, aber sie
verlagerte eine Voraussetzung in eine Einstellung, die im Repo unsichtbar ist.
Dieselbe Lehre wie bei den aufrufbaren Workflows — was nicht im Repo steht,
kann das Repo nicht sicherstellen.

---

## Die Website wird erzeugt, nicht gepflegt

Jede Regel auf der Seite kommt aus `regeln()` des Bots, der sie anwendet. Es
gibt keine zweite, handgepflegte Liste — sie würde driften, und die Seite
behauptete dann etwas, das kein Bot tut.

Wo die Schwere vom Zusammenhang abhängt und deshalb keine Tabelle im Code
existiert (Workflow-Bot), gibt es eine `REGELN`-Beschreibung — **und eine
Prüfung, die sie gegen die Regeln hält, die der Bot gegen seine Fixtures
tatsächlich meldet.** Eine Beschreibung, die driften darf, driftet.

Die Seite lädt nichts nach: kein Stylesheet, keine Schrift, kein Skript von
woanders. Eine Seite, die ein Sicherheitswerkzeug beschreibt, holt keinen Code
von fremden Adressen — und die eigene Regel „Fremd-Actions festlegen" gälte
sonst überall außer auf der eigenen Seite.

Und sie zeigt, was sie weiß: liegt kein Ergebnis der Gegenprobe vor, sagt sie
das. Eine entkommene Mutation wird angezeigt, nicht weggelassen. Der
Veröffentlichungs-Workflow fährt die Gegenprobe **vor** dem Bauen; ist sie rot,
wird nichts veröffentlicht.

---

## Der Aufseher darf einordnen, nie entfernen — und das steht im Code, nicht im Prompt

Die Zusicherung „kein Befund geht verloren" hängt **nicht** daran, dass das
Modell sich an den Systemtext hält. Sie hängt daran, wie `verbinde()` gebaut
ist: die Ergebnisliste entsteht aus den **Befunden**, nie aus der Antwort.

Was das Modell schickt, wird gegen die Liste der übergebenen Fingerabdrücke
geprüft und gegen die vier erlaubten Einschätzungen. Alles andere fällt weg.
Ein Modell, das „geloescht" zurückgibt oder einen Befund erfindet, erreicht
damit genau nichts.

Der Systemtext sagt dasselbe — aber er ist die Bitte, nicht die Zusicherung.
Sechs Prüfungen fahren die Angriffe (leere Antwort, zu wenige Einträge,
erfundener Fingerabdruck, erfundene Einschätzung, Müll in der Liste,
Steuerzeichen), und fünf Mutationen halten sie fest.

---

## Der Aufseher endet mit `0`, wenn er nicht laufen konnte — anders als der Dependency-Bot

Beim Dependency-Bot heisst ein misslungener Abruf `2`: „der Lauf beweist
nichts". Beim Aufseher heisst er `0`. Das ist kein Widerspruch.

Der Dependency-Bot **fällt ein Urteil** — gibt es bekannte Schwachstellen oder
nicht. Ohne Antwort hat er keines, und ein grüner Haken wäre eine Lüge.

Der Aufseher fällt **keins**. Die Bots haben ihres bereits gefällt, ihre
Rückgabewerte stehen, und ihre Befunde stehen unverändert im Bericht. Was
fehlt, ist die Sortierhilfe. Der Bericht sagt das ausdrücklich
(`aufseher.status`), statt es zu verschweigen.

Wer ohne Einordnung nicht weitermachen will, nimmt `--require`; dann ist es
eine `2`. Eine Mutation prüft, dass `--require` auch wirkt.

---

## Der Aufseher spricht die Anthropic-Messages-API

Eine Form, nicht zwei. Zwei Anbieter-Formen hiessen zwei Code-Pfade, und ein
zweiter Pfad, der nur halb geprüft ist, ist schlechter als keiner.

Standardmodell ist `claude-opus-5`. `--model` und `--api-url` sind da, weil man
sie zum Prüfen braucht und weil ein anderes Anthropic-Modell eine Zeile
Änderung sein soll. Ein Anbieter mit anderer Request-Form braucht mehr — das
steht als Grenze in `grenzen.md` und als offener Punkt da, nicht als
Halbimplementierung im Code.

Kein SDK: die Abhängigkeitsfreiheit gilt auch hier. Der Aufruf ist ein
`urllib`-POST.

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

## Die eigenen Actions sind auf Commits festgelegt

Erledigt am 2026-09-09. Jede `uses:`-Zeile in `.github/workflows/` zeigt auf
einen vollen Commit-SHA, mit dem lesbaren Tag als Kommentar dahinter — genau
das, was der Workflow-Bot von jedem verlangt.

Die SHAs sind **vom Remote geholt**, nicht aus dem Gedächtnis:

```
git ls-remote https://github.com/actions/checkout refs/tags/v4
```

Vorher stand hier, dass sie fehlen, weil kein verifizierter vorlag — einen zu
erfinden, damit die eigene Prüfung schöner aussieht, war keine Option. Der
Eintrag bleibt als Beleg dafür stehen, dass „ich weiß es nicht" ein
vollständiger Zustand ist, bis man es weiß.

Zwei Prüfungen halten es: der Workflow-Bot läuft über die eigenen Workflows
jetzt mit Schwelle `info` — also ohne jede Nachsicht —, und eine zweite geht
jede `uses:`-Zeile durch und verlangt einen 40-stelligen SHA.

---

## Der Name ist „Chinook Security", der Bezeichner bleibt `chinook`

Festgelegt am 2026-09-10 vom Projektinhaber. Das Projekt heisst **Chinook
Security**. Vorher stand hier und überall „Chinook" — kürzer, und das Repo
heisst ohnehin `Chinook-security`. Das ist kein Grund.

Umbenannt wurde, was der Name als **Anzeige** ist: die Überschrift der README
und ihr Fliesstext, Titel und Kopf der Website, die `name:`-Zeilen der sechs
Actions — die stehen in der Actions-Oberfläche fremder Repos —, die
Beschreibung der Kommandozeile, der Titel des JSON-Schemas, die Kommentare.

**Die Bezeichner bleiben.** Sie sind Adressen, keine Namen:

| Bezeichner | warum er bleibt |
| --- | --- |
| `chinook/`, `python -m chinook.cli` | Importpfad. Eine Umbenennung bricht jeden Aufruf in den sechs Actions. |
| `prog="chinook"` | das Kommando, das man tippt |
| `CHINOOK_AI_TOKEN` | Repo-Secret. Ein neuer Name zwingt jeden Nutzer, es neu anzulegen. |
| `Pheonix-Studio-cat/Chinook-security` | die Repo-Adresse, auf die `uses:` in fremden Repos zeigt |

Dieselbe Trennung wie bei „PostgreSQL" und `psql`, oder „Node.js" und `node`.
Der Anzeigename darf sich ändern, ohne dass jemandes Aufruf bricht.

Wer die Bezeichner mitziehen will, muss es ausdrücklich sagen: das ist ein
Bruch für jeden, der die Bots schon eingebaut hat, und anders als der Bruch am
Ausgabeformat lässt er sich nicht durch eine Zeile in der README auffangen.

**Dabei gefunden:** die gesamte `--help`-Ausgabe war bei der
Englisch-Umstellung deutsch geblieben, ebenso die Beschreibungstexte im
JSON-Schema. Beides ist jetzt englisch. Die Lehre steht im Gedächtnis-Repo als
Fehler Nr. 19: *wer die Ausgabe eines Werkzeugs übersetzt, ruft das Werkzeug
danach auf.* Den Quelltext zu lesen genügt nicht — `help="..."` sieht nicht wie
Prosa aus.

---

## Der Gegenproben-Bot: das eigene Verfahren nach aussen gedreht

Die Gegenprobe war von Anfang an das, was Chinook Security von anderen
Sicherheitswerkzeugen unterscheidet -- und sie prueft bis jetzt nur die eigenen
Bots. Der Gegenproben-Bot richtet dasselbe Verfahren auf ein **fremdes** Repo:
er bricht dessen Code absichtlich und laesst dessen eigene Tests laufen.

**Warum das ein Sicherheitsbefund ist und nicht bloss ein Testwerkzeug.** Jeder
andere Bot hier sagt, was im Code steht. Dieser sagt, was die Pruefungen nicht
merken wuerden. Eine gruene Pruefsuite, die eine entschaerfte
Berechtigungspruefung durchwinkt, sieht genauso aus wie eine, die sie faengt --
und genau diese Sorte Luecke ist die teure.

### Vier Entscheidungen, die dabei fielen

**1. Rote Vorlage heisst 2, nicht 0.** Laeuft die Pruefsuite schon vorher rot,
ist "gefangen" nicht von "war schon kaputt" zu unterscheiden. Der Bot mutiert
dann gar nicht erst und meldet `Unprovable`. Dasselbe bei fehlendem
Testkommando und bei nichts Mutierbarem.

**2. Der Befund traegt nie den Quelltext.** In `if token == "..."` steckt ein
Geheimnis, und der Bericht landet in einem fremden Action-Log. Gemeldet werden
Ort und Operator. Die erste Fassung verletzte das: `return-forced-true` schrieb
den urspruenglichen Rueckgabeausdruck mit. Gefangen hat es eine Pruefung, die
genau danach sucht -- sie steht jetzt in der allgemeinen Fassung da und gilt
fuer **jeden** kuenftigen Operator, nicht nur den einen bekannten Fall.

**3. Keine Shell.** Der Bot bekommt ein Kommando von aussen und fuehrt es aus --
das ist sein Zweck. Die Shell dazwischen liess sich aber vermeiden, und der
eigene Code-Bot hat das angemahnt, als sie noch mitlief. Die Regel zu
entschaerfen waere der falsche Weg gewesen; `shlex.split` und ein Aufruf ohne
Shell haben nichts gekostet: `npm test`, `vitest run`, `bash tests/run.sh`,
`python3 -m unittest discover` brauchen keine. Wer wirklich eine will, schreibt
`sh -c "..."` hin und sieht sie dann auch in seiner Workflow-Datei stehen.

**4. Die Auswahl ist bestimmt, nicht zufaellig.** Zwei Laeufe ueber denselben
Stand pruefen dieselben Mutationen, sicherheitsnahe zuerst. Reihum ueber die
Dateien, damit eine einzige grosse nicht das ganze Budget frisst und der Rest
ungeprueft bleibt, ohne dass es auffaellt. Ein Bot, der jedes Mal etwas anderes
misst, ist in einer CI nicht zu gebrauchen.

### Python ueber den Syntaxbaum, JavaScript zeilenweise

Fuer Python sagt `ast` (Standardbibliothek, also keine Abhaengigkeit), **wo**
etwas steht; ersetzt wird im Text. `ast.unparse` wuerde die ganze Datei neu
schreiben und dabei Kommentare und Formatierung verlieren -- das waere ein
zweiter, ungewollter Unterschied, und ein zweiter Unterschied macht die Messung
wertlos.

Fuer JavaScript und TypeScript gibt es keinen Parser in der
Standardbibliothek. Also zeilenweise, dieselbe Entscheidung wie beim
Workflow-Bot. Der Preis ist Genauigkeit, und er wird bewusst in die **sichere**
Richtung bezahlt: eine Mutation, die Unsinn erzeugt, laesst die Pruefsuite
umfallen und gilt als gefangen -- das kostet Budget, meldet aber nichts
Falsches. Gefaehrlich waere der andere Fall, und deshalb werden Kommentare und
Zeichenketten ausgelassen, lieber einmal zu oft.

### Was der neue Bot nebenbei aufgedeckt hat

Die Seite schrieb **"5 bots" von Hand** -- auf einer Seite, deren erklaerter
Punkt es ist, aus der Quelle erzeugt und nicht gepflegt zu sein. Ebenso die
Liste der Bot-Module in der zugehoerigen Pruefung. Beides ist jetzt abgeleitet,
und zwei Mutationen halten es fest.

Und zwei bestehende Mutationen waren **mehrdeutig**: ihr Suchtext kam mehrfach
in `cli.py` vor, `replace(..., 1)` traf die erste Stelle statt der gemeinten.
Eine davon war es von Anfang an. Die Gegenprobe weist Mehrdeutigkeit jetzt
zurueck, statt sie stillschweigend hinzunehmen.
