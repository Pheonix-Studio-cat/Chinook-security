# Dauerauftrag

Was hier steht, arbeitet Claude **jeden Montag** von selbst ab. Geändert wird
es wie jede andere Datei: bearbeiten, committen, fertig. Beim nächsten Lauf
gilt der neue Text.

> **Wer das liest:** du bist Claude, per GitHub Action in
> `Pheonix-Studio-cat/Chinook-security` gestartet. Lies zuerst `CLAUDE.md`
> und `docs/`, falls vorhanden. Arbeite die Punkte unten der Reihe nach ab.
> **Findest du nichts zu tun, ist das ein gültiges Ergebnis** — sag es und
> öffne keinen leeren Pull Request.

---

## 1. Driftet die README gegenüber dem Quelltext?

**Das ist der wichtigste Punkt, weil es schon passiert ist.** Die README stand
einmal auf „146 Prüfungen und 25 Mutationen", während es in Wahrheit 162 und
31 waren. Niemandem war es aufgefallen, weil beide Zahlen von Hand gepflegt
sind.

Zähle nach und vergleiche mit dem, was in der README steht:

```
python3 -m unittest discover -s checks -t . -q 2>&1 | grep "^Ran"
python3 -c "from checks.counterproof import MUTATIONEN; print(len(MUTATIONEN))"
python3 -c "
from webseite import build
print(sum(len(m.regeln()) for m, _, _ in build.BOTS), 'Regeln,', len(build.BOTS), 'Bots')"
```

Stimmt eine Zahl nicht, **korrigiere sie in der README** und öffne einen Pull
Request. Stimmen alle, sag das und tu nichts.

## 2. Sind alle Actions auf einen Commit festgelegt?

Jede `uses:`-Zeile in `.github/workflows/` und in `actions/` muss auf einen
40-stelligen Commit zeigen, nicht auf einen Zweig oder ein Tag. Das ist genau
das, was der Workflow-Bot bei anderen anmahnt.

```
python3 -m chinook.cli workflow-bot --path . --fail-on info
```

**Findest du eine ungepinnte Action: hol den Commit mit `git ls-remote`,
erfinde ihn nie.** Eine falsche 40-stellige Zahl sieht genauso echt aus wie
eine richtige.

## 3. Hält die Gegenprobe noch?

```
python3 -m unittest discover -s checks -t . -q
python3 checks/counterproof.py
```

Ist eine Mutation **entkommen**, ist die zugehörige Prüfung wertlos geworden.
Das ist ein Befund, kein Schönheitsfehler: **öffne einen Pull Request, der die
Prüfung repariert**, und beschreibe im Text, was sie vorher nicht bewiesen hat.

Ein entkommener Fall kann auch an einer schlecht gebauten Mutation liegen —
eine, die den Text ändert und nicht das Verhalten. Prüfe beides, bevor du die
Prüfung beschuldigst.

## 4. Sagen die eigenen Bots etwas über das eigene Repo?

```
python3 -m chinook.cli secret-bot   --path . --fail-on info --history
python3 -m chinook.cli code-bot     --path . --fail-on info
python3 -m chinook.cli license-bot  --path . --fail-on info
```

Ein Befund im eigenen Repo wiegt doppelt: ein Sicherheitswerkzeug, das die
eigenen Regeln nicht einhält, ist kein Argument.

**Entschärfe nie eine Regel, damit der eigene Lauf grün wird.** Behebe die
Ursache oder melde sie. Das ist in diesem Projekt schon dreimal die richtige
Entscheidung gewesen.

---

## Was du nicht tust

- **Nichts erfinden.** Keine Zahlen, keine Commit-SHAs, keine Benchmarks. Was
  du nicht gemessen hast, schreibst du nicht hin.
- **Kein Geheimnis in einen Bericht.** Befunde tragen nie den gefundenen Wert
  — dieselbe Regel, die die Bots selbst befolgen.
- **Nichts direkt auf `main`.** Immer ein Zweig und ein Pull Request; gemergt
  wird hier vom Projektinhaber.
- **Keinen leeren Pull Request.** Nichts gefunden heisst nichts gefunden.

## Was einen guten Pull-Request-Text ausmacht

Was war, warum es so war, woran man es wiedererkennt, und die Regel in einem
Satz. Ein Text, den man nur versteht, wenn man dabei war, ist keiner.
