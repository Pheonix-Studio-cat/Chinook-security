# Mitarbeiten

## Die eine Regel

**Jede neue Regel braucht ein absichtlich kaputtes Fixture und einen sauberen
Gegenfall.** Eine Regel, die nur gegen sauberen Code gelaufen ist, hat nichts
bewiesen.

Und: **jede neue Prüfung braucht eine Mutation in `checks/counterproof.py`**,
die zeigt, dass die Prüfung anschlägt, wenn der Bot kaputt ist. Bleibt sie
grün, ist sie wertlos — genau das meldet die Gegenprobe dann auch.

## Ein Lauf

```
python3 -m unittest discover -s checks -t . -v   # die Prüfungen
python3 -m checks.counterproof                   # die Gegenprobe
python3 -m chinook.cli secret-bot   --path . --history --fail-on critical
python3 -m chinook.cli workflow-bot --path . --fail-on medium
```

Dasselbe läuft in `.github/workflows/selfcheck.yml` bei jedem Pull Request.

## Grenzen, die bleiben

- **Keine Abhängigkeiten.** Nur Standardbibliothek. Wer eine braucht, begründet
  sie in `docs/entscheidungen.md` — und rechnet damit, dass die Antwort Nein ist.
- **Kein Fixture mit einem formatgültigen Token als Datei.** Solche Werte werden
  in `checks/fixtures.py` zur Laufzeit aus Teilen zusammengesetzt. Ein echtes
  Token-Format im Repo wird von der Push-Protection blockiert und von Scannern
  gemeldet.
- **Kaputte Workflows liegen unter `fixtures/`**, nie unter `.github/workflows/`
  — sonst führt GitHub sie aus.
- **Keine erfundenen Zahlen.** Keine Erkennungsraten, keine Vergleiche, keine
  Benchmarks ohne Messung, die im Repo nachvollziehbar ist.

## Ein neuer Bot

1. `chinook/<name>_bot.py` mit `run(root, excludes) -> list[Finding]`.
2. In `chinook/cli.py` unter `BOTS` eintragen.
3. `actions/<name>-bot/action.yml` nach dem Muster der beiden vorhandenen —
   Eingaben gehen über `env`, nie als `${{ }}` in den Skripttext.
4. Fixtures, Prüfungen, Mutationen.
5. In `README.md` und `docs/` beschreiben, samt der Grenzen.

## Sprache

Deutsch in Dokumentation, Kommentaren und Commit-Meldungen. Bezeichner im Code
bleiben englisch.
