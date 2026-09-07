"""Erzeugt die absichtlich kaputten Faelle zur Laufzeit.

**Warum nicht als Datei im Repo?** Ein Fixture mit einem formatgueltigen Token
ist selbst ein Problem: GitHubs Push-Protection blockiert den Push, Scanner
melden das Repo, und wer die Datei kopiert, verteilt einen Sting, der wie ein
Schluessel aussieht. Also werden die Zeichenketten hier aus Teilen
zusammengesetzt und liegen nur im Temp-Verzeichnis des Laufs.

Die Werte sind erfunden und gehoeren zu keinem Konto.
"""

from __future__ import annotations

import os
import subprocess
import tempfile

# Aus Teilen zusammengesetzt, damit im Quelltext nichts steht, das ein Scanner
# fuer einen echten Schluessel haelt.
FAKE = {
    "aws-access-key-id": "AKIA" + "QWERTYUIOPASDFGH",
    "github-token": "ghp_" + "0a1B" * 9,
    "huggingface-token": "hf_" + "wXyZ" * 9,
    "anthropic-key": "sk-ant-" + "api03-" + "kLmN" * 8,
    "openai-key": "sk-" + "pQrS" * 9,
    "slack-token": "xoxb-" + "1234567890-" + "abcdefghij",
    "google-api-key": "AIza" + "SyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456",
    # Auch dieser Kopf wird zerlegt -- sonst faende der Secret-Bot sein
    # eigenes Fixture-Modul.
    "private-key-block": "-----BEGIN RSA " + "PRIVATE KEY" + "-----",
    "assigned-credential": "Zg7-" + "Tp41xQv9Ls",
}


def secret_line(rule: str) -> str:
    """Eine Zeile, in der genau diese Regel greifen muss."""
    value = FAKE[rule]
    if rule == "private-key-block":
        return value
    if rule == "assigned-credential":
        return f'api_key = "{value}"'
    return f'wert = "{value}"'


CLEAN_FILE = (
    "# Diese Datei ist absichtlich sauber.\n"
    'api_key = os.environ["API_KEY"]\n'
    'password = "changeme"          # Platzhalter, kein Fund\n'
    'token = "${DEPLOY_TOKEN}"      # Interpolation, kein Fund\n'
    'beispiel = "your-key-here-1234567890"\n'
)


def write_broken_tree(root: str, rule: str) -> str:
    """Legt unter `root` eine Datei an, in der `rule` greifen muss."""
    path = os.path.join(root, "src")
    os.makedirs(path, exist_ok=True)
    target = os.path.join(path, "konfiguration.py")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("# Kaputt mit Absicht.\n")
        handle.write(secret_line(rule) + "\n")
    return target


def write_clean_tree(root: str) -> str:
    path = os.path.join(root, "src")
    os.makedirs(path, exist_ok=True)
    target = os.path.join(path, "konfiguration.py")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(CLEAN_FILE)
    return target


def git(root: str, *args: str) -> None:
    subprocess.run(["git", "-C", root, *args], check=True, capture_output=True, text=True)


def make_repo_with_deleted_secret(rule: str = "aws-access-key-id") -> tempfile.TemporaryDirectory:
    """Ein Git-Repo, dessen Arbeitsbaum sauber ist und dessen History nicht.

    Genau der Fall, den ein reiner Diff-Scan durchgehen laesst.
    """
    handle = tempfile.TemporaryDirectory()
    root = handle.name
    git(root, "init", "--quiet", "--initial-branch=main")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "user.name", "Fixture")
    write_broken_tree(root, rule)
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "Erster Commit mit dem Fund")
    write_clean_tree(root)
    git(root, "add", "-A")
    git(root, "commit", "--quiet", "-m", "Aufgeraeumt -- aber nur im Arbeitsbaum")
    return handle
