# Chinook Security

**Security bots as GitHub Actions — and an AI layer that keeps the bots
honest.** Open source, MIT.

A security tool that runs green without checking anything is worse than none:
it creates trust that carries nothing. That is why the **counterproof** is not
an extra in Chinook Security but the core — every rule is run against a deliberately
broken case, and every check is run against a deliberately broken bot. Whatever
stays green is treated as worthless, and said so.

> **English is the default; German where it is more practical.** Everything a
> stranger reads is English — this README, the website, the findings the bots
> emit, the field names in the reports. `docs/`, the code comments and the
> commit messages stay German, because that is the project owner's language and
> nobody else needs them.

---

## Status

**All five stages are built:** the shared finding format, six bots, the
counterproof, one composite action per bot, the **overseer** that triages the
findings and keeps the bots honest, the **website** and the **weekly run**.

| Part | State |
| --- | --- |
| Finding format (JSON + SARIF) | ✅ `chinook/findings.py`, `schema/finding.schema.json` |
| **Secret bot** | ✅ working tree and git history |
| **Workflow bot** | ✅ the Actions themselves |
| **Dependency bot** | ✅ lockfiles against OSV.dev |
| **Code bot** | ✅ 12 patterns in Python, JavaScript, shell |
| **Licence bot** | ✅ what is missing and what disagrees |
| **Counterproof bot** | ✅ breaks your code, runs your tests, reports what stayed green |
| Composite action per bot | ✅ proven from a foreign repository too |
| **Overseer** (AI layer) | ✅ triages, never removes |
| Counterproof | ✅ 47 mutations, all caught |
| **Website** | ✅ generated from the source, GitHub Pages |
| **Weekly run** | ✅ Mondays, without a commit |

**216 checks, all green. 47 mutations, all caught.**

**No dependencies.** The Python standard library only. A security tool with
three hundred transitive packages is an attack surface itself, and a lockfile
wants maintaining.

---

## Installing

Into the repository you want checked, as `.github/workflows/chinook.yml`:

```yaml
name: Chinook Security
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
      - uses: Pheonix-Studio-cat/Chinook-security/actions/license-bot@main
```

The **counterproof bot** is a separate step, because it needs to know how to run
your tests — and because it costs one test run per mutation:

```yaml
      - uses: Pheonix-Studio-cat/Chinook-security/actions/counterproof@main
        with:
          test-command: "npm test"   # or: vitest run / pytest / bash tests/run.sh
          budget: "20"               # mutations to run; each is a full test run
```

No test command, a red test suite, or nothing it can break — and the step ends
with **2**, not 0. It never reports a clean run it did not earn.

The **overseer** is a separate step, if you want it:

```yaml
      - uses: Pheonix-Studio-cat/Chinook-security/actions/overseer@main
        env:
          CHINOOK_AI_TOKEN: ${{ secrets.CHINOOK_AI_TOKEN }}
        with:
          reports: chinook-secret-bot.json,chinook-code-bot.json
```

Without the secret it is **skipped** and the run stays green — the bots'
findings then stand unchanged. That is deliberate; see below.

> ⚠️ `@main` is for trying it out. For day-to-day use, pin a commit SHA —
> exactly what the workflow bot demands of every other action. Once there is a
> `v1` tag it will be named here.

**Why composite actions and not reusable workflows?** A reusable workflow
(`uses: …/secret-bot.yml@v1`) would be one line instead of four. But it would
have to know which version of Chinook Security to fetch — and there is no usable value
for that: `github.job_workflow_sha` was empty in all three cases tested (local
call, full path within the same repository, call from a foreign repository).
Without it, only a hard-wired ref would remain, which then no longer matches
the caller's `@…`: the bot would come from a different version than the user
pinned, and nobody would notice.

A composite action does not have that problem. It finds its own source through
`github.action_path`, and that source is in **exactly** the version behind the
`@`. Four more lines, and the version is right. Proven: the project owner's
memory repository embeds the secret bot this way, from another — and private —
repository.

### Exit codes

| Value | Meaning |
| --- | --- |
| `0` | nothing found that reaches the threshold |
| `1` | findings at or above the threshold |
| `2` | **the run could not determine anything** — e.g. OSV was unreachable |

The `2` is the reason it exists: a request that did not get through is not an
empty result. It does not count as passing.

### Inputs

| Input | Meaning |
| --- | --- |
| `path` | root of the directory to check (default `.`) |
| `exclude` | paths, comma-separated |
| `history` | **secret bot only:** also check the git history, needs `fetch-depth: 0` |
| `fail-on` | severity at which the step fails (default `high`, licence bot `medium`) |
| `report` | path of the JSON report |
| `sarif` | path of the SARIF report, empty = none |

Every bot returns `report` and `total` as outputs.

To see the findings in GitHub's security view, upload the SARIF file with
`github/codeql-action/upload-sarif`. That needs `security-events: write` — a
permission that belongs **in the individual job**, not at the top of the file.

---

## What the bots find

### Counterproof bot

**Every other bot tells you what is in your code. This one tells you what your
tests would not notice.**

It changes your code on purpose — flips a comparison, turns an `and` into an
`or`, forces a `return` to `true` — then runs **your own test suite**. Whatever
stays green is a behaviour that nothing checks.

```
counterproof-bot: 14 of 20 mutations caught
  38 source file(s), 412 mutation(s) possible
  [high] src/auth.js:31 survived -- boolean-operator-swapped: && -> || (source line not shown)
```

That line says: somebody could weaken the condition in your permission check
and your CI would stay green.

| What | How |
| --- | --- |
| Languages | Python (via the syntax tree), JavaScript and TypeScript (line-based) |
| Test command | yours — `npm test`, `vitest run`, `pytest`, `bash tests/run.sh` |
| Severity | `high` in security-relevant code, `low` elsewhere |
| Cost | one full test run per mutation — `budget` is the dial |

**It refuses to run against a red test suite.** If your tests already fail, a
caught mutation cannot be told apart from an already broken build, so the run
ends with **2** — "proves nothing" — and not with 0.

**And it refuses to report when nothing was caught at all.** If not one
mutation out of the whole budget was caught, the run never showed that your
test command reacts to a code change — so "everything survived" cannot be told
apart from "the command does not exercise this code". That also ends with
**2**, with the surviving mutations printed but explicitly marked as
unreadable. A measurement without a positive control is not a measurement.

The first run in a real CI produced exactly that case:

```
counterproof-bot: 0 of 20 mutations caught
  43 source file(s), 443 mutation(s) possible
```

while another repository, on the same day, produced a healthy one:

```
counterproof-bot: 11 of 20 mutations caught
  33 source file(s), 613 mutation(s) possible
```

Without the control, both would have looked like a list of findings.

> 🔒 **A finding never contains your source.** Reported are the location and the
> operator, never the line that was changed. `if token == "hunter2"` would
> otherwise put the password into the action log — the same rule the secret bot
> follows, and for the same reason. A check holds this for *every* operator, and
> it caught a real leak in the first version of this bot.

**The report always carries the coverage.** `0 survived` means nothing on its
own — it could mean nothing escaped, or that nothing was measured. So the number
of mutations run stands next to it, always.

**The selection is deterministic, not random.** Two runs over the same commit
test the same mutations; security-relevant files come first, and no single large
file can eat the whole budget. A bot that measures something different every
time is useless in CI.

### Secret bot

Nine rules: AWS access key ID, GitHub token, Hugging Face token, Anthropic,
OpenAI, Slack and Google keys, private key blocks, and credentials assigned to
a variable. The last rule runs at medium confidence and lets recognisable
placeholders through (`changeme`, `${VAR}`, `your-key-here`).

**It checks the history too.** A secret sitting in an old commit is not gone
just because the current file is clean — and that is exactly what a diff-only
scan misses.

> 🔒 **A finding never contains the find.** Reported are rule, location and
> length, nothing else — no prefix, no hash. In a public repository anyone can
> read the action log; a secret bot that prints the key it found would be the
> leak itself. A check holds this, and the counterproof shows that the check
> fires when redaction is switched off.

### Workflow bot

| Rule | Severity | What it means |
| --- | --- | --- |
| `pull-request-target-checkout` | critical | `pull_request_target` runs with the target repository's secrets. Checking out the PR head inside it runs foreign code with those secrets. |
| `script-injection` | high | A title or comment is substituted into a `run:` or `script:` block before execution. A backtick in it is then a command. |
| `permissions-write-all` | high | Every step inherits all write permissions, a third-party action included. |
| `unpinned-action` | medium (`actions/*`: info) | A tag can be moved. Then what runs here with this repository's permissions changes. |
| `permissions-missing` | medium | Without `permissions:` the repository defaults apply — configured elsewhere, changeable without this file changing. |

**Deliberately line-based, no YAML parser** — that is the price of having no
dependencies. It is too coarse for anchors and multi-line flow maps; that is
written down in `docs/`, not hidden.

### Dependency bot

Reads the **lockfiles**, not the wish lists. Whatever it finds it asks
**OSV.dev** about — the open vulnerability database, no key and no sign-up.

| File | Ecosystem |
| --- | --- |
| `requirements.txt` (only `==`), `poetry.lock` | PyPI |
| `package-lock.json` (format 1 as well as 2/3), `yarn.lock` (v1 and Berry), `pnpm-lock.yaml` | npm |
| `go.mod` | Go |
| `Cargo.lock` | crates.io |
| `composer.lock` | Packagist |

A misspelled ecosystem name would find **nothing** — and nothing looks like
"clean". So `checks/oekosystemprobe.py` asks the real service, during the
self-check, whether OSV knows the names. It works by difference: first it asks
with an invented ecosystem; only if OSV *rejects* that is "not rejected"
evidence.

Two rules: `known-vulnerability` (high) and `dependency-unpinned` (low, only
for `requirements.txt` without `==`).

> 🔴 **A failed request is not an empty result.** If the query does not get
> through, or the answer does not match the request, the run ends with exit
> code **2** — not with a green tick. Whoever could not ask knows nothing.

**Chinook Security does not rate severity itself.** Every known vulnerability is "high",
and the advisory IDs are in the finding. Deriving a number from a CVSS vector
we never fetched would be an invented figure; rating is the overseer's job.

### Code bot

Twelve patterns, separated by file extension:

| Language | What is looked for |
| --- | --- |
| Python | executed text (`eval`/`exec`), shell calls with substituted values, `pickle`, unsafe YAML, disabled TLS verification, `mktemp` |
| JavaScript / TypeScript | executed text, `exec` with an assembled command, `innerHTML`, disabled TLS verification |
| Shell | running what was downloaded (`curl …` piped into a shell), `eval` |

Pattern-based, **without data flow analysis**: it sees *that* a dangerous spot
is there, not *whether* something foreign arrives at it. Rules at medium
confidence are marked as such.

### Licence bot

| Rule | Severity | What it means |
| --- | --- | --- |
| `license-file-missing` | medium | no licence file in the root directory |
| `license-undeclared` | medium | `package.json` or `pyproject.toml` without a licence field |
| `license-link-broken` | medium | the declaration points at a file that does not exist |
| `license-mismatch` | medium | declaration and the accompanying text disagree |
| `license-unrecognised` | info | not a known SPDX identifier — *License status requires verification* |

> ⚖️ **It states no legal fact.** It never says which licence something is
> under — only what is declared, what is missing and what disagrees. Everything
> beyond that is a question for a human. A check holds that no finding claims a
> licence.

---

## The overseer

The AI layer. It has two jobs, and the second is the real one.

**Triage the findings.** One of four assessments per finding — `bestaetigt`
(confirmed), `vermutlich-echt` (probably real), `vermutlich-rauschen` (probably
noise), `unklar` (unclear) — plus a sentence or two of reasoning. Without
triage every scanner rollout suffocates in false positives.

**Keep the bots honest.** `python3 -m checks.counterproof --json …` writes the
counterproof result in machine-readable form: which bot was deliberately
broken, and whether the checks went red as a result. A bot that stays green
against a broken fixture is broken — and then it says so.

### Three properties fixed before a line of it existed

| | |
| --- | --- |
| **It does not spend someone else's money** | The key comes from `CHINOOK_AI_TOKEN` in the repository of whoever runs it. Chinook Security holds none. |
| **It is optional** | Without a key everything else keeps running. A scanner that fails because a model did not answer is worse than none. |
| **It has no tools and no write access** | It inevitably reads foreign text — paths from a fork, package names. A model with tools reading such text is prompt injection with write access. |

### And the guarantee everything hangs on

> 🔒 **No finding gets lost.** The model's answer can only attach a `triage`
> field to a finding. It cannot remove one, change a severity, or invent one.

Technically: the result list is built from the **findings**, never from the
answer. Whatever the model says about an unknown fingerprint is dropped; an
assessment outside the four allowed ones is dropped; the reasoning is stripped
of control characters and truncated. Six checks run exactly these attacks, and
five mutations hold them.

Clearing findings away stays a human decision.

### When it cannot run

| Case | What happens |
| --- | --- |
| no key | `uebersprungen` (skipped), exit code `0` |
| request fails / model declines | `fehlgeschlagen` (failed), exit code `0` |
| the same with `--require` | exit code `2` |

Why `0` here and not `2` like the dependency bot? Because the overseer **passes
no judgement**. The bots have already passed theirs, and their findings stand
unchanged in the report. Whoever will not proceed without triage uses
`--require`.

The call goes to the Anthropic Messages API, default model `claude-opus-5`.
Another model with `--model`; another address with `--api-url`. Other providers
speak a different request shape — that is in `docs/grenzen.md`.

---

## The website

Static, a single HTML file, **generated from the source**:

```
python3 -m webseite.build --gegenprobe chinook-gegenprobe.json
```

Every rule on the page comes from the bot that applies it (`regeln()`). A
hand-maintained list would drift, and the page would then describe something no
bot does. One check holds that every rule is on the page — and a second that
the rule tables match **exactly** the rules the bots report against their
fixtures.

The page **loads nothing**: no stylesheet, no font, no script from anywhere
else. A page describing a security tool does not fetch code from foreign
addresses. That is checked too.

And it shows the **state of the counterproof** — which mutation was caught and
which was not. If no result is available it says so instead of claiming
something. The build runs on every merge to `main` and once a week.

Publishing goes through the **`gh-pages`** branch, not through
`actions/deploy-pages`: that would have required a repository setting nobody
can see in the source. Creating the branch, on the other hand, made GitHub
Pages activate on its own. Each run writes a single commit with no history —
the branch is generated content, not a place to edit.

The page lives at `https://pheonix-studio-cat.github.io/Chinook-security/`.

## The weekly run

Mondays: checks, counterproof and all five bots over Chinook Security's own repository,
without anyone having to commit anything. It catches what changes **without a
commit** — a new advisory at OSV, a changed default in GitHub Actions, a tool
that answers differently than last week.

## The counterproof

```
python3 -m checks.counterproof [--json counterproof.json]
```

It copies the repository, breaks the bots **on purpose** — redaction switched
off, a rule skipped, `is_pinned` always returning `True`, the OSV error
swallowed, the overseer dropping findings — and demands that the checks go
**red** as a result. Forty-seven mutations, all caught.

Each mutation first verifies that it changed the file at all, and that the text
it replaces occurs **exactly once**. Without the first, an ineffective mutation
could pass judgement. Without the second, a mutation silently moves to a
different place when the file grows — which is exactly what happened when the
sixth bot was added, to two mutations that had been ambiguous from the start.

Ten of the forty-three break the **counterproof bot itself**: the report leaking
source, a comment being mutated, a red baseline accepted, someone else's source
left broken on disk. The bot that breaks foreign code is the last one that
should be taken at its word.

The reason for all of it is above: *a check that has never run against a
deliberately broken state is not a check.*

---

## Layout

```
chinook/            the bots, standard library only
  findings.py       the shared finding format, JSON and SARIF
  secret_bot.py  workflow_bot.py  dependency_bot.py  code_bot.py  license_bot.py
  overseer.py       the overseer — triages, never removes
  cli.py            python3 -m chinook.cli <bot> …
actions/            one composite action per bot
.github/workflows/  the self-check
webseite/build.py   generates the page from the bots' rules
checks/             the checks and the counterproof
fixtures/workflows/ deliberately broken workflows — outside .github/workflows
                    so GitHub does not run them
fixtures/code/      the code samples as JSON — not as .py/.js/.sh, or the code
                    bot would report its own fixtures
schema/             the finding format as JSON Schema
docs/               the rules in detail, limits, decisions (German)
```

The fixtures for secrets are **generated at runtime**
(`checks/fixtures.py`), not stored as files: a format-valid token in the
repository is blocked by GitHub's push protection and reported by scanners.

---

## Open

- **Tag `v1`**, so users can write `@v1` instead of `@main` or a commit SHA.
- **The overseer has never run against a real model.** The checks run against a
  stub — rightly so, what is checked is what Chinook Security does with the answer.
  Whether a real model produces usable assessments is open.
- **Licences of dependencies** for the licence bot — it currently sees only the
  repository itself, not what it pulls in.
- **Fixed versions in the finding.** The OSV batch query returns only IDs; a
  fixed version would need a second request per advisory.

---

## Licence

MIT, see [`LICENSE`](LICENSE). Please report vulnerabilities as described in
[`SECURITY.md`](SECURITY.md).
