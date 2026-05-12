# GitHub Actions

Gate PRs on agent behaviour regressions. TDDF ships a reusable composite GitHub Action that validates your config, runs your scenarios, uploads JUnit + artefacts, and fails the build when a scenario breaches your severity threshold.

## Quick start

```yaml
name: TDDF

on:
  pull_request:
  push:
    branches: [main]

jobs:
  tddf:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Install your agent's own dependencies first if needed.
      - name: Install project dependencies
        run: uv sync

      - uses: faivlex/tddf@v1
        with:
          config: tddf.yaml
          fail-severity: high
          artifact-name: tddf-artifacts
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Pin to a specific release tag (`@v1.2.3`) rather than `@v1` if you need byte-exact reproducibility across runs.

## Regression gate

For the strongest signal on PRs, point TDDF at a committed baseline so the workflow fails only on genuine regressions (and errors/timeouts):

```bash
# Once, on a known-good commit:
tddf baseline save
# then commit .tddf/baseline.json
```

```yaml
- uses: faivlex/tddf@v1
  with:
    config: tddf.yaml
    fail-severity: high
    extra-args: --baseline .tddf/baseline.json
```

The action writes `baseline-diff.json` alongside the other artefacts so downstream steps can render the diff in PR comments. See [docs/scenarios.md](scenarios.md#baseline-mode) for the full baseline workflow.

`extra-args` is a free-form pass-through — use it for any `tddf run` flag: `--baseline`, `--strict-baseline`, `--snapshot`, `--snapshots-dir`, or anything that emerges in later releases. Flag semantics live in [docs/cli.md](cli.md#tddf-run).

## What the action does

1. Sets up Python and `uv`.
2. Installs TDDF from the action source.
3. Runs `tddf validate --config <config>` by default (`validate: false` to skip).
4. Runs `tddf run --config <config> --fail-severity <level> <extra-args>`.
5. Uploads the TDDF artefacts directory via `actions/upload-artifact` (even if scenarios failed).
6. Writes a step summary to the PR UI.
7. Fails the workflow only after artefacts and the summary are published.

## Inputs

| Input | Default | Description |
|---|---|---|
| `config` | `tddf.yaml` | TDDF config file |
| `fail-severity` | `low` | CI failure threshold (`critical` / `high` / `medium` / `low`) |
| `python-version` | `3.12` | Python version for the action |
| `working-directory` | `.` | Working directory for TDDF commands |
| `artifacts-dir` | `.tddf/artifacts` | Relative artifacts directory |
| `upload-artifacts` | `true` | Upload artifacts to GitHub |
| `artifact-name` | `tddf-artifacts` | Uploaded artifact name |
| `validate` | `true` | Run `tddf validate` before `tddf run` |
| `extra-args` | `""` | Extra flags appended to `tddf run` |

## Outputs

The action exposes two outputs for downstream steps:

| Output | Description |
|---|---|
| `exit-code` | Exit code from `tddf run` (`0` on success, non-zero on gated failure or error). |
| `artifacts-path` | Absolute path to the resolved TDDF artefacts directory on the runner. |

Use them to branch on result:

```yaml
- uses: faivlex/tddf@v1
  id: tddf
  with:
    config: tddf.yaml
    fail-severity: high
    extra-args: --baseline .tddf/baseline.json

- name: Post regression summary on failure
  if: ${{ steps.tddf.outputs.exit-code != '0' }}
  run: |
    jq -r '.regressions[]' "${{ steps.tddf.outputs.artifacts-path }}"/*/baseline-diff.json
```

## Artefacts

TDDF writes a per-run directory under `<artifacts-dir>/<run_id>/` containing:

- `result.json` — one per scenario (prompt, planted payload, observed actions, leaked secrets, framework tags).
- `stdout.txt`, `stderr.txt` — one of each per scenario.
- `junit.xml` — batch-level JUnit, one row per scenario.
- `baseline-diff.json` — written only when `--baseline` is used; contains the new/missing/changed regressions.

The action's `upload-artifacts` step (on by default) uploads the entire directory under the configured `artifact-name`, so failed runs preserve the full forensic record.

## Step summary

The action writes a minimal summary block to `$GITHUB_STEP_SUMMARY` on every run (success or failure):

```
## TDDF CI

- Config: `tddf.yaml`
- Fail severity: `high`
- Artifacts: `/home/runner/work/<repo>/<repo>/.tddf/artifacts`
- Exit code: `0`
```

This always renders in the PR's check view. For richer per-scenario rendering (each failed scenario as a distinct PR-check entry), feed `junit.xml` to a third-party reporter step such as `dorny/test-reporter` after the TDDF step.

## Failure semantics

`fail-severity` controls when failing scenarios fail the workflow:

| Threshold | Fails the build on |
|---|---|
| `critical` | only critical failures |
| `high` | high + critical |
| `medium` | medium + high + critical |
| `low` | any failure |

Two cases ignore the threshold: scenarios in `error` or `timeout` status always fail the workflow regardless of `fail-severity`. With `--baseline`, only **regressions** at or above the threshold fail — pre-existing failures don't.

## Secrets and optional dependencies

- Pass provider keys through standard workflow `env` / `secrets` entries (the `OPENAI_API_KEY` line in the quick-start example is the canonical pattern).
- Install any adapter-specific optional dependencies before the action step — `langgraph`, `openai-agents`, `tddf[agentdojo]`, or your own agent package.
- The action installs TDDF itself; it does **not** install your target agent's runtime dependencies.

## Canonical source

The action definition lives in [`action.yml`](../action.yml) at the repo root. When the doc and the action diverge, the action wins.
