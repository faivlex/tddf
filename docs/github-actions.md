# GitHub Actions

Catch agent security regressions in CI. TDDF ships a reusable composite GitHub Action that validates your config, runs your trap scenarios, uploads artifacts, and fails the build when a scenario breaches your severity threshold.

## Example

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

      - uses: owner/tddf@v1
        with:
          config: tddf.yaml
          fail-severity: high
          artifact-name: tddf-artifacts
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

Replace `owner/tddf@v1` with the tagged TDDF release you want to pin.

## What It Does

The action:

1. Sets up Python and `uv`
2. Installs TDDF from the action source
3. Runs `tddf validate --config ...` by default
4. Runs `tddf run --config ... --fail-severity ...`
5. Uploads the TDDF artifacts directory via `actions/upload-artifact`
6. Fails the workflow only after artifacts and a step summary are published

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `config` | `tddf.yaml` | TDDF config file |
| `fail-severity` | `low` | CI failure threshold |
| `python-version` | `3.12` | Python version for the action |
| `working-directory` | `.` | Working directory for TDDF commands |
| `artifacts-dir` | `.tddf/artifacts` | Relative artifacts directory |
| `upload-artifacts` | `true` | Upload artifacts to GitHub |
| `artifact-name` | `tddf-artifacts` | Uploaded artifact name |
| `validate` | `true` | Run `tddf validate` before execution |

## Artifacts And Failure Semantics

- TDDF always writes per-scenario JSON/stdout/stderr files plus any adapter-specific artifacts.
- TDDF also writes a batch-level `junit.xml` under `.tddf/artifacts/<run_id>/junit.xml`.
- The GitHub Action uploads the configured artifacts directory even when scenarios fail.
- `fail-severity` controls whether failing scenarios should fail the workflow:
  - `critical`: only critical scenario failures fail the build
  - `high`: high and critical failures fail the build
  - `medium`: medium, high, and critical failures fail the build
  - `low`: any failing scenario fails the build
- TDDF `error` and `timeout` results still fail the workflow regardless of severity threshold.

## Secrets And Optional Dependencies

- Pass provider keys through standard workflow `env`/`secrets` entries.
- Install any adapter-specific optional dependencies before the action step.
  - Example: `langgraph`, `openai-agents`, or your own agent package.
- The action installs TDDF itself; it does not install your target agent's runtime dependencies.
