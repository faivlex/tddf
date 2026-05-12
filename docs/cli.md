# CLI reference

`tddf` is a Typer-based CLI. Every command has built-in `--help`; this page documents the surface, the flags worth knowing, and where each command fits in the workflow. For exhaustive flag listings, run `tddf <command> --help`.

## Commands at a glance

| Command | Purpose |
|---|---|
| `tddf init` | Generate a starter `tddf.yaml` for an adapter |
| `tddf validate` | Check config shape and resolve capabilities |
| `tddf run` | Run scenarios and report pass/fail |
| `tddf watch` | Re-run scenarios on every save |
| `tddf assess` | Auto-discover agent capabilities and generate a starter scenario set |
| `tddf baseline save` | Capture the current pass/fail + evidence fingerprints as a CI gate |
| `tddf baseline show` | Pretty-print a saved baseline |
| `tddf snapshot save` | Capture byte-exact observable snapshots for scenarios with `snapshot: true` |
| `tddf snapshot show <id>` | Pretty-print a saved snapshot |
| `tddf install-hook` | Install a git pre-push / pre-commit hook that runs TDDF |
| `tddf import injecagent` | Import the [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) benchmark |
| `tddf import agentdojo` | Import the [AgentDojo](https://github.com/ethz-spylab/agentdojo) benchmark (needs `tddf[agentdojo]`) |
| `tddf mcp-server` | Run TDDF as an MCP server over stdio (invoked by agent SDKs) |
| `tddf version` | Print the installed TDDF version |

## `tddf run`

Run the scenarios in `tddf.yaml` and report pass/fail.

Key flags:

- `--config <path>` — config file to load (default: `tddf.yaml`).
- `--fail-severity {critical|high|medium|low}` — exit non-zero only for failures at or above this severity. Errors and timeouts always fail.
- `--baseline <path>` — compare against a saved baseline; exit non-zero only on **regressions** (and errors/timeouts).
- `--strict-baseline` — under `--baseline`, also fail on drift, missing scenarios, and new-failing scenarios.
- `--snapshot` — compare observables against saved snapshots for scenarios with `snapshot: true`; fail on mismatch. See [docs/snapshots.md](snapshots.md).

Examples:

```bash
tddf run                                          # absolute pass/fail
tddf run --fail-severity high                     # only HIGH+ failures gate the build
tddf run --baseline .tddf/baseline.json           # regression gate
tddf run --baseline .tddf/baseline.json --strict-baseline
tddf run --snapshot --fail-severity high          # snapshot gate
```

`tddf run` always writes per-scenario `result.json` and a batch-level `junit.xml` under `.tddf/artifacts/<run_id>/` (controlled by the `output:` section of the config).

## `tddf baseline save` / `show`

Baseline mode is the CI gate. See [docs/scenarios.md#baseline-mode](scenarios.md#baseline-mode) for the full workflow.

```bash
tddf baseline save                          # write .tddf/baseline.json
tddf baseline save --baseline custom.json   # alternate path
tddf baseline save --include-errors         # save even if scenarios errored (not recommended)
tddf baseline show                          # pretty-print the saved baseline
```

The save command runs every scenario once, captures pass/fail + a lossy fingerprint per scenario, and tags the file with the current git commit (auto-detected). Commit `.tddf/baseline.json` alongside your code.

## `tddf snapshot save` / `show`

Byte-exact snapshots — opposite of the lossy baseline. See [docs/snapshots.md](snapshots.md).

```bash
tddf snapshot save                          # write .tddf/snapshots/*.json for snapshot-enabled scenarios
tddf snapshot save --snapshots-dir custom/  # alternate location
tddf snapshot show <scenario-id>            # pretty-print one snapshot
```

## `tddf watch`

Re-run scenarios whenever the config or any `--watch` path changes. Same gating semantics as `tddf run`.

Key flags:

- `--config <path>` — config to watch (also runs the suite).
- `--watch <path>` — additional path to watch. Repeat for multiple paths.
- `--interval <seconds>` — poll interval (default 0.5, range 0.05–30).
- `--baseline`, `--strict-baseline`, `--snapshot`, `--snapshots-dir`, `--fail-severity` — same meaning as on `tddf run`.

```bash
tddf watch --watch src/my_agent.py
tddf watch --watch src/ --baseline .tddf/baseline.json
```

In watch mode, `--fail-severity` is informational — the loop keeps going regardless. Ctrl-C to stop.

## `tddf init`

Generate a starter `tddf.yaml` for one of the supported adapters.

```bash
tddf init --adapter langgraph
tddf init --adapter claude_agent_sdk --config tddf.yaml --force
```

Adapter choices: `command`, `hermes`, `openclaw`, `langgraph`, `openai_agents`, `claude_agent_sdk`. `--force` overwrites an existing file.

## `tddf validate`

Load the config and report shape + resolved capabilities without running anything.

```bash
tddf validate
tddf validate --config tddf.staging.yaml
```

Output includes the target kind, target capabilities, harness capabilities, scenario count, and per-scenario capability requirements — useful for catching mis-wired adapters before `tddf run` does.

## `tddf assess`

Probe the agent's capabilities (does it have `web`? does it use MCP tools?) and generate a starter scenario set matched to what's actually exposed.

```bash
tddf assess                                              # run the assessment, print findings
tddf assess --write-generated-config tddf.generated.yaml # also persist the generated config
```

Useful for bootstrapping a regression suite against an unfamiliar agent. The generated config is a starting point — review and adapt the scenarios before committing.

## `tddf install-hook`

Install a native git hook that runs `tddf run` automatically. The hook gracefully no-ops when `tddf` isn't on `PATH`.

Key flags:

- `--stage {pre-push|pre-commit}` — default `pre-push` (recommended). `pre-commit` fires more often and slows the commit loop.
- `--config <path>` — config path baked into the hook.
- `--baseline <path>` — baseline path the hook consults if it exists.
- `--fail-severity <level>` — severity gate baked into the hook (default `high`).
- `--force` — overwrite an existing hook at this stage.

```bash
tddf install-hook                                       # pre-push, --fail-severity high
tddf install-hook --stage pre-commit --fail-severity critical
```

The installed hook checks for the baseline file at run time — if `.tddf/baseline.json` exists, the hook gates on regressions; otherwise it gates on absolute pass/fail.

## `tddf import injecagent` / `agentdojo`

Materialise published benchmark cases as TDDF scenarios with provenance. Each command writes a single registry YAML that you reference from `scenarios_from_registry:` in your config.

InjecAgent:

```bash
tddf import injecagent \
  --revision main \
  --output registries/injecagent.yaml \
  --attack-kind data-stealing \      # data-stealing | direct-harm
  --setting base \                   # base | enhanced
  --limit 100                        # optional cap
```

AgentDojo (requires `pip install 'tddf[agentdojo]'`):

```bash
tddf import agentdojo \
  --revision 0.1.35 \
  --suite banking \                  # banking | workspace | slack | travel
  --output registries/agentdojo-banking.yaml \
  --benchmark-version v1.2.2 \
  --limit 100
```

Both commands record the upstream repo, revision, license, and per-case provenance in the registry file. For zero-setup curated subsets, reference `builtin://injecagent_curated` or `builtin://agentdojo_curated` instead of running the importer.

## `tddf mcp-server`

Run TDDF as an MCP server over stdio. Invoked as a subprocess by MCP clients (e.g. the Claude Agent SDK) — not normally run by hand. See [docs/mcp.md](mcp.md) for the integration story.

```bash
tddf mcp-server --config tddf.yaml --capture-file .tddf/mcp-capture.jsonl
```

`--capture-file` defaults to `$TDDF_MCP_CAPTURE_FILE` if set. The parent `tddf run` process merges the captured tool-call records into its evaluator view after the agent exits.

## `tddf version`

```bash
tddf version
```

Prints the installed TDDF version. Same value that lands in every snapshot's `tddf_version` field.

## Canonical source

Command definitions live in [`src/tddf/cli.py`](../src/tddf/cli.py). Each command is a Typer entry point and its help text is the canonical flag description — when in doubt, run `tddf <command> --help`.
