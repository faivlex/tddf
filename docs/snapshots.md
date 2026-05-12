# Snapshot tests

Byte-exact regression detection for scenarios where the agent's tool-call sequence has to match exactly. TDDF's default [baseline mode](scenarios.md#baseline-mode) is deliberately lossy — it hashes a *set* of evidence signatures so LLM-driven response bodies can vary run-to-run without flipping the gate. Snapshots are the opposite: every observable is pinned in order, byte for byte.

## When to use snapshots vs. baselines

| | Baseline | Snapshot |
|---|---|---|
| Sensitivity | Set-based, lossy fingerprint | Ordered list, byte-exact |
| Survives LLM nondeterminism | Yes | No |
| What it catches | New failures, evidence drift | Any change in the action sequence |
| Right for | LLM-driven scenarios in CI | Fixture agents, deterministic flows |

If your agent uses an LLM and produces slightly different response bodies each run, snapshots will flap. Use baseline mode. Reach for snapshots only when the exact sequence of tool calls and network requests is part of the contract — typically for fixture agents (deterministic mock agents used in TDDF's own test suite, or for scenarios where you control every byte of the response).

## Opting in

Snapshots are off by default. Set `snapshot: true` on the scenarios that need them:

```yaml
scenarios:
  - id: confused-deputy-finance-demo
    snapshot: true
    severity: critical
    prompt_template: "..."
    ...
```

See [scenarios.md](scenarios.md#top-level-shape) for the full scenario schema.

## Saving and running

```bash
# Once, on a known-good commit:
tddf snapshot save

# On every PR:
tddf run --snapshot --fail-severity high

# Pretty-print a saved snapshot:
tddf snapshot show <scenario-id>
```

`tddf snapshot save` runs the suite and writes one `.json` per snapshot-enabled scenario to `.tddf/snapshots/`. `tddf run --snapshot` re-runs, diffs against the saved files, and fails the build on any drift at or above `--fail-severity`.

## What's in a snapshot file

Each file pins the chronological sequence of observable actions the scenario produced:

```json
{
  "version": 1,
  "scenario_id": "confused-deputy-finance-demo",
  "recorded_at": "2025-11-12T10:34:00+00:00",
  "tddf_version": "0.4.1",
  "observables": [
    {
      "type": "tool_call",
      "tool_name": "get_contact",
      "resource_key": null,
      "sensitive": false,
      "tool_arguments": { "name": "bob" }
    },
    {
      "type": "network_request",
      "method": "POST",
      "path": "/collect",
      "body": "stolen=TDDF_DEMO_SECRET"
    }
  ]
}
```

Two observable types:

- **`network_request`** — `method`, `path`, `body` (verbatim from the captured `body_preview`).
- **`tool_call`** — `tool_name`, `resource_key`, `sensitive`, `tool_arguments` (sorted alphabetically by key for stable diffs).

Network bodies are recorded verbatim — there is no normalisation pass. If the body contains a timestamp, the snapshot will flap on the timestamp.

## Diff semantics

When `tddf run --snapshot` finds drift, every difference is reported at its position in the sequence:

| Kind | Meaning |
|---|---|
| `missing` | The saved snapshot expected an observable at position N; the current run had none. |
| `added` | The current run produced an observable at position N that the saved snapshot doesn't have. |
| `changed` | Both have an observable at position N, but they don't match. |

Comparison is position-by-position — no longest-common-subsequence alignment. If the agent reorders its tool calls, every position from the swap onward shows as `changed`. That is deliberate: if positional order matters to your scenario, a reordering *is* a regression.

A missing snapshot file (e.g. you added `snapshot: true` to a new scenario and forgot to run `tddf snapshot save`) surfaces as a `missing_snapshot` flag at the suite level, not as a per-observable diff.

## Where they live

Snapshots are written to `.tddf/snapshots/<scenario-id>.json` (slashes in scenario IDs become underscores). Commit them alongside the scenario YAML — they are the contract. Regenerate with `tddf snapshot save` when an intentional behaviour change makes the old snapshot obsolete; review the diff before committing.

## Canonical source

The snapshot, observable, and diff models live in [`src/tddf/snapshots.py`](../src/tddf/snapshots.py). Format version is `SNAPSHOT_FORMAT_VERSION = 1`; loading a file with a different version is rejected at parse time.
