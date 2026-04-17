"""Jest-style snapshot tests for scenario observables.

Baseline regression mode (``src/tddf/baseline.py``) is deliberately lossy —
it hashes a *set* of evidence signatures so LLM-driven bodies can vary
run-to-run without flipping the baseline. Snapshot mode is the opposite:
every scenario that opts in pins the exact ordered sequence of observable
actions (network requests + MCP tool calls) the agent produced, including
bodies and tool arguments.

Snapshots live under ``.tddf/snapshots/<scenario-id>.json``, are committed
to the repo, and are only checked for scenarios that set ``snapshot: true``
in ``tddf.yaml``. Diffs surface as an ordered list of ``missing`` /
``added`` / ``changed`` entries so the regression is actionable.

This file intentionally does not import ``baseline`` — the two gates are
orthogonal and either (or both) can be active on a single run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from tddf import __version__
from tddf.results import RunResult


SNAPSHOT_FORMAT_VERSION = 1
DEFAULT_SNAPSHOTS_DIR = Path(".tddf/snapshots")


class Observable(BaseModel):
    """A canonical record of one observable action the agent produced.

    Observables preserve chronological order (via their index in the
    ``Snapshot.observables`` list) because for multi-turn scenarios the
    sequence of tool calls itself is load-bearing.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["network_request", "tool_call"]
    method: str | None = None
    path: str | None = None
    body: str | None = None
    tool_name: str | None = None
    resource_key: str | None = None
    sensitive: bool | None = None
    tool_arguments: dict[str, str] | None = None


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = SNAPSHOT_FORMAT_VERSION
    scenario_id: str
    recorded_at: str
    tddf_version: str
    observables: list[Observable] = Field(default_factory=list)


class SnapshotLoadError(ValueError):
    pass


def extract_observables(result: RunResult) -> list[Observable]:
    """Build the canonical observables list for ``result``.

    Network-request bodies are included verbatim (via the already-captured
    ``body_preview``) and tool-call arguments are included as a sorted
    dict, because snapshot semantics are "byte-exact sequence match" — if
    the caller wanted fuzziness, they would use baseline mode instead.
    """
    observables: list[Observable] = []
    for item in result.evidence:
        if item.kind == "network_request":
            observables.append(
                Observable(
                    type="network_request",
                    method=item.method,
                    path=item.path,
                    body=item.body_preview or "",
                )
            )
        elif item.kind == "tool_call":
            sorted_args: dict[str, str] | None = None
            if item.tool_arguments:
                sorted_args = dict(sorted(item.tool_arguments.items()))
            observables.append(
                Observable(
                    type="tool_call",
                    tool_name=item.tool_name,
                    resource_key=item.resource_key,
                    sensitive=item.sensitive,
                    tool_arguments=sorted_args,
                )
            )
    return observables


def build_snapshot(result: RunResult) -> Snapshot:
    return Snapshot(
        version=SNAPSHOT_FORMAT_VERSION,
        scenario_id=result.scenario_id,
        recorded_at=datetime.now(UTC).isoformat(),
        tddf_version=__version__,
        observables=extract_observables(result),
    )


def snapshot_path_for(scenario_id: str, snapshots_dir: Path) -> Path:
    safe = scenario_id.replace("/", "_")
    return snapshots_dir / f"{safe}.json"


def load_snapshot(path: Path) -> Snapshot:
    if not path.exists():
        raise SnapshotLoadError(f"Snapshot file not found: {path}")
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SnapshotLoadError(
            f"Snapshot file is not valid JSON: {path}: {exc}"
        ) from exc
    try:
        snapshot = Snapshot.model_validate(raw)
    except ValueError as exc:
        raise SnapshotLoadError(f"Snapshot file is invalid: {path}: {exc}") from exc
    if snapshot.version != SNAPSHOT_FORMAT_VERSION:
        raise SnapshotLoadError(
            f"Snapshot file version {snapshot.version} is not supported "
            f"(this TDDF expects version {SNAPSHOT_FORMAT_VERSION})."
        )
    return snapshot


def write_snapshot(path: Path, snapshot: Snapshot) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = (
        json.dumps(snapshot.model_dump(mode="json"), indent=2, sort_keys=False) + "\n"
    )
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(rendered)
    tmp.replace(path)


@dataclass(slots=True)
class ObservableDiff:
    kind: Literal["missing", "added", "changed"]
    index: int
    expected: Observable | None = None
    actual: Observable | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "index": self.index,
            "expected": self.expected.model_dump(mode="json")
            if self.expected is not None
            else None,
            "actual": self.actual.model_dump(mode="json")
            if self.actual is not None
            else None,
        }


@dataclass(slots=True)
class SnapshotDiff:
    scenario_id: str
    snapshot_path: Path
    diffs: list[ObservableDiff] = field(default_factory=list)
    missing_snapshot: bool = False

    @property
    def is_clean(self) -> bool:
        return not self.missing_snapshot and not self.diffs

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "snapshot_path": str(self.snapshot_path),
            "missing_snapshot": self.missing_snapshot,
            "diffs": [d.to_dict() for d in self.diffs],
        }


def compare_observables(
    expected: list[Observable],
    actual: list[Observable],
) -> list[ObservableDiff]:
    """Walk the two ordered lists in lockstep, reporting position-by-position
    differences. This intentionally does NOT try to align via an LCS — the
    whole point of a snapshot is that positional order is load-bearing."""
    diffs: list[ObservableDiff] = []
    for index in range(max(len(expected), len(actual))):
        expected_at = expected[index] if index < len(expected) else None
        actual_at = actual[index] if index < len(actual) else None
        if expected_at is None and actual_at is not None:
            diffs.append(
                ObservableDiff(kind="added", index=index, actual=actual_at)
            )
        elif actual_at is None and expected_at is not None:
            diffs.append(
                ObservableDiff(kind="missing", index=index, expected=expected_at)
            )
        elif expected_at != actual_at:
            diffs.append(
                ObservableDiff(
                    kind="changed",
                    index=index,
                    expected=expected_at,
                    actual=actual_at,
                )
            )
    return diffs


def compare_snapshot_for_result(
    result: RunResult,
    snapshots_dir: Path,
) -> SnapshotDiff:
    """Load the saved snapshot for ``result.scenario_id`` and diff it
    against the current run's observables. If no snapshot exists, the
    returned diff is marked ``missing_snapshot`` — the CLI can treat that
    as either an error (strict) or an invitation to run ``tddf snapshot
    save`` depending on caller policy."""
    path = snapshot_path_for(result.scenario_id, snapshots_dir)
    if not path.exists():
        return SnapshotDiff(
            scenario_id=result.scenario_id,
            snapshot_path=path,
            missing_snapshot=True,
        )
    expected = load_snapshot(path)
    actual = extract_observables(result)
    return SnapshotDiff(
        scenario_id=result.scenario_id,
        snapshot_path=path,
        diffs=compare_observables(expected.observables, actual),
    )
