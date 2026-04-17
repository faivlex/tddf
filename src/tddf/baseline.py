from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from tddf import __version__
from tddf.config import TddfConfig, TrapConfig
from tddf.results import SEVERITY_RANK, RunBatch, RunResult


def _stable_path(path: str | None) -> str | None:
    """Strip query string so fingerprints stay stable under LLM output variability."""
    if not path:
        return None
    parsed = urlparse(path)
    return parsed.path if parsed.path else path


BASELINE_FORMAT_VERSION = 1
DEFAULT_BASELINE_PATH = Path(".tddf/baseline.json")

ScenarioCategory = Literal[
    "unchanged", "improved", "regressed", "drifted", "new", "missing"
]


class BaselineFingerprintEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    method: str | None = None
    path: str | None = None
    tool_name: str | None = None
    resource_key: str | None = None
    sensitive: bool | None = None

    def sort_key(self) -> tuple[object, ...]:
        return (
            self.kind,
            self.method or "",
            self.path or "",
            self.tool_name or "",
            self.resource_key or "",
            1 if self.sensitive else 0,
        )

    def signature(self) -> tuple[object, ...]:
        return (
            self.kind,
            self.method,
            self.path,
            self.tool_name,
            self.resource_key,
            bool(self.sensitive) if self.sensitive is not None else None,
        )


class BaselineScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_hash: str
    adapter: str
    severity: str
    status: Literal["passed", "failed"]
    evidence_fingerprint: list[BaselineFingerprintEntry] = Field(default_factory=list)


class BaselineFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = BASELINE_FORMAT_VERSION
    recorded_at: str
    tddf_version: str
    git_commit: str | None = None
    config_hash: str
    scenarios: dict[str, BaselineScenario]


def _canonical_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _sha256(data: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(data).encode()).hexdigest()


def _canonicalize_scenario_payload(payload: dict[str, object]) -> dict[str, object]:
    """Canonicalize author-authored set-semantic fields before hashing.

    ``frameworks`` is a list of compliance references that carry set, not
    sequence, semantics — reordering them in YAML for readability should not
    invalidate an otherwise-unchanged baseline. Keep ordered fields (``steps``,
    ``workspace.files``) as-is since their order is load-bearing.

    ``snapshot`` is a test-mode toggle — it opts the scenario into stricter
    snapshot comparisons but does not change what the agent sees or does.
    Exclude it so flipping the flag does not invalidate existing baselines.
    """
    if isinstance(payload.get("frameworks"), list):
        payload = {**payload, "frameworks": sorted(payload["frameworks"])}
    if "snapshot" in payload:
        payload = {k: v for k, v in payload.items() if k != "snapshot"}
    return payload


def compute_scenario_content_hash(trap: TrapConfig) -> str:
    return _sha256(_canonicalize_scenario_payload(trap.model_dump(mode="json")))


def compute_config_hash(config: TddfConfig) -> str:
    return _sha256(config.model_dump(mode="json"))


def extract_evidence_fingerprint(result: RunResult) -> list[BaselineFingerprintEntry]:
    seen: dict[tuple[object, ...], BaselineFingerprintEntry] = {}
    for item in result.evidence:
        entry = BaselineFingerprintEntry(
            kind=item.kind,
            method=item.method,
            path=_stable_path(item.path),
            tool_name=item.tool_name,
            resource_key=item.resource_key,
            sensitive=item.sensitive,
        )
        seen[entry.signature()] = entry
    return sorted(seen.values(), key=lambda e: e.sort_key())


class BaselineBuildError(ValueError):
    pass


class BaselineLoadError(ValueError):
    pass


def build_baseline(
    batch: RunBatch,
    config: TddfConfig,
    *,
    git_commit: str | None = None,
    include_errors: bool = False,
) -> BaselineFile:
    bad = [r for r in batch.results if r.status in {"error", "timeout"}]
    if bad and not include_errors:
        ids = ", ".join(r.scenario_id for r in bad)
        raise BaselineBuildError(
            f"Refusing to save baseline: {len(bad)} scenario(s) errored or timed out "
            f"({ids}). Re-run with --include-errors to override (not recommended)."
        )

    scenarios_by_id = {trap.id: trap for trap in config.scenario_definitions}
    scenarios: dict[str, BaselineScenario] = {}
    orphan_results: list[str] = []
    for result in batch.results:
        if result.status in {"error", "timeout"}:
            continue
        trap = scenarios_by_id.get(result.scenario_id)
        if trap is None:
            orphan_results.append(result.scenario_id)
            continue
        status: Literal["passed", "failed"] = (
            "passed" if result.status == "passed" else "failed"
        )
        scenarios[result.scenario_id] = BaselineScenario(
            content_hash=compute_scenario_content_hash(trap),
            adapter=result.adapter_name,
            severity=result.severity,
            status=status,
            evidence_fingerprint=extract_evidence_fingerprint(result),
        )

    if orphan_results:
        raise BaselineBuildError(
            "Refusing to save baseline: result scenario ids do not appear in the "
            "loaded config (possible config/result mismatch): "
            + ", ".join(orphan_results)
        )

    if not scenarios:
        raise BaselineBuildError(
            "Refusing to save baseline: assembled 0 scenarios. This typically "
            "means every scenario errored or timed out — fix the target before "
            "snapshotting a baseline."
        )

    return BaselineFile(
        version=BASELINE_FORMAT_VERSION,
        recorded_at=datetime.now(UTC).isoformat(),
        tddf_version=__version__,
        git_commit=git_commit,
        config_hash=compute_config_hash(config),
        scenarios=scenarios,
    )


def detect_git_commit(cwd: Path | None = None) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha or None


def load_baseline(path: Path) -> BaselineFile:
    if not path.exists():
        raise BaselineLoadError(f"Baseline file not found: {path}")
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise BaselineLoadError(
            f"Baseline file is not valid JSON: {path}: {exc}"
        ) from exc
    try:
        baseline = BaselineFile.model_validate(raw)
    except ValueError as exc:
        raise BaselineLoadError(f"Baseline file is invalid: {path}: {exc}") from exc
    if baseline.version != BASELINE_FORMAT_VERSION:
        raise BaselineLoadError(
            f"Baseline file version {baseline.version} is not supported "
            f"(this TDDF expects version {BASELINE_FORMAT_VERSION})."
        )
    return baseline


def write_baseline(path: Path, baseline: BaselineFile) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = baseline.model_dump(mode="json")
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(rendered)
    tmp.replace(path)


@dataclass(slots=True)
class ScenarioDiff:
    scenario_id: str
    category: ScenarioCategory
    severity: str
    adapter: str | None
    baseline_status: str | None
    current_status: str | None
    summary: str | None = None
    added_evidence: list[BaselineFingerprintEntry] = field(default_factory=list)
    removed_evidence: list[BaselineFingerprintEntry] = field(default_factory=list)
    content_changed: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id,
            "category": self.category,
            "severity": self.severity,
            "adapter": self.adapter,
            "baseline_status": self.baseline_status,
            "current_status": self.current_status,
            "summary": self.summary,
            "content_changed": self.content_changed,
            "added_evidence": [
                e.model_dump(mode="json") for e in self.added_evidence
            ],
            "removed_evidence": [
                e.model_dump(mode="json") for e in self.removed_evidence
            ],
        }


@dataclass(slots=True)
class BaselineDiff:
    baseline_path: Path
    baseline_recorded_at: str
    baseline_commit: str | None
    baseline_tddf_version: str
    scenario_diffs: list[ScenarioDiff]
    config_hash_changed: bool

    def _filter(self, category: ScenarioCategory) -> list[ScenarioDiff]:
        return [d for d in self.scenario_diffs if d.category == category]

    @property
    def unchanged(self) -> list[ScenarioDiff]:
        return self._filter("unchanged")

    @property
    def improved(self) -> list[ScenarioDiff]:
        return self._filter("improved")

    @property
    def regressed(self) -> list[ScenarioDiff]:
        return self._filter("regressed")

    @property
    def drifted(self) -> list[ScenarioDiff]:
        return self._filter("drifted")

    @property
    def new(self) -> list[ScenarioDiff]:
        return self._filter("new")

    @property
    def missing(self) -> list[ScenarioDiff]:
        return self._filter("missing")

    def should_fail(self, fail_severity: str, strict: bool) -> bool:
        for diff in self.scenario_diffs:
            if diff.current_status in {"error", "timeout"}:
                return True
        threshold = SEVERITY_RANK[fail_severity]
        for diff in self.regressed:
            if SEVERITY_RANK.get(diff.severity, 0) >= threshold:
                return True
        if strict:
            if self.drifted:
                return True
            if self.missing:
                return True
            for diff in self.new:
                if diff.current_status == "failed":
                    return True
        return False

    def summary_counts(self) -> dict[str, int]:
        return {
            "unchanged": len(self.unchanged),
            "improved": len(self.improved),
            "regressed": len(self.regressed),
            "drifted": len(self.drifted),
            "new": len(self.new),
            "missing": len(self.missing),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline_path": str(self.baseline_path),
            "baseline_recorded_at": self.baseline_recorded_at,
            "baseline_commit": self.baseline_commit,
            "baseline_tddf_version": self.baseline_tddf_version,
            "config_hash_changed": self.config_hash_changed,
            "summary": self.summary_counts(),
            "scenario_diffs": [d.to_dict() for d in self.scenario_diffs],
        }


def _evidence_delta(
    baseline_entries: list[BaselineFingerprintEntry],
    current_entries: list[BaselineFingerprintEntry],
) -> tuple[list[BaselineFingerprintEntry], list[BaselineFingerprintEntry]]:
    baseline_set = {e.signature(): e for e in baseline_entries}
    current_set = {e.signature(): e for e in current_entries}
    added = [e for sig, e in current_set.items() if sig not in baseline_set]
    removed = [e for sig, e in baseline_set.items() if sig not in current_set]
    added.sort(key=lambda x: x.sort_key())
    removed.sort(key=lambda x: x.sort_key())
    return added, removed


def compare(
    baseline: BaselineFile,
    batch: RunBatch,
    config: TddfConfig,
    *,
    baseline_path: Path,
) -> BaselineDiff:
    current_scenarios_by_id = {trap.id: trap for trap in config.scenario_definitions}
    results_by_id = {r.scenario_id: r for r in batch.results}
    diffs: list[ScenarioDiff] = []

    current_ids = set(results_by_id.keys())
    baseline_ids = set(baseline.scenarios.keys())

    for scenario_id in sorted(current_ids):
        result = results_by_id[scenario_id]
        trap = current_scenarios_by_id.get(scenario_id)
        current_hash = (
            compute_scenario_content_hash(trap) if trap is not None else None
        )
        current_fp = extract_evidence_fingerprint(result)
        baseline_entry = baseline.scenarios.get(scenario_id)

        if baseline_entry is None or (
            current_hash is not None and baseline_entry.content_hash != current_hash
        ):
            diffs.append(
                ScenarioDiff(
                    scenario_id=scenario_id,
                    category="new",
                    severity=result.severity,
                    adapter=result.adapter_name,
                    baseline_status=(
                        baseline_entry.status if baseline_entry is not None else None
                    ),
                    current_status=result.status,
                    summary=result.summary,
                    added_evidence=current_fp,
                    content_changed=baseline_entry is not None,
                )
            )
            continue

        if result.status in {"error", "timeout"}:
            diffs.append(
                ScenarioDiff(
                    scenario_id=scenario_id,
                    category="drifted",
                    severity=result.severity,
                    adapter=result.adapter_name,
                    baseline_status=baseline_entry.status,
                    current_status=result.status,
                    summary=result.summary,
                )
            )
            continue

        added, removed = _evidence_delta(
            baseline_entry.evidence_fingerprint, current_fp
        )

        if baseline_entry.status == "passed" and result.status == "failed":
            category: ScenarioCategory = "regressed"
        elif baseline_entry.status == "failed" and result.status == "passed":
            category = "improved"
        elif added or removed:
            category = "drifted"
        else:
            category = "unchanged"

        diffs.append(
            ScenarioDiff(
                scenario_id=scenario_id,
                category=category,
                severity=result.severity,
                adapter=result.adapter_name,
                baseline_status=baseline_entry.status,
                current_status=result.status,
                summary=result.summary if category != "unchanged" else None,
                added_evidence=added,
                removed_evidence=removed,
            )
        )

    for scenario_id in sorted(baseline_ids - current_ids):
        baseline_entry = baseline.scenarios[scenario_id]
        diffs.append(
            ScenarioDiff(
                scenario_id=scenario_id,
                category="missing",
                severity=baseline_entry.severity,
                adapter=baseline_entry.adapter,
                baseline_status=baseline_entry.status,
                current_status=None,
            )
        )

    current_config_hash = compute_config_hash(config)
    return BaselineDiff(
        baseline_path=baseline_path,
        baseline_recorded_at=baseline.recorded_at,
        baseline_commit=baseline.git_commit,
        baseline_tddf_version=baseline.tddf_version,
        scenario_diffs=diffs,
        config_hash_changed=(current_config_hash != baseline.config_hash),
    )
