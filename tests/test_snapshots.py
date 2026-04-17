from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tddf.results import Evidence, RunResult
from tddf.snapshots import (
    Observable,
    Snapshot,
    SnapshotLoadError,
    build_snapshot,
    compare_observables,
    compare_snapshot_for_result,
    extract_observables,
    load_snapshot,
    snapshot_path_for,
    write_snapshot,
)


def _make_result(
    scenario_id: str = "scn",
    evidence: list[Evidence] | None = None,
) -> RunResult:
    return RunResult(
        run_id="run-test",
        scenario_id=scenario_id,
        status="passed",
        trap_id=scenario_id,
        prompt="p",
        target_command=["python", "-c", "print(0)"],
        config_path="tddf.yaml",
        started_at=datetime.now(UTC).isoformat(),
        completed_at=datetime.now(UTC).isoformat(),
        web_url=None,
        document_path=None,
        workspace_path=None,
        attacker_url="http://localhost/collect",
        adapter_name="command",
        severity="high",
        summary="",
        evidence=evidence or [],
    )


def test_extract_observables_preserves_order_including_bodies() -> None:
    result = _make_result(
        evidence=[
            Evidence(
                kind="network_request",
                detail="",
                method="POST",
                path="/collect?stolen=foo",
                body_preview="stolen=foo",
                body_size=10,
            ),
            Evidence(
                kind="tool_call",
                detail="",
                tool_name="read_resource",
                resource_key="demo_secret",
                sensitive=True,
                tool_arguments={"z": "late", "a": "early"},
            ),
        ],
    )
    observables = extract_observables(result)
    assert len(observables) == 2
    assert observables[0].type == "network_request"
    assert observables[0].body == "stolen=foo"
    assert observables[0].path == "/collect?stolen=foo"
    assert observables[1].type == "tool_call"
    assert observables[1].sensitive is True
    # Tool arguments are stored sorted for snapshot stability.
    assert list(observables[1].tool_arguments.keys()) == ["a", "z"]


def test_extract_observables_skips_unknown_evidence_kinds() -> None:
    result = _make_result(
        evidence=[
            Evidence(kind="unknown_kind", detail="x"),
            Evidence(
                kind="network_request", detail="", method="POST", path="/collect"
            ),
        ],
    )
    observables = extract_observables(result)
    assert len(observables) == 1
    assert observables[0].type == "network_request"


def test_compare_observables_clean_on_byte_exact_match() -> None:
    a = [
        Observable(type="network_request", method="POST", path="/x", body="abc"),
    ]
    b = [
        Observable(type="network_request", method="POST", path="/x", body="abc"),
    ]
    assert compare_observables(a, b) == []


def test_compare_observables_flags_changed_body() -> None:
    expected = [
        Observable(type="network_request", method="POST", path="/x", body="abc")
    ]
    actual = [
        Observable(type="network_request", method="POST", path="/x", body="XYZ")
    ]
    diffs = compare_observables(expected, actual)
    assert len(diffs) == 1
    assert diffs[0].kind == "changed"
    assert diffs[0].index == 0


def test_compare_observables_flags_order_change_as_two_changes() -> None:
    """Positional snapshots don't LCS-align — swapping two observables
    shows up as two ``changed`` entries at their respective indexes.
    This is intentional: the test asserts "nothing moved"."""
    a = Observable(type="network_request", method="POST", path="/a")
    b = Observable(type="network_request", method="POST", path="/b")
    diffs = compare_observables([a, b], [b, a])
    assert len(diffs) == 2
    assert all(d.kind == "changed" for d in diffs)


def test_compare_observables_flags_missing_and_added() -> None:
    a = Observable(type="network_request", method="POST", path="/a")
    b = Observable(type="network_request", method="POST", path="/b")

    only_first = compare_observables([a, b], [a])
    assert len(only_first) == 1
    assert only_first[0].kind == "missing"
    assert only_first[0].index == 1

    extra = compare_observables([a], [a, b])
    assert len(extra) == 1
    assert extra[0].kind == "added"
    assert extra[0].index == 1


def test_write_and_load_snapshot_roundtrip(tmp_path: Path) -> None:
    result = _make_result(
        evidence=[
            Evidence(kind="network_request", detail="", method="POST", path="/collect")
        ],
    )
    snapshot = build_snapshot(result)
    path = tmp_path / "scn.json"
    write_snapshot(path, snapshot)

    loaded = load_snapshot(path)
    assert loaded.scenario_id == "scn"
    assert loaded.version == 1
    assert loaded.observables == snapshot.observables


def test_load_snapshot_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SnapshotLoadError):
        load_snapshot(tmp_path / "nope.json")


def test_load_snapshot_rejects_version_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            {
                "version": 999,
                "scenario_id": "x",
                "recorded_at": "x",
                "tddf_version": "x",
                "observables": [],
            }
        )
    )
    with pytest.raises(SnapshotLoadError):
        load_snapshot(path)


def test_snapshot_path_for_replaces_slashes(tmp_path: Path) -> None:
    path = snapshot_path_for("some/id/with/slashes", tmp_path)
    # File-system-safe path: slashes collapsed into underscores.
    assert path == tmp_path / "some_id_with_slashes.json"


def test_compare_snapshot_for_result_flags_missing(tmp_path: Path) -> None:
    result = _make_result(scenario_id="missing-scn")
    diff = compare_snapshot_for_result(result, tmp_path)
    assert diff.missing_snapshot is True
    assert diff.is_clean is False


def test_compare_snapshot_for_result_clean_when_observables_match(
    tmp_path: Path,
) -> None:
    evidence = [Evidence(kind="network_request", detail="", method="POST", path="/x")]
    recorded = _make_result(scenario_id="scn", evidence=evidence)
    snapshot = build_snapshot(recorded)
    write_snapshot(snapshot_path_for("scn", tmp_path), snapshot)

    current = _make_result(scenario_id="scn", evidence=evidence)
    diff = compare_snapshot_for_result(current, tmp_path)
    assert diff.is_clean
