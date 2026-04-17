from __future__ import annotations

from datetime import datetime
from pathlib import Path

from tddf.watch import _snapshot_mtimes, detect_changes, run_watch


def test_snapshot_mtimes_records_none_for_missing_paths(tmp_path: Path) -> None:
    existing = tmp_path / "a.yaml"
    existing.write_text("x")
    missing = tmp_path / "nope.yaml"

    snapshot = _snapshot_mtimes([existing, missing])

    assert snapshot[existing] is not None
    assert snapshot[missing] is None


def test_detect_changes_flags_mtime_bump(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_text("one")
    first = _snapshot_mtimes([path])

    # Rewrite with a materially later mtime; don't rely on filesystem
    # resolution by explicitly stamping the mtime forward.
    path.write_text("two")
    import os
    future = first[path] + 10
    os.utime(path, (future, future))

    current, changed = detect_changes(first, [path])
    assert changed == [path]
    assert current[path] == future


def test_detect_changes_detects_appearance_and_disappearance(tmp_path: Path) -> None:
    path = tmp_path / "late"
    snapshot_before = _snapshot_mtimes([path])  # path is missing
    assert snapshot_before[path] is None

    path.write_text("now here")
    snapshot_after, changed = detect_changes(snapshot_before, [path])
    assert changed == [path]

    path.unlink()
    snapshot_gone, changed_gone = detect_changes(snapshot_after, [path])
    assert changed_gone == [path]
    assert snapshot_gone[path] is None


def test_run_watch_invokes_run_once_on_change_then_exits_on_interrupt(
    tmp_path: Path,
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("initial")

    call_count = {"value": 0}
    notifications: list[str] = []

    def _run_once() -> int:
        call_count["value"] += 1
        # After the second invocation (initial + one change), simulate the
        # user pressing Ctrl-C inside the run so the watcher exits cleanly.
        if call_count["value"] >= 2:
            raise KeyboardInterrupt
        # Between the initial call and the loop's first iteration, mutate
        # the file so the watcher picks up a change.
        import os
        current_mtime = path.stat().st_mtime
        os.utime(path, (current_mtime + 5, current_mtime + 5))
        return 0

    run_watch(
        [path],
        run_once=_run_once,
        interval=0.01,
        clock=lambda: datetime(2026, 4, 17, 9, 0, 0),
        notify=notifications.append,
    )

    assert call_count["value"] == 2
    # Status lines cover start, watch target, detected change, and stop.
    assert any("started at" in line for line in notifications)
    assert any("watching" in line for line in notifications)
    assert any("changed" in line for line in notifications)
    assert any("stopped" in line for line in notifications)


def test_run_watch_ignores_repeated_identical_snapshots(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("x")

    calls = {"value": 0}

    def _run_once() -> int:
        calls["value"] += 1
        if calls["value"] >= 1:
            # Exit immediately after the initial run so we can assert the
            # loop did not spuriously re-invoke without a change.
            raise KeyboardInterrupt
        return 0

    run_watch(
        [path],
        run_once=_run_once,
        interval=0.01,
        notify=lambda _line: None,
    )

    assert calls["value"] == 1
