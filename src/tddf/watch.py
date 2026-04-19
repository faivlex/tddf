"""File-change watcher for ``tddf watch``.

Keeps the run loop small and easy to reason about — stdlib polling rather
than a filesystem-event dependency, so the CLI stays single-file-install
and cross-platform without optional extras.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


def _normalize_paths(paths: Iterable[Path]) -> set[Path]:
    return {Path(path).resolve() for path in paths}


def _is_ignored(path: Path, ignored_paths: set[Path]) -> bool:
    resolved = path.resolve()
    return any(resolved == ignored or resolved.is_relative_to(ignored) for ignored in ignored_paths)


def _expand_watch_paths(path: Path) -> set[Path]:
    """Expand a watched path to the concrete filesystem entries whose mtimes
    should be tracked. Directories recursively include their descendants so
    edits under ``--watch src`` trigger re-runs too."""
    expanded = {path}
    try:
        if path.is_dir():
            expanded.update(child for child in path.rglob("*"))
    except OSError:
        return {path}
    return expanded


def _snapshot_mtimes(
    paths: Iterable[Path],
    ignored_paths: Iterable[Path] | None = None,
) -> dict[Path, float | None]:
    """Return a ``{path: mtime}`` snapshot. Missing paths map to ``None``
    so they can reappear later and be detected as a change."""
    snapshot: dict[Path, float | None] = {}
    ignored = _normalize_paths(ignored_paths or [])
    for path in paths:
        for candidate in _expand_watch_paths(path):
            if ignored and _is_ignored(candidate, ignored):
                continue
            try:
                snapshot[candidate] = candidate.stat().st_mtime
            except FileNotFoundError:
                snapshot[candidate] = None
            except OSError:
                snapshot[candidate] = None
    return snapshot


def detect_changes(
    previous: dict[Path, float | None],
    paths: Iterable[Path],
    ignored_paths: Iterable[Path] | None = None,
) -> tuple[dict[Path, float | None], list[Path]]:
    """Compare the previous snapshot against a fresh one. Returns
    ``(current_snapshot, [paths_that_changed_or_appeared_or_disappeared])``.
    The first element is always returned so callers can carry it forward."""
    current = _snapshot_mtimes(paths, ignored_paths)
    changed = [
        path
        for path in sorted(set(previous) | set(current))
        if previous.get(path) != current.get(path)
    ]
    return current, changed


def run_watch(
    paths: Iterable[Path],
    run_once: Callable[[], int],
    *,
    interval: float = 0.5,
    ignored_paths: Callable[[], Iterable[Path]] | Iterable[Path] | None = None,
    clock: Callable[[], datetime] | None = None,
    notify: Callable[[str], None] | None = None,
) -> None:
    """Poll ``paths`` every ``interval`` seconds and invoke ``run_once``
    whenever any path's mtime changes (or it appears / disappears).

    - ``run_once`` must be self-contained (no ``typer.Exit`` escapes) so
      the loop can continue after a failing run.
    - ``notify`` receives user-facing status lines; defaults to ``print``.
    - ``clock`` is injectable for deterministic tests.

    Blocks until ``KeyboardInterrupt`` is raised inside the sleep, at which
    point the loop exits cleanly. The caller is responsible for any
    outer cleanup.
    """
    resolved_paths = [Path(p) for p in paths]
    emit = notify if notify is not None else print
    now = clock if clock is not None else datetime.now

    def _current_ignored() -> Iterable[Path]:
        if ignored_paths is None:
            return []
        if callable(ignored_paths):
            return ignored_paths()
        return ignored_paths

    emit(f"tddf watch · started at {now().strftime('%H:%M:%S')}")
    for path in resolved_paths:
        emit(f"tddf watch · watching {path}")

    last = _snapshot_mtimes(resolved_paths, _current_ignored())

    try:
        run_once()
        while True:
            time.sleep(interval)
            last, changed = detect_changes(last, resolved_paths, _current_ignored())
            if changed:
                changed_label = ", ".join(str(path) for path in changed)
                emit(
                    f"tddf watch · {now().strftime('%H:%M:%S')} · changed: "
                    f"{changed_label}"
                )
                run_once()
    except KeyboardInterrupt:
        emit("tddf watch · stopped.")
