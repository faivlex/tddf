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


def _snapshot_mtimes(paths: Iterable[Path]) -> dict[Path, float | None]:
    """Return a ``{path: mtime}`` snapshot. Missing paths map to ``None``
    so they can reappear later and be detected as a change."""
    snapshot: dict[Path, float | None] = {}
    for path in paths:
        try:
            snapshot[path] = path.stat().st_mtime
        except FileNotFoundError:
            snapshot[path] = None
        except OSError:
            snapshot[path] = None
    return snapshot


def detect_changes(
    previous: dict[Path, float | None],
    paths: Iterable[Path],
) -> tuple[dict[Path, float | None], list[Path]]:
    """Compare the previous snapshot against a fresh one. Returns
    ``(current_snapshot, [paths_that_changed_or_appeared_or_disappeared])``.
    The first element is always returned so callers can carry it forward."""
    current = _snapshot_mtimes(paths)
    changed = [path for path, mtime in current.items() if previous.get(path) != mtime]
    return current, changed


def run_watch(
    paths: Iterable[Path],
    run_once: Callable[[], int],
    *,
    interval: float = 0.5,
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

    emit(f"tddf watch · started at {now().strftime('%H:%M:%S')}")
    for path in resolved_paths:
        emit(f"tddf watch · watching {path}")

    last = _snapshot_mtimes(resolved_paths)

    try:
        run_once()
        while True:
            time.sleep(interval)
            last, changed = detect_changes(last, resolved_paths)
            if changed:
                changed_label = ", ".join(str(path) for path in changed)
                emit(
                    f"tddf watch · {now().strftime('%H:%M:%S')} · changed: "
                    f"{changed_label}"
                )
                run_once()
    except KeyboardInterrupt:
        emit("tddf watch · stopped.")
