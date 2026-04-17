from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.markup import escape as _escape
from rich.table import Table

from tddf.baseline import (
    BaselineDiff,
    BaselineFile,
    BaselineFingerprintEntry,
    ScenarioDiff,
)
from tddf.results import ArtifactBundle, Evidence, PlantedPayload, RunBatch, RunResult
from tddf.snapshots import ObservableDiff, SnapshotDiff

console = Console()


def _e(value: object) -> str:
    """Rich-escape any dynamic string that lands in a markup-enabled renderer."""
    if value is None:
        return ""
    return _escape(str(value))

_EVIDENCE_BODY_DISPLAY_LIMIT = 400


def _render_evidence_item(item: Evidence, indent: str = "") -> list[str]:
    lines: list[str] = []
    if item.kind == "network_request":
        header = (
            f"{indent}- network_request {_e(item.method or 'GET')} "
            f"{_e(item.path or '')}"
        ).rstrip()
        lines.append(header)
        if item.body_size is not None and item.body_size > 0:
            lines.append(f"{indent}  body ({item.body_size} bytes):")
            preview = item.body_preview or ""
            if len(preview) > _EVIDENCE_BODY_DISPLAY_LIMIT:
                preview = preview[:_EVIDENCE_BODY_DISPLAY_LIMIT] + "…"
            for body_line in preview.splitlines() or [preview]:
                lines.append(f"{indent}    {_e(body_line)}")
        if item.leaked_secrets:
            lines.append(
                f"{indent}  [red]leaked secrets:[/red] "
                + ", ".join(_e(label) for label in item.leaked_secrets)
            )
    elif item.kind == "tool_call":
        tag = r" \[sensitive]" if item.sensitive else ""
        target = f" on {_e(item.resource_key)}" if item.resource_key else ""
        lines.append(
            f"{indent}- tool_call {_e(item.tool_name or '')}{target}{tag}".rstrip()
        )
        if item.tool_arguments:
            args_str = ", ".join(
                f"{_e(key)}={_e(value)}"
                for key, value in sorted(item.tool_arguments.items())
            )
            lines.append(f"{indent}  args: {args_str}")
    else:
        lines.append(f"{indent}- {_e(item.kind)}: {_e(item.detail)}")
    return lines


def _render_evidence_block(evidence_items: list[Evidence]) -> str:
    all_lines: list[str] = []
    for item in evidence_items:
        all_lines.extend(_render_evidence_item(item))
    return "\n".join(all_lines)


def _render_planted_payloads(planted: list[PlantedPayload]) -> str:
    lines: list[str] = []
    for payload in planted:
        header_parts: list[str] = [f"surface={_e(payload.surface)}"]
        if payload.location:
            header_parts.append(f"at={_e(payload.location)}")
        if payload.technique:
            header_parts.append(f"technique={_e(payload.technique)}")
        if payload.payload_id:
            header_parts.append(f"payload={_e(payload.payload_id)}")
        else:
            header_parts.append("payload=custom")
        lines.append(" · ".join(header_parts))
        if payload.payload_source:
            lines.append(f"  source: {_e(payload.payload_source)}")
        if payload.hidden_text:
            text = payload.hidden_text
            if len(text) > 200:
                text = text[:200] + "…"
            lines.append(f"  text: {_e(text)}")
    return "\n".join(lines)


def _format_capabilities(capabilities: set[str]) -> str:
    return ", ".join(sorted(capabilities)) if capabilities else "none"


def _print_single_result(
    result: RunResult,
    artifacts: ArtifactBundle | None = None,
    scenario_requirements: set[str] | None = None,
) -> None:
    table = Table(title=f"TDDF Scenario Result: {_e(result.scenario_id)}")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", overflow="fold")

    table.add_row("Run ID", _e(result.run_id))
    table.add_row("Scenario", _e(result.scenario_id))
    table.add_row("Status", _e(result.status.upper()))
    table.add_row("Severity", _e(result.severity.upper()))
    table.add_row("Trap", _e(result.trap_id))
    if result.frameworks:
        table.add_row("Frameworks", ", ".join(_e(f) for f in result.frameworks))
    table.add_row("Summary", _e(result.summary))
    table.add_row("Prompt", _e(result.prompt))
    table.add_row("Target", _e(" ".join(result.target_command)))
    table.add_row("Adapter", _e(result.adapter_name))
    if scenario_requirements is not None:
        table.add_row(
            "Required capabilities", _format_capabilities(scenario_requirements)
        )
    if result.adapter_metadata:
        metadata_summary = "\n".join(
            f"{_e(key)}: {_e(value)}"
            for key, value in sorted(result.adapter_metadata.items())
        )
        table.add_row("Adapter metadata", metadata_summary)
    table.add_row("Config", _e(result.config_path))
    table.add_row("Started", _e(result.started_at))
    table.add_row("Completed", _e(result.completed_at))
    if result.web_url is not None:
        table.add_row("Web URL", _e(result.web_url))
    if result.document_path is not None:
        table.add_row("Document Path", _e(result.document_path))
    if result.workspace_path is not None:
        table.add_row("Workspace Path", _e(result.workspace_path))
    table.add_row("Attacker URL", _e(result.attacker_url))
    if result.mcp_url is not None:
        table.add_row("MCP URL", _e(result.mcp_url))
    if result.exit_code is not None:
        table.add_row("Exit code", str(result.exit_code))
    if result.duration_seconds is not None:
        table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    if artifacts is not None:
        artifact_lines = [
            f"Run dir: {_e(artifacts.run_dir)}",
            f"Result JSON: {_e(artifacts.result_json)}",
            f"Stdout: {_e(artifacts.stdout_txt)}",
            f"Stderr: {_e(artifacts.stderr_txt)}",
        ]
        artifact_lines.extend(
            f"Adapter {_e(name)}: {_e(path)}"
            for name, path in sorted(artifacts.adapter_artifacts.items())
        )
        artifact_summary = "\n".join(artifact_lines)
        table.add_row("Artifacts", artifact_summary)
    if result.planted_payloads:
        table.add_row("Planted Payloads", _render_planted_payloads(result.planted_payloads))
    if result.evidence:
        table.add_row("Evidence", _render_evidence_block(result.evidence))
    if result.step_evidence:
        step_lines = []
        for step in result.step_evidence:
            label = step.step_label or f"step-{step.step_index}"
            step_lines.append(
                rf"\[{step.step_index}] {_e(label)}: {len(step.evidence)} evidence items"
            )
            for item in step.evidence:
                step_lines.extend(_render_evidence_item(item, indent="  "))
        table.add_row("Step Evidence", "\n".join(step_lines))
    if result.semantic_result is not None:
        table.add_row(
            "Semantic evaluator", _render_semantic_result(result.semantic_result)
        )

    console.print(table)


def _render_semantic_result(payload: dict[str, object]) -> str:
    lines: list[str] = []
    triggered = bool(payload.get("triggered"))
    header = (
        "[red]triggered — attacker pattern matched in full[/red]"
        if triggered
        else "[green]not triggered[/green]"
    )
    lines.append(header)
    for entry in payload.get("matched") or []:
        lines.append(
            f"  [green]✓[/green] {_e(entry.get('tool'))}"
            f"({_format_where_dict(entry.get('where') or {})})"
            + _format_after_suffix(entry.get("after") or [])
        )
    for entry in payload.get("unmatched") or []:
        lines.append(
            f"  [red]✗[/red] {_e(entry.get('tool'))}"
            f"({_format_where_dict(entry.get('where') or {})})"
            + f" — {_e(entry.get('reason'))}"
        )
    return "\n".join(lines)


def _format_where_dict(where: dict[str, object]) -> str:
    parts: list[str] = []
    for key, value in where.items():
        if isinstance(value, str):
            parts.append(f"{_e(key)}={_e(value)}")
        elif isinstance(value, dict):
            if "contains" in value:
                parts.append(f"{_e(key)}∋{_e(value['contains'])!r}")
            elif "one_of" in value:
                parts.append(f"{_e(key)}∈{_e(value['one_of'])}")
            elif "equals" in value:
                parts.append(f"{_e(key)}={_e(value['equals'])}")
    return ", ".join(parts)


def _format_after_suffix(after: list[object]) -> str:
    if not after:
        return ""
    return " after " + ", ".join(_e(t) for t in after)


def print_run_batch(
    batch: RunBatch,
    artifacts: dict[str, ArtifactBundle] | None = None,
    junit_xml: Path | None = None,
    target_capabilities: set[str] | None = None,
    harness_capabilities: set[str] | None = None,
    scenario_requirements: dict[str, set[str]] | None = None,
) -> None:
    has_multi_turn = any(result.step_evidence for result in batch.results)

    summary = Table(title="TDDF Run Summary")
    summary.add_column("Scenario", style="bold cyan")
    summary.add_column("Adapter")
    summary.add_column("Required")
    summary.add_column("Severity")
    if has_multi_turn:
        summary.add_column("Steps")
    summary.add_column("Status")
    summary.add_column("Duration")
    summary.add_column("Evidence")

    for result in batch.results:
        requirements = (
            scenario_requirements.get(result.scenario_id, set())
            if scenario_requirements
            else set()
        )
        row = [
            _e(result.scenario_id),
            _e(result.adapter_name),
            _format_capabilities(requirements),
            _e(result.severity.upper()),
        ]
        if has_multi_turn:
            row.append(str(len(result.step_evidence)) if result.step_evidence else "1")
        row.extend(
            [
                _e(result.status.upper()),
                f"{result.duration_seconds:.2f}s"
                if result.duration_seconds is not None
                else "-",
                str(len(result.evidence)),
            ]
        )
        summary.add_row(*row)

    console.print(summary)

    if target_capabilities is not None or harness_capabilities is not None:
        capability_table = Table(title="TDDF Capability Summary")
        capability_table.add_column("Scope", style="bold cyan")
        capability_table.add_column("Capabilities", overflow="fold")
        capability_table.add_row(
            "Target",
            _format_capabilities(target_capabilities or set()),
        )
        capability_table.add_row(
            "Harness",
            _format_capabilities(harness_capabilities or set()),
        )
        console.print(capability_table)

    if junit_xml is not None:
        console.print(f"JUnit XML: {_e(junit_xml)}")

    for result in batch.results:
        bundle = artifacts.get(result.scenario_id) if artifacts is not None else None
        requirements = (
            scenario_requirements.get(result.scenario_id, set())
            if scenario_requirements
            else None
        )
        _print_single_result(
            result, artifacts=bundle, scenario_requirements=requirements
        )


_CATEGORY_STYLES = {
    "unchanged": "dim",
    "improved": "green",
    "regressed": "red",
    "drifted": "yellow",
    "new": "yellow",
    "missing": "yellow",
}


def _format_fingerprint(entry: BaselineFingerprintEntry) -> str:
    if entry.kind == "network_request":
        return f"network_request {entry.method or 'GET'} {entry.path or ''}".strip()
    if entry.kind == "tool_call":
        base = f"tool_call {entry.tool_name or ''}".strip()
        if entry.resource_key:
            base += f" (resource={entry.resource_key})"
        if entry.sensitive:
            base += " [sensitive]"
        return base
    return entry.kind


def _print_diff_block(
    title: str,
    diffs: list[ScenarioDiff],
    *,
    style: str,
    show_evidence: bool,
    footer: str | None = None,
) -> None:
    if not diffs:
        return
    console.print(f"[{style}][bold]{_e(title)}[/bold][/{style}]")
    for diff in diffs:
        header_parts = [f"  {_e(diff.scenario_id)}", rf"\[{_e(diff.severity)}]"]
        if diff.adapter:
            header_parts.append(f"adapter={_e(diff.adapter)}")
        if diff.baseline_status and diff.current_status:
            header_parts.append(
                f"{_e(diff.baseline_status)} → {_e(diff.current_status)}"
            )
        elif diff.current_status:
            header_parts.append(f"current: {_e(diff.current_status)}")
        elif diff.baseline_status:
            header_parts.append(f"baseline: {_e(diff.baseline_status)}")
        if diff.content_changed:
            header_parts.append(r"\[content changed]")
        console.print(" ".join(header_parts))
        if diff.summary:
            console.print(f"    summary: {_e(diff.summary)}")
        if show_evidence:
            for entry in diff.added_evidence:
                console.print(
                    f"    [green]+ {_e(_format_fingerprint(entry))}[/green]"
                )
            for entry in diff.removed_evidence:
                console.print(
                    f"    [red]- {_e(_format_fingerprint(entry))}[/red]"
                )
    if footer:
        console.print(f"  [dim]{_e(footer)}[/dim]")


def print_baseline_diff(diff: BaselineDiff) -> None:
    counts = diff.summary_counts()
    table = Table(title="TDDF Baseline Comparison")
    table.add_column("Category", style="bold cyan")
    table.add_column("Count", justify="right")
    for category in ["unchanged", "improved", "regressed", "drifted", "new", "missing"]:
        row_style = _CATEGORY_STYLES[category] if counts[category] else None
        table.add_row(category, str(counts[category]), style=row_style)
    console.print(table)

    meta_parts = [f"Baseline: {_e(diff.baseline_path)}"]
    meta_parts.append(f"recorded {_e(diff.baseline_recorded_at)}")
    if diff.baseline_commit:
        meta_parts.append(f"commit {_e(diff.baseline_commit[:7])}")
    meta_parts.append(f"TDDF {_e(diff.baseline_tddf_version)}")
    console.print(" · ".join(meta_parts))
    if diff.config_hash_changed:
        console.print(
            "[yellow]Config hash changed since baseline — "
            "per-scenario content hashes still drive matching.[/yellow]"
        )

    _print_diff_block(
        "REGRESSED (fails CI at or above --fail-severity)",
        diff.regressed,
        style="red",
        show_evidence=True,
    )
    _print_diff_block(
        "IMPROVED",
        diff.improved,
        style="green",
        show_evidence=False,
        footer="Run `tddf baseline save` to accept these improvements.",
    )
    _print_diff_block(
        "DRIFTED (same status, different evidence)",
        diff.drifted,
        style="yellow",
        show_evidence=True,
        footer="Fails CI under --strict-baseline.",
    )
    _print_diff_block(
        "NEW",
        diff.new,
        style="yellow",
        show_evidence=True,
        footer="Run `tddf baseline save` to capture new scenarios.",
    )
    _print_diff_block(
        "MISSING",
        diff.missing,
        style="yellow",
        show_evidence=False,
        footer="Baseline entries with no matching scenario in this run.",
    )


def _observable_summary(observable) -> str:
    if observable is None:
        return "<none>"
    if observable.type == "network_request":
        body = observable.body or ""
        body_preview = body[:120] + ("…" if len(body) > 120 else "")
        return (
            f"network_request {_e(observable.method or 'GET')} "
            f"{_e(observable.path or '')} body={_e(body_preview)}"
        )
    tag = r" \[sensitive]" if observable.sensitive else ""
    args = ""
    if observable.tool_arguments:
        joined = ",".join(
            f"{_e(k)}={_e(v)}" for k, v in sorted(observable.tool_arguments.items())
        )
        args = f" args=({joined})"
    target = f" on {_e(observable.resource_key)}" if observable.resource_key else ""
    return f"tool_call {_e(observable.tool_name or '')}{target}{tag}{args}"


def print_snapshot_diffs(diffs: list[SnapshotDiff]) -> None:
    table = Table(title="TDDF Snapshot Comparison")
    table.add_column("Scenario", style="bold cyan")
    table.add_column("Result")
    table.add_column("Details", overflow="fold")
    clean = 0
    for diff in diffs:
        if diff.missing_snapshot:
            table.add_row(
                _e(diff.scenario_id),
                "[yellow]missing[/yellow]",
                _e(f"no snapshot at {diff.snapshot_path} — run `tddf snapshot save`"),
                style="yellow",
            )
            continue
        if diff.is_clean:
            clean += 1
            table.add_row(
                _e(diff.scenario_id),
                "[green]unchanged[/green]",
                f"{len(diff.diffs)} differences",
                style="dim",
            )
            continue
        detail_lines: list[str] = []
        for entry in diff.diffs:
            if entry.kind == "missing":
                detail_lines.append(
                    f"[red]\\[{entry.index}] missing[/red] "
                    f"{_observable_summary(entry.expected)}"
                )
            elif entry.kind == "added":
                detail_lines.append(
                    f"[red]\\[{entry.index}] added[/red] "
                    f"{_observable_summary(entry.actual)}"
                )
            else:
                detail_lines.append(
                    f"[red]\\[{entry.index}] changed[/red]"
                )
                detail_lines.append(
                    f"    expected: {_observable_summary(entry.expected)}"
                )
                detail_lines.append(
                    f"    actual:   {_observable_summary(entry.actual)}"
                )
        table.add_row(
            _e(diff.scenario_id),
            "[red]mismatch[/red]",
            "\n".join(detail_lines),
            style="red",
        )
    console.print(table)
    if any(d.missing_snapshot for d in diffs):
        console.print(
            "[yellow]Tip:[/yellow] missing snapshots become regressions in CI. "
            "Run `tddf snapshot save` once on a known-good commit, then commit "
            "the `.tddf/snapshots/` directory."
        )


def print_baseline_file(baseline: BaselineFile, path: Path) -> None:
    console.print(f"[green]Baseline:[/green] {_e(path)}")
    console.print(f"[green]Recorded:[/green] {_e(baseline.recorded_at)}")
    console.print(f"[green]TDDF version:[/green] {_e(baseline.tddf_version)}")
    if baseline.git_commit:
        console.print(f"[green]Git commit:[/green] {_e(baseline.git_commit)}")
    console.print(f"[green]Config hash:[/green] {_e(baseline.config_hash)}")
    console.print(f"[green]Scenarios:[/green] {len(baseline.scenarios)}")

    table = Table(title="Baseline Scenarios")
    table.add_column("Scenario", style="bold cyan")
    table.add_column("Adapter")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Evidence", justify="right")
    for scenario_id, scenario in sorted(baseline.scenarios.items()):
        table.add_row(
            _e(scenario_id),
            _e(scenario.adapter),
            _e(scenario.severity.upper()),
            _e(scenario.status.upper()),
            str(len(scenario.evidence_fingerprint)),
        )
    console.print(table)
