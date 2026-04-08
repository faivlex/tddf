from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from tddf.results import ArtifactBundle, RunBatch, RunResult

console = Console()


def _format_capabilities(capabilities: set[str]) -> str:
    return ", ".join(sorted(capabilities)) if capabilities else "none"


def _print_single_result(
    result: RunResult,
    artifacts: ArtifactBundle | None = None,
    scenario_requirements: set[str] | None = None,
) -> None:
    table = Table(title=f"TDDF Scenario Result: {result.scenario_id}")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", overflow="fold")

    table.add_row("Run ID", result.run_id)
    table.add_row("Scenario", result.scenario_id)
    table.add_row("Status", result.status.upper())
    table.add_row("Trap", result.trap_id)
    table.add_row("Summary", result.summary)
    table.add_row("Target", " ".join(result.target_command))
    table.add_row("Adapter", result.adapter_name)
    if scenario_requirements is not None:
        table.add_row(
            "Required capabilities", _format_capabilities(scenario_requirements)
        )
    if result.adapter_metadata:
        metadata_summary = "\n".join(
            f"{key}: {value}" for key, value in sorted(result.adapter_metadata.items())
        )
        table.add_row("Adapter metadata", metadata_summary)
    table.add_row("Config", result.config_path)
    table.add_row("Started", result.started_at)
    table.add_row("Completed", result.completed_at)
    if result.web_url is not None:
        table.add_row("Web URL", result.web_url)
    if result.document_path is not None:
        table.add_row("Document Path", result.document_path)
    if result.workspace_path is not None:
        table.add_row("Workspace Path", result.workspace_path)
    table.add_row("Attacker URL", result.attacker_url)
    if result.mcp_url is not None:
        table.add_row("MCP URL", result.mcp_url)
    if result.exit_code is not None:
        table.add_row("Exit code", str(result.exit_code))
    if result.duration_seconds is not None:
        table.add_row("Duration", f"{result.duration_seconds:.2f}s")
    if artifacts is not None:
        artifact_lines = [
            f"Run dir: {artifacts.run_dir}",
            f"Result JSON: {artifacts.result_json}",
            f"Stdout: {artifacts.stdout_txt}",
            f"Stderr: {artifacts.stderr_txt}",
        ]
        artifact_lines.extend(
            f"Adapter {name}: {path}"
            for name, path in sorted(artifacts.adapter_artifacts.items())
        )
        artifact_summary = "\n".join(artifact_lines)
        table.add_row("Artifacts", artifact_summary)
    if result.evidence:
        evidence_summary = "\n".join(
            f"- {item.kind}: {item.detail}" for item in result.evidence
        )
        table.add_row("Evidence", evidence_summary)

    console.print(table)


def print_run_batch(
    batch: RunBatch,
    artifacts: dict[str, ArtifactBundle] | None = None,
    junit_xml: Path | None = None,
    target_capabilities: set[str] | None = None,
    harness_capabilities: set[str] | None = None,
    scenario_requirements: dict[str, set[str]] | None = None,
) -> None:
    summary = Table(title="TDDF Run Summary")
    summary.add_column("Scenario", style="bold cyan")
    summary.add_column("Adapter")
    summary.add_column("Required")
    summary.add_column("Status")
    summary.add_column("Duration")
    summary.add_column("Evidence")

    for result in batch.results:
        requirements = (
            scenario_requirements.get(result.scenario_id, set())
            if scenario_requirements
            else set()
        )
        summary.add_row(
            result.scenario_id,
            result.adapter_name,
            _format_capabilities(requirements),
            result.status.upper(),
            f"{result.duration_seconds:.2f}s"
            if result.duration_seconds is not None
            else "-",
            str(len(result.evidence)),
        )

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
        console.print(f"JUnit XML: {junit_xml}")

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
