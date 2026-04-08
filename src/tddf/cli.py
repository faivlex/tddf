from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import yaml
from rich.console import Console

from tddf import __version__
from tddf.config_loader import DEFAULT_CONFIG_PATH, ConfigError, load_config
from tddf.output import print_run_batch
from tddf.runner import execute_run
from tddf.target import describe_target, resolve_artifacts_dir


def _format_capabilities(capabilities: set[str]) -> str:
    return ", ".join(sorted(capabilities)) if capabilities else "none"


def _describe_scenario_requirements(loaded: object) -> list[tuple[str, str]]:
    return [
        (
            scenario.id,
            _format_capabilities(scenario.required_capabilities),
        )
        for scenario in loaded.scenario_definitions
    ]


def _normalize_for_output(payload: object) -> object:
    if isinstance(payload, Path):
        return str(payload)
    if isinstance(payload, dict):
        return {
            str(key): _normalize_for_output(value) for key, value in payload.items()
        }
    if isinstance(payload, list):
        return [_normalize_for_output(item) for item in payload]
    return payload


app = typer.Typer(
    help="TDDF: deterministic agent-trap evaluations for local command targets."
)
console = Console()


@app.command()
def validate(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
) -> None:
    """Validate a TDDF configuration file."""
    try:
        loaded = load_config(config)
    except ConfigError as error:
        console.print(f"[red]Invalid configuration:[/red] {error}")
        raise typer.Exit(code=1) from error

    console.print(
        f"[green]Configuration valid[/green] for target: {describe_target(loaded)}"
    )
    console.print(f"[green]Target kind:[/green] {loaded.target.kind}")
    console.print(
        f"[green]Target capabilities:[/green] {_format_capabilities(loaded.target_capabilities)}"
    )
    console.print(
        f"[green]Harness capabilities:[/green] {_format_capabilities(loaded.harness_capabilities)}"
    )
    console.print(f"[green]Scenarios:[/green] {len(loaded.scenario_definitions)}")
    console.print("[green]Scenario requirements:[/green]")
    for scenario_id, requirements in _describe_scenario_requirements(loaded):
        console.print(f"- {scenario_id}: {requirements}")
    if loaded.target.kind == "hermes":
        hermes_payload = yaml.safe_dump(
            _normalize_for_output(loaded.target.hermes.model_dump(mode="python")),
            sort_keys=False,
        ).strip()
        console.print("[green]Hermes options:[/green]")
        console.print(hermes_payload)
    if loaded.target.kind == "openclaw":
        openclaw_payload = yaml.safe_dump(
            _normalize_for_output(loaded.target.openclaw.model_dump(mode="python")),
            sort_keys=False,
        ).strip()
        console.print("[green]OpenClaw options:[/green]")
        console.print(openclaw_payload)


@app.command()
def run(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
) -> None:
    """Execute a deterministic TDDF evaluation."""
    try:
        loaded = load_config(config)
    except ConfigError as error:
        console.print(f"[red]Invalid configuration:[/red] {error}")
        raise typer.Exit(code=1) from error

    resolved_config_path = config.resolve()
    batch = asyncio.run(execute_run(loaded, resolved_config_path))
    artifacts_dir = resolve_artifacts_dir(loaded, resolved_config_path)
    artifacts = (
        {
            result.scenario_id: result.write_artifacts(artifacts_dir)
            for result in batch.results
        }
        if loaded.output.write_json
        else None
    )
    print_run_batch(
        batch,
        artifacts=artifacts,
        target_capabilities=loaded.target_capabilities,
        harness_capabilities=loaded.harness_capabilities,
        scenario_requirements={
            scenario.id: scenario.required_capabilities
            for scenario in loaded.scenario_definitions
        },
    )
    if batch.status in {"failed", "error", "timeout"}:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the installed TDDF version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
