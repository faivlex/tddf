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
from tddf.templates import TemplateAdapter, render_config


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
    help=(
        "TDDF — test whether your AI agent can be tricked into leaking data.\n\n"
        "Hosts trap content locally, runs your agent against it, and checks "
        "for exfiltration attempts and sensitive tool access. "
        "Pass/fail is deterministic: no LLM-as-judge."
    ),
    epilog=(
        "Examples:\n"
        "  tddf init --adapter command\n"
        "  tddf validate --config tddf.yaml\n"
        "  tddf run --config tddf.yaml\n\n"
        "Docs: https://github.com/your-org/tddf"
    ),
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
console = Console()


@app.command()
def init(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    adapter: TemplateAdapter = typer.Option(TemplateAdapter.COMMAND, "--adapter"),
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing config file."
    ),
) -> None:
    """Generate a starter config file for a target adapter (command, hermes, openclaw)."""
    resolved_config = config.resolve()
    if resolved_config.exists() and not force:
        console.print(
            f"[red]Refusing to overwrite existing config:[/red] {resolved_config}"
        )
        console.print("Re-run with [bold]--force[/bold] to overwrite it.")
        raise typer.Exit(code=1)

    resolved_config.parent.mkdir(parents=True, exist_ok=True)
    resolved_config.write_text(render_config(adapter))
    console.print(
        f"[green]Wrote starter config[/green] for adapter [bold]{adapter.value}[/bold]: {resolved_config}"
    )
    console.print("Next steps:")
    console.print(f"1. tddf validate --config {resolved_config}")
    console.print(f"2. tddf run --config {resolved_config}")


@app.command()
def validate(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
) -> None:
    """Check config shape, target capabilities, and scenario compatibility."""
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
    """Run all trap scenarios against your agent and report pass/fail results."""
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
    junit_xml = (
        batch.write_junit_xml(artifacts_dir) if loaded.output.write_junit else None
    )
    print_run_batch(
        batch,
        artifacts=artifacts,
        junit_xml=junit_xml,
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
