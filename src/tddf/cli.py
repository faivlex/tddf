from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
import yaml
from rich.console import Console

from tddf import __version__
from tddf.assess import (
    discover_capabilities,
    generate_assessment_config,
    generated_scenario_summary,
)
from tddf.config_loader import DEFAULT_CONFIG_PATH, ConfigError, load_config
from tddf.importers.injecagent import (
    DEFAULT_INJECAGENT_LICENSE,
    DEFAULT_INJECAGENT_REPO,
    InjecAgentAttackKind,
    InjecAgentImportRequest,
    InjecAgentSetting,
    import_injecagent,
)
from tddf.output import print_run_batch
from tddf.registry import write_trap_registry
from tddf.runner import execute_run
from tddf.results import SEVERITY_RANK
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
        "  tddf run --config tddf.yaml\n"
        "  tddf assess --config tddf.yaml\n\n"
        "Docs: https://github.com/your-org/tddf"
    ),
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
import_app = typer.Typer(
    help="Import attack payloads from academic benchmarks into local registry files."
)
app.add_typer(import_app, name="import")
console = Console()


@app.command()
def init(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config"),
    adapter: TemplateAdapter = typer.Option(TemplateAdapter.COMMAND, "--adapter"),
    force: bool = typer.Option(
        False, "--force", help="Overwrite an existing config file."
    ),
) -> None:
    """Generate a starter config file for a target adapter."""
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
    if loaded.target.kind == "langgraph":
        langgraph_payload = yaml.safe_dump(
            _normalize_for_output(loaded.target.langgraph.model_dump(mode="python")),
            sort_keys=False,
            allow_unicode=True,
        ).strip()
        console.print("[green]LangGraph options:[/green]")
        console.print(langgraph_payload)
    if loaded.target.kind == "openai_agents":
        openai_agents_payload = yaml.safe_dump(
            _normalize_for_output(
                loaded.target.openai_agents.model_dump(mode="python")
            ),
            sort_keys=False,
            allow_unicode=True,
        ).strip()
        console.print("[green]OpenAI Agents options:[/green]")
        console.print(openai_agents_payload)


@import_app.command("injecagent")
def import_injecagent_command(
    output: Path = typer.Option(..., "--output"),
    revision: str = typer.Option(
        ..., "--revision", help="Pinned InjecAgent commit, tag, or branch ref."
    ),
    source_path: Path | None = typer.Option(
        None,
        "--source-path",
        exists=False,
        file_okay=False,
        dir_okay=True,
        help="Optional local InjecAgent checkout or fixture directory.",
    ),
    attack_kind: InjecAgentAttackKind = typer.Option(
        InjecAgentAttackKind.DATA_STEALING, "--attack-kind"
    ),
    setting: InjecAgentSetting = typer.Option(InjecAgentSetting.BASE, "--setting"),
    limit: int | None = typer.Option(None, "--limit", min=1),
    source_repo: str = typer.Option(DEFAULT_INJECAGENT_REPO, "--source-repo"),
    source_license: str = typer.Option(DEFAULT_INJECAGENT_LICENSE, "--source-license"),
) -> None:
    """Import InjecAgent benchmark cases into a local registry file with provenance."""
    request = InjecAgentImportRequest(
        revision=revision,
        attack_kind=attack_kind,
        setting=setting,
        source_repo=source_repo,
        source_license=source_license,
        source_path=source_path.resolve() if source_path is not None else None,
        limit=limit,
    )
    try:
        registry = import_injecagent(request)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as error:
        console.print(f"[red]Import failed:[/red] {error}")
        raise typer.Exit(code=1) from error

    resolved_output = output.resolve()
    write_trap_registry(resolved_output, registry)
    console.print(
        f"[green]Imported[/green] {len(registry.traps)} InjecAgent traps to {resolved_output}"
    )
    console.print(
        f"[green]Source:[/green] {registry.source_repo}@{registry.source_revision}"
    )


@app.command()
def run(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    fail_severity: str = typer.Option(
        "low",
        "--fail-severity",
        help="Exit non-zero only for failures at or above this severity (errors and timeouts always fail).",
    ),
) -> None:
    """Run all trap scenarios against your agent and report pass/fail results."""
    if fail_severity not in SEVERITY_RANK:
        console.print(
            "[red]Invalid fail severity:[/red] choose one of critical, high, medium, low"
        )
        raise typer.Exit(code=1)
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
    if batch.should_fail(fail_severity):
        raise typer.Exit(code=1)


@app.command()
def assess(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    fail_severity: str = typer.Option(
        "low",
        "--fail-severity",
        help="Exit non-zero only for failures at or above this severity (errors and timeouts always fail).",
    ),
    write_generated_config: Path | None = typer.Option(
        None,
        "--write-generated-config",
        help="Optional path to write the generated assessment config for reproducibility.",
    ),
) -> None:
    """Point TDDF at your agent and let it figure out what to test — no manual scenario authoring needed."""
    if fail_severity not in SEVERITY_RANK:
        console.print(
            "[red]Invalid fail severity:[/red] choose one of critical, high, medium, low"
        )
        raise typer.Exit(code=1)
    try:
        loaded = load_config(config)
    except ConfigError as error:
        console.print(f"[red]Invalid configuration:[/red] {error}")
        raise typer.Exit(code=1) from error

    resolved_config_path = config.resolve()
    discovery = asyncio.run(discover_capabilities(loaded, resolved_config_path))
    assessed = generate_assessment_config(loaded, discovery)

    if write_generated_config is not None:
        resolved_generated_path = write_generated_config.resolve()
        resolved_generated_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_generated_path.write_text(
            yaml.safe_dump(
                _normalize_for_output(assessed.model_dump(mode="python")),
                sort_keys=False,
                allow_unicode=True,
            )
        )
        console.print(
            f"[green]Wrote generated assessment config:[/green] {resolved_generated_path}"
        )

    console.print(f"[green]Discovery source:[/green] {discovery.source}")
    console.print(
        f"[green]Discovered capabilities:[/green] {_format_capabilities(assessed.target_capabilities & set(discovery.capabilities))}"
    )
    console.print(
        f"[green]Generated scenarios:[/green] {len(assessed.scenario_definitions)}"
    )
    for scenario_id in generated_scenario_summary(assessed):
        console.print(f"- {scenario_id}")

    batch = asyncio.run(execute_run(assessed, resolved_config_path))
    artifacts_dir = resolve_artifacts_dir(assessed, resolved_config_path)
    artifacts = (
        {
            result.scenario_id: result.write_artifacts(artifacts_dir)
            for result in batch.results
        }
        if assessed.output.write_json
        else None
    )
    junit_xml = (
        batch.write_junit_xml(artifacts_dir) if assessed.output.write_junit else None
    )
    print_run_batch(
        batch,
        artifacts=artifacts,
        junit_xml=junit_xml,
        target_capabilities=assessed.target_capabilities,
        harness_capabilities=assessed.harness_capabilities,
        scenario_requirements={
            scenario.id: scenario.required_capabilities
            for scenario in assessed.scenario_definitions
        },
    )
    if batch.should_fail(fail_severity):
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the installed TDDF version."""
    console.print(__version__)


if __name__ == "__main__":
    app()
