from __future__ import annotations

import asyncio
import json
import os
import sys
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
from tddf.baseline import (
    DEFAULT_BASELINE_PATH,
    BaselineBuildError,
    BaselineLoadError,
    build_baseline,
    compare,
    detect_git_commit,
    load_baseline,
    write_baseline,
)
from tddf.config_loader import DEFAULT_CONFIG_PATH, ConfigError, load_config
from tddf.importers.agentdojo import (
    DEFAULT_AGENTDOJO_LICENSE,
    DEFAULT_AGENTDOJO_REPO,
    DEFAULT_BENCHMARK_VERSION,
    AgentDojoImportError,
    AgentDojoImportRequest,
    AgentDojoSuite,
    import_agentdojo,
)
from tddf.importers.injecagent import (
    DEFAULT_INJECAGENT_LICENSE,
    DEFAULT_INJECAGENT_REPO,
    InjecAgentAttackKind,
    InjecAgentImportRequest,
    InjecAgentSetting,
    import_injecagent,
)
from tddf.output import (
    print_baseline_diff,
    print_baseline_file,
    print_run_batch,
    print_snapshot_diffs,
)
from tddf.registry import write_trap_registry
from tddf.runner import execute_run
from tddf.results import SEVERITY_RANK
from tddf.snapshots import (
    DEFAULT_SNAPSHOTS_DIR,
    SnapshotLoadError,
    build_snapshot,
    compare_snapshot_for_result,
    load_snapshot,
    snapshot_path_for,
    write_snapshot,
)
from tddf.target import describe_target, resolve_artifacts_dir
from tddf.templates import TemplateAdapter, render_config
from tddf.watch import run_watch


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
        "TDDF — behaviour regression tests for AI agents.\n\n"
        "Runs your agent against local mock servers with planted traps and checks "
        "deterministically whether the agent leaks data or abuses sensitive tools. "
        "Scenarios live in your repo. No LLM-as-judge. Nothing uploaded."
    ),
    epilog=(
        "Examples:\n"
        "  tddf init --adapter command\n"
        "  tddf validate --config tddf.yaml\n"
        "  tddf run --config tddf.yaml\n"
        "  tddf assess --config tddf.yaml\n\n"
        "Docs: https://github.com/gonzalosr/tddf"
    ),
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
import_app = typer.Typer(
    help="Import attack payloads from academic benchmarks into local registry files."
)
app.add_typer(import_app, name="import")
baseline_app = typer.Typer(
    help="Manage TDDF run baselines for regression detection."
)
app.add_typer(baseline_app, name="baseline")
snapshot_app = typer.Typer(
    help="Manage per-scenario observable snapshots (byte-exact regression gate)."
)
app.add_typer(snapshot_app, name="snapshot")
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
    if loaded.target.kind == "claude_agent_sdk":
        claude_agent_sdk_payload = yaml.safe_dump(
            _normalize_for_output(
                loaded.target.claude_agent_sdk.model_dump(mode="python")
            ),
            sort_keys=False,
            allow_unicode=True,
        ).strip()
        console.print("[green]Claude Agent SDK options:[/green]")
        console.print(claude_agent_sdk_payload)


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


@import_app.command("agentdojo")
def import_agentdojo_command(
    output: Path = typer.Option(..., "--output"),
    revision: str = typer.Option(
        ..., "--revision", help="Pinned AgentDojo commit, tag, or release ref."
    ),
    source_path: Path | None = typer.Option(
        None,
        "--source-path",
        exists=False,
        file_okay=False,
        dir_okay=True,
        help=(
            "Optional local AgentDojo checkout. When supplied, the importer "
            "adds it to sys.path before loading the package — use this to "
            "pin to a checkout rather than the installed version."
        ),
    ),
    suite: AgentDojoSuite = typer.Option(AgentDojoSuite.BANKING, "--suite"),
    benchmark_version: str = typer.Option(
        DEFAULT_BENCHMARK_VERSION,
        "--benchmark-version",
        help="AgentDojo benchmark version (e.g. v1.2.2).",
    ),
    limit: int | None = typer.Option(None, "--limit", min=1),
    source_repo: str = typer.Option(DEFAULT_AGENTDOJO_REPO, "--source-repo"),
    source_license: str = typer.Option(DEFAULT_AGENTDOJO_LICENSE, "--source-license"),
) -> None:
    """Import AgentDojo benchmark cases into a local registry file with provenance.

    Requires the optional 'agentdojo' dependency: ``pip install 'tddf[agentdojo]'``.
    """
    request = AgentDojoImportRequest(
        revision=revision,
        suite=suite,
        benchmark_version=benchmark_version,
        source_repo=source_repo,
        source_license=source_license,
        source_path=source_path.resolve() if source_path is not None else None,
        limit=limit,
    )
    try:
        registry = import_agentdojo(request)
    except AgentDojoImportError as error:
        console.print(f"[red]Import failed:[/red] {error}")
        raise typer.Exit(code=1) from error

    resolved_output = output.resolve()
    write_trap_registry(resolved_output, registry)
    console.print(
        f"[green]Imported[/green] {len(registry.traps)} AgentDojo traps to {resolved_output}"
    )
    console.print(
        f"[green]Source:[/green] {registry.source_repo}@{registry.source_revision} "
        f"(suite={suite.value}, version={benchmark_version})"
    )


def _execute_run_once(
    config: Path,
    fail_severity: str,
    baseline: Path | None,
    strict_baseline: bool,
    snapshot_compare: bool = False,
    snapshots_dir: Path = DEFAULT_SNAPSHOTS_DIR,
) -> int:
    """Core run logic shared between ``tddf run`` and ``tddf watch``.

    Returns an exit code (0 = clean, 1 = failures/regressions, 2 = baseline
    missing/corrupt) rather than raising ``typer.Exit`` so the watch loop
    can continue after a failing run. User-facing output is still written
    to the console.
    """
    if fail_severity not in SEVERITY_RANK:
        console.print(
            "[red]Invalid fail severity:[/red] choose one of critical, high, medium, low"
        )
        return 1
    if strict_baseline and baseline is None:
        console.print("[red]--strict-baseline requires --baseline.[/red]")
        return 1

    try:
        loaded = load_config(config)
    except ConfigError as error:
        console.print(f"[red]Invalid configuration:[/red] {error}")
        return 1

    baseline_file = None
    baseline_path_resolved: Path | None = None
    if baseline is not None:
        baseline_path_resolved = baseline.resolve()
        try:
            baseline_file = load_baseline(baseline_path_resolved)
        except BaselineLoadError as error:
            console.print(f"[red]Cannot load baseline:[/red] {error}")
            return 2

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

    snapshot_fail = False
    if snapshot_compare:
        resolved_snapshots_dir = snapshots_dir.resolve()
        snapshot_diffs = []
        for result in batch.results:
            scenarios_by_id = {
                s.id: s for s in loaded.scenario_definitions
            }
            scenario = scenarios_by_id.get(result.scenario_id)
            if scenario is None or not scenario.snapshot:
                continue
            try:
                diff = compare_snapshot_for_result(result, resolved_snapshots_dir)
            except SnapshotLoadError as error:
                console.print(f"[red]Cannot load snapshot:[/red] {error}")
                return 2
            snapshot_diffs.append(diff)
            if not diff.is_clean:
                snapshot_fail = True
        if snapshot_diffs:
            print_snapshot_diffs(snapshot_diffs)
            run_dir = artifacts_dir / batch.run_id
            run_dir.mkdir(parents=True, exist_ok=True)
            diff_path = run_dir / "snapshot-diffs.json"
            diff_path.write_text(
                json.dumps([d.to_dict() for d in snapshot_diffs], indent=2) + "\n"
            )
            console.print(f"Snapshot diffs JSON: {diff_path}")

    if baseline_file is not None:
        assert baseline_path_resolved is not None
        diff = compare(
            baseline_file, batch, loaded, baseline_path=baseline_path_resolved
        )
        print_baseline_diff(diff)
        run_dir = artifacts_dir / batch.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        diff_path = run_dir / "baseline-diff.json"
        diff_path.write_text(json.dumps(diff.to_dict(), indent=2) + "\n")
        console.print(f"Baseline diff JSON: {diff_path}")
        baseline_fail = diff.should_fail(fail_severity, strict=strict_baseline)
        return 1 if baseline_fail or snapshot_fail else 0

    return 1 if batch.should_fail(fail_severity) or snapshot_fail else 0


@app.command()
def run(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    fail_severity: str = typer.Option(
        "low",
        "--fail-severity",
        help="Exit non-zero only for failures at or above this severity (errors and timeouts always fail).",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Optional path to a saved baseline. With --baseline, the run exits non-zero only on regressions (and error/timeout).",
    ),
    strict_baseline: bool = typer.Option(
        False,
        "--strict-baseline",
        help="Under --baseline, also fail the run on drift, missing scenarios, and new-failing scenarios.",
    ),
    snapshot_compare: bool = typer.Option(
        False,
        "--snapshot",
        help="Compare observables against saved snapshots for scenarios with snapshot: true; fail on mismatch.",
    ),
    snapshots_dir: Path = typer.Option(
        DEFAULT_SNAPSHOTS_DIR,
        "--snapshots-dir",
        help="Directory holding per-scenario snapshot files (used with --snapshot).",
    ),
) -> None:
    """Run scenarios and report pass/fail. With --baseline, compare to the saved baseline and gate on regressions."""
    code = _execute_run_once(
        config,
        fail_severity,
        baseline,
        strict_baseline,
        snapshot_compare=snapshot_compare,
        snapshots_dir=snapshots_dir,
    )
    if code != 0:
        raise typer.Exit(code=code)


@app.command()
def watch(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    fail_severity: str = typer.Option(
        "low",
        "--fail-severity",
        help="Exit non-zero only for failures at or above this severity (informational in watch mode; does not stop the loop).",
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Optional path to a saved baseline. With --baseline, each run reports regressions.",
    ),
    strict_baseline: bool = typer.Option(
        False,
        "--strict-baseline",
        help="Under --baseline, also treat drift / missing / new-failing as regressions.",
    ),
    snapshot_compare: bool = typer.Option(
        False,
        "--snapshot",
        help="Compare observables against saved snapshots each re-run.",
    ),
    snapshots_dir: Path = typer.Option(
        DEFAULT_SNAPSHOTS_DIR,
        "--snapshots-dir",
        help="Directory holding per-scenario snapshot files (used with --snapshot).",
    ),
    watch_path: list[Path] = typer.Option(
        None,
        "--watch",
        help="Additional path to watch for changes. Repeat for multiple paths. The config file is always watched.",
    ),
    interval: float = typer.Option(
        0.5,
        "--interval",
        help="Poll interval in seconds.",
        min=0.05,
        max=30.0,
    ),
) -> None:
    """Watch the config (and --watch paths) and re-run scenarios when any change. Ctrl-C to stop."""
    watched: list[Path] = [config]
    if watch_path:
        watched.extend(watch_path)
    watched = [path.resolve() for path in watched]

    def _once() -> int:
        return _execute_run_once(
            config,
            fail_severity,
            baseline,
            strict_baseline,
            snapshot_compare=snapshot_compare,
            snapshots_dir=snapshots_dir,
        )

    run_watch(
        watched,
        run_once=_once,
        interval=interval,
        notify=lambda line: console.print(f"[bold cyan]{line}[/bold cyan]"),
    )


@snapshot_app.command("save")
def snapshot_save_command(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    snapshots_dir: Path = typer.Option(
        DEFAULT_SNAPSHOTS_DIR,
        "--snapshots-dir",
        help="Directory to write per-scenario snapshot files into.",
    ),
) -> None:
    """Record snapshots for every scenario that has ``snapshot: true``."""
    try:
        loaded = load_config(config)
    except ConfigError as error:
        console.print(f"[red]Invalid configuration:[/red] {error}")
        raise typer.Exit(code=1) from error

    snapshot_ids = {
        scenario.id
        for scenario in loaded.scenario_definitions
        if scenario.snapshot
    }
    if not snapshot_ids:
        console.print(
            "[yellow]No scenarios have `snapshot: true`.[/yellow] "
            "Set the flag on the scenarios you want byte-exact regression gating for, "
            "then re-run this command."
        )
        raise typer.Exit(code=1)

    resolved_config_path = config.resolve()
    batch = asyncio.run(execute_run(loaded, resolved_config_path))
    resolved_snapshots_dir = snapshots_dir.resolve()

    written: list[Path] = []
    for result in batch.results:
        if result.scenario_id not in snapshot_ids:
            continue
        if result.status in {"error", "timeout"}:
            console.print(
                f"[yellow]Skipping {result.scenario_id}:[/yellow] "
                f"result status is {result.status}."
            )
            continue
        snap = build_snapshot(result)
        out = snapshot_path_for(result.scenario_id, resolved_snapshots_dir)
        write_snapshot(out, snap)
        written.append(out)

    if not written:
        console.print(
            "[red]No snapshots were written — every snapshot-enabled scenario "
            "errored or timed out.[/red]"
        )
        raise typer.Exit(code=2)

    console.print(
        f"[green]Wrote {len(written)} snapshot(s) to[/green] "
        f"{resolved_snapshots_dir}"
    )
    for path in written:
        console.print(f"- {path}")


@snapshot_app.command("show")
def snapshot_show_command(
    scenario_id: str = typer.Argument(
        ..., help="Scenario id whose snapshot should be pretty-printed."
    ),
    snapshots_dir: Path = typer.Option(
        DEFAULT_SNAPSHOTS_DIR,
        "--snapshots-dir",
        help="Directory holding per-scenario snapshot files.",
    ),
) -> None:
    """Pretty-print a saved snapshot file."""
    path = snapshot_path_for(scenario_id, snapshots_dir.resolve())
    try:
        snap = load_snapshot(path)
    except SnapshotLoadError as error:
        console.print(f"[red]Cannot load snapshot:[/red] {error}")
        raise typer.Exit(code=2) from error

    console.print(f"[green]Snapshot:[/green] {path}")
    console.print(f"[green]Scenario:[/green] {snap.scenario_id}")
    console.print(f"[green]Recorded:[/green] {snap.recorded_at}")
    console.print(f"[green]TDDF version:[/green] {snap.tddf_version}")
    console.print(f"[green]Observables:[/green] {len(snap.observables)}")
    for index, observable in enumerate(snap.observables):
        console.print(f"[bold]\\[{index}][/bold] {observable.type}")
        dump = observable.model_dump(mode="json", exclude_none=True)
        dump.pop("type", None)
        for key, value in dump.items():
            console.print(f"  {key}: {value}")


@app.command("install-hook")
def install_hook_command(
    stage: str = typer.Option(
        "pre-push",
        "--stage",
        help="Git hook stage. Use 'pre-push' (default, recommended) or 'pre-commit' (slower commit loop).",
    ),
    config: Path = typer.Option(
        DEFAULT_CONFIG_PATH,
        "--config",
        help="Config path the installed hook will reference.",
    ),
    baseline: Path = typer.Option(
        DEFAULT_BASELINE_PATH,
        "--baseline",
        help="Baseline path the installed hook will consult if it exists.",
    ),
    fail_severity: str = typer.Option(
        "high",
        "--fail-severity",
        help="Severity gate the installed hook will use.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing hook at this stage.",
    ),
) -> None:
    """Install a native git hook (pre-push by default) that runs TDDF on each push / commit."""
    if stage not in {"pre-push", "pre-commit"}:
        console.print(
            "[red]Invalid stage:[/red] choose 'pre-push' or 'pre-commit'."
        )
        raise typer.Exit(code=1)
    if fail_severity not in SEVERITY_RANK:
        console.print(
            "[red]Invalid fail severity:[/red] choose one of critical, high, medium, low"
        )
        raise typer.Exit(code=1)

    git_dir = Path(".git")
    hooks_dir = git_dir / "hooks"
    if not git_dir.is_dir():
        console.print("[red]Not a git repository:[/red] no .git directory found.")
        raise typer.Exit(code=1)
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_path = hooks_dir / stage
    if hook_path.exists() and not force:
        console.print(
            f"[red]Refusing to overwrite existing hook:[/red] {hook_path}"
        )
        console.print("Re-run with [bold]--force[/bold] to overwrite it.")
        raise typer.Exit(code=1)

    script = _render_hook_script(config, baseline, fail_severity)
    hook_path.write_text(script)
    hook_path.chmod(0o755)
    console.print(
        f"[green]Installed[/green] {stage} hook at [bold]{hook_path}[/bold]"
    )
    console.print(
        f"  runs: tddf run --config {config} "
        f"(with --baseline {baseline} if present) "
        f"--fail-severity {fail_severity}"
    )


def _render_hook_script(
    config: Path,
    baseline: Path,
    fail_severity: str,
) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "# Installed by `tddf install-hook`. Safe to delete.\n"
        "set -e\n"
        "if ! command -v tddf >/dev/null 2>&1; then\n"
        '    echo "tddf not in PATH — skipping TDDF hook" >&2\n'
        "    exit 0\n"
        "fi\n"
        f'if [ -f "{baseline}" ]; then\n'
        f'    exec tddf run --config "{config}" --baseline "{baseline}" '
        f'--fail-severity "{fail_severity}"\n'
        "else\n"
        f'    exec tddf run --config "{config}" --fail-severity "{fail_severity}"\n'
        "fi\n"
    )


@baseline_app.command("save")
def baseline_save_command(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    baseline: Path = typer.Option(
        DEFAULT_BASELINE_PATH,
        "--baseline",
        help="Path to write the baseline file.",
    ),
    include_errors: bool = typer.Option(
        False,
        "--include-errors",
        help="Save the baseline even if some scenarios errored or timed out (not recommended).",
    ),
) -> None:
    """Run all scenarios once and save the results as a new baseline for future regression detection."""
    try:
        loaded = load_config(config)
    except ConfigError as error:
        console.print(f"[red]Invalid configuration:[/red] {error}")
        raise typer.Exit(code=1) from error

    resolved_config_path = config.resolve()
    batch = asyncio.run(execute_run(loaded, resolved_config_path))

    git_commit = detect_git_commit(cwd=resolved_config_path.parent)
    try:
        baseline_file = build_baseline(
            batch, loaded, git_commit=git_commit, include_errors=include_errors
        )
    except BaselineBuildError as error:
        console.print(f"[red]Baseline not saved:[/red] {error}")
        raise typer.Exit(code=2) from error

    resolved_baseline_path = baseline.resolve()
    write_baseline(resolved_baseline_path, baseline_file)

    passed = sum(
        1 for entry in baseline_file.scenarios.values() if entry.status == "passed"
    )
    failed = sum(
        1 for entry in baseline_file.scenarios.values() if entry.status == "failed"
    )
    console.print(
        f"[green]Saved baseline[/green] for {len(baseline_file.scenarios)} scenario(s) "
        f"to {resolved_baseline_path}"
    )
    if git_commit:
        console.print(f"[green]Git commit:[/green] {git_commit}")
    console.print(
        f"[green]Baseline status:[/green] {passed} passed, {failed} failed"
    )


@baseline_app.command("show")
def baseline_show_command(
    baseline: Path = typer.Option(
        DEFAULT_BASELINE_PATH,
        "--baseline",
        help="Path to the baseline file.",
    ),
) -> None:
    """Pretty-print a saved baseline."""
    resolved = baseline.resolve()
    try:
        baseline_file = load_baseline(resolved)
    except BaselineLoadError as error:
        console.print(f"[red]Cannot load baseline:[/red] {error}")
        raise typer.Exit(code=2) from error

    print_baseline_file(baseline_file, resolved)


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
    """Probe an agent's capabilities and generate a starter scenario set — useful for bootstrapping a regression suite."""
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


@app.command("mcp-server")
def mcp_server_command(
    config: Path = typer.Option(DEFAULT_CONFIG_PATH, "--config", exists=False),
    capture_file: Path | None = typer.Option(
        None,
        "--capture-file",
        help=(
            "Path to write captured tool-call records as JSON Lines. "
            "Defaults to $TDDF_MCP_CAPTURE_FILE if set."
        ),
    ),
) -> None:
    """Run TDDF as an MCP server over stdio.

    Invoked as a subprocess by agent MCP clients (e.g. Claude Agent SDK).
    Reads JSON-RPC 2.0 requests from stdin, writes responses to stdout,
    and appends every captured tool-call record to ``--capture-file`` so
    the parent ``tddf run`` process can merge them into its evaluator
    view after the agent exits.
    """
    # Prefer TDDF_CONFIG_PATH from the subprocess env (set by ``tddf run``)
    # over the default so the stdio server uses the same config as the
    # running scenario when the user relies on defaults.
    if config == DEFAULT_CONFIG_PATH and os.environ.get("TDDF_CONFIG_PATH"):
        config = Path(os.environ["TDDF_CONFIG_PATH"])

    try:
        loaded = load_config(config)
    except ConfigError as error:
        print(f"tddf mcp-server: invalid config: {error}", file=sys.stderr)
        raise typer.Exit(code=1) from error

    if capture_file is None:
        env_capture = os.environ.get("TDDF_MCP_CAPTURE_FILE")
        if env_capture:
            capture_file = Path(env_capture)

    # Deferred import so tddf's main CLI path doesn't eagerly load the
    # stdio module if it's never used.
    from tddf.mcp_stdio import run_stdio_server

    run_stdio_server(loaded.mcp, capture_file)


if __name__ == "__main__":
    app()
