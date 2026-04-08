from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tddf.cli import app
from tddf.config_loader import load_config


runner = CliRunner()


def test_help_mentions_init_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "init" in result.stdout
    assert "validate" in result.stdout
    assert "run" in result.stdout


def test_init_writes_loadable_command_template(tmp_path: Path) -> None:
    config_path = tmp_path / "tddf.yaml"

    result = runner.invoke(
        app,
        ["init", "--config", str(config_path), "--adapter", "command"],
    )

    assert result.exit_code == 0
    assert config_path.exists()

    config = load_config(config_path)
    assert config.target.kind == "command"
    assert config.target.command == ["tddf-safe-agent"]
    assert config.scenario_definitions[0].requires_mcp is True


def test_init_rejects_existing_file_without_force(tmp_path: Path) -> None:
    config_path = tmp_path / "tddf.yaml"
    config_path.write_text("target: {}\n")

    result = runner.invoke(app, ["init", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "Refusing to overwrite existing config" in result.stdout
