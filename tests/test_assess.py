from __future__ import annotations

import asyncio
from pathlib import Path

import yaml
from typer.testing import CliRunner

from tddf.assess import discover_capabilities, generate_assessment_config
from tddf.cli import app
from tddf.config_loader import load_config


ROOT = Path(".").resolve()
HERMES_BASE_HOME = ROOT / "tests/fixtures/hermes-home"
OPENCLAW_BASE_HOME = ROOT / "tests/fixtures/openclaw-home"
runner = CliRunner()


def _write_config(
    tmp_path: Path, raw: dict[str, object], name: str = "tddf.yaml"
) -> Path:
    config_path = tmp_path / name
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True))
    return config_path


def test_discover_capabilities_uses_structured_output(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "command",
                "command": ["python", "tests/fixtures/discovery_json_agent.py"],
                "cwd": str(ROOT),
                "env": {},
            },
            "mcp": {"enabled": False},
        },
        "structured.yaml",
    )
    config = load_config(config_path)

    discovery = asyncio.run(discover_capabilities(config, config_path))

    assert discovery.source == "structured_output"
    assert discovery.capabilities == {"web", "workspace"}


def test_discover_capabilities_uses_heuristic_output(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "command",
                "command": ["python", "tests/fixtures/discovery_text_agent.py"],
                "cwd": str(ROOT),
                "env": {},
            },
            "mcp": {"enabled": False},
        },
        "heuristic.yaml",
    )
    config = load_config(config_path)

    discovery = asyncio.run(discover_capabilities(config, config_path))

    assert discovery.source == "heuristic_output"
    assert discovery.capabilities == {"web", "workspace"}


def test_generate_assessment_config_is_deterministic(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "command",
                "command": ["python", "tests/fixtures/safe_agent.py"],
                "cwd": str(ROOT),
                "env": {},
            },
            "mcp": {"enabled": False},
        },
    )
    config = load_config(config_path)

    discovery = type("Discovery", (), {"capabilities": {"web", "workspace"}})()
    assessed = generate_assessment_config(config, discovery)

    assert [scenario.id for scenario in assessed.scenario_definitions] == [
        "assess-multi-turn-context",
        "assess-web-content-assess-web-html-comment",
        "assess-web-content-assess-web-base64",
        "assess-workspace-poisoning-assess-workspace-comment",
        "assess-workspace-poisoning-assess-workspace-base64",
    ]


def test_assess_command_passes_for_safe_command_target(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "command",
                "command": ["python", "tests/fixtures/safe_agent.py"],
                "cwd": str(ROOT),
                "env": {},
            },
            "mcp": {"enabled": False},
        },
        "command-safe.yaml",
    )
    generated_path = tmp_path / "generated.yaml"

    result = runner.invoke(
        app,
        [
            "assess",
            "--config",
            str(config_path),
            "--write-generated-config",
            str(generated_path),
        ],
    )

    assert result.exit_code == 0
    assert "Discovery source" in result.stdout
    assert "Generated scenarios" in result.stdout
    assert generated_path.exists()


def test_assess_command_fails_for_exfil_command_target(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "command",
                "command": ["python", "tests/fixtures/exfil_agent.py"],
                "cwd": str(ROOT),
                "env": {},
            },
            "mcp": {"enabled": False},
        },
        "command-exfil.yaml",
    )

    result = runner.invoke(app, ["assess", "--config", str(config_path)])

    assert result.exit_code == 1
    assert "FAILED" in result.stdout or "failed" in result.stdout.lower()


def test_assess_command_passes_for_mock_hermes(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "hermes",
                "cwd": str(ROOT),
                "env": {},
                "hermes": {
                    "command_prefix": ["python", "tests/fixtures/mock_hermes.py"],
                    "toolsets": ["web"],
                    "use_temp_home": True,
                    "base_home_dir": str(HERMES_BASE_HOME),
                    "inject_mcp_config": False,
                },
            },
            "mcp": {"enabled": False},
        },
        "hermes-assess.yaml",
    )

    result = runner.invoke(app, ["assess", "--config", str(config_path)])

    assert result.exit_code == 0
    assert "assess-web-content-assess-web-html-comment" in result.stdout


def test_assess_command_passes_for_mock_openclaw(tmp_path: Path) -> None:
    config_path = _write_config(
        tmp_path,
        {
            "target": {
                "kind": "openclaw",
                "cwd": str(ROOT),
                "env": {},
                "openclaw": {
                    "command_prefix": ["python", "tests/fixtures/mock_openclaw.py"],
                    "local": True,
                    "use_temp_home": True,
                    "base_home_dir": str(OPENCLAW_BASE_HOME),
                    "inject_mcp_config": False,
                },
            },
            "mcp": {"enabled": False},
        },
        "openclaw-assess.yaml",
    )

    result = runner.invoke(
        app, ["assess", "--config", str(config_path), "--fail-severity", "critical"]
    )

    assert result.exit_code == 0
    assert "Generated scenarios" in result.stdout
    assert "assess-oversight-evasion" in result.stdout
