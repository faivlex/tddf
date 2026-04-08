from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tddf.config_loader import ConfigError, load_config


ROOT = Path(".").resolve()


HERMES_TARGET = {
    "kind": "hermes",
    "cwd": str(ROOT),
    "env": {},
    "hermes": {
        "command_prefix": ["python", "tests/fixtures/mock_hermes.py"],
        "toolsets": ["web", "file", "terminal"],
        "model": "demo-model",
        "provider": "demo-provider",
        "use_temp_home": True,
        "inject_mcp_config": True,
    },
}


def _write_config(tmp_path: Path, raw: dict[str, object], name: str = "tddf.yaml") -> Path:
    config_path = tmp_path / name
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    return config_path


def test_load_default_config_exposes_expected_capabilities() -> None:
    config = load_config(Path("tddf.yaml"))

    assert config.target.kind == "command"
    assert config.target_capabilities == {"web", "document", "deputy", "workspace", "mcp"}
    assert config.harness_capabilities == {"mcp"}
    assert [scenario.id for scenario in config.scenario_definitions] == [
        "hidden-content-exfiltration",
        "metadata-obfuscation-demo",
        "markdown-masking-demo",
        "poisoned-workspace-search",
        "confused-deputy-finance-demo",
    ]
    assert [scenario.required_capabilities for scenario in config.scenario_definitions] == [
        {"web", "mcp"},
        {"web", "mcp"},
        {"document", "mcp"},
        {"workspace", "mcp"},
        {"deputy"},
    ]


def test_load_config_rejects_hermes_mcp_injection_without_temp_home(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = {
        "kind": "hermes",
        "cwd": str(ROOT),
        "env": {},
        "hermes": {
            "command_prefix": ["python", "tests/fixtures/mock_hermes.py"],
            "use_temp_home": False,
            "inject_mcp_config": True,
        },
    }
    config_path = _write_config(tmp_path, raw, "invalid-hermes.yaml")

    with pytest.raises(ConfigError, match="use_temp_home"):
        load_config(config_path)


def test_load_config_accepts_mcp_capable_hermes_target(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = HERMES_TARGET
    config_path = _write_config(tmp_path, raw, "hermes.yaml")

    config = load_config(config_path)

    assert config.target.kind == "hermes"
    assert config.target_capabilities == {"web", "document", "deputy", "workspace", "mcp"}


def test_mcp_required_scenario_rejects_disabled_harness(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["mcp"]["enabled"] = False
    raw["scenarios"][0]["requires_mcp"] = True
    config_path = _write_config(tmp_path, raw, "mcp-disabled.yaml")

    with pytest.raises(ConfigError, match="TDDF harness lacks 'mcp' capability"):
        load_config(config_path)
