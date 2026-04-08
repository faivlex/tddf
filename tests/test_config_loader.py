from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from tddf.config_loader import ConfigError, load_config


ROOT = Path(".").resolve()
CLAUDE_AGENT_SDK_PYTHONPATH = os.pathsep.join(
    [
        str((ROOT / "tests/fixtures/claude_agent_sdk").resolve()),
        os.environ.get("PYTHONPATH", ""),
    ]
)
OPENAI_AGENTS_PYTHONPATH = os.pathsep.join(
    [
        str((ROOT / "tests/fixtures/openai_agents_sdk").resolve()),
        os.environ.get("PYTHONPATH", ""),
    ]
)


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


OPENCLAW_TARGET = {
    "kind": "openclaw",
    "cwd": str(ROOT),
    "env": {},
    "openclaw": {
        "command_prefix": ["python", "tests/fixtures/mock_openclaw.py"],
        "local": True,
        "use_temp_home": True,
        "inject_mcp_config": True,
    },
}


LANGGRAPH_TARGET = {
    "kind": "langgraph",
    "cwd": str(ROOT),
    "env": {},
    "langgraph": {
        "graph": "tests.fixtures.mock_langgraph:safe_graph",
        "capabilities": ["web", "workspace", "mcp"],
        "input_mode": "messages",
        "stream_modes": ["values", "updates", "custom"],
        "use_thread_id": True,
    },
}


OPENAI_AGENTS_TARGET = {
    "kind": "openai_agents",
    "cwd": str(ROOT),
    "env": {"PYTHONPATH": OPENAI_AGENTS_PYTHONPATH},
    "openai_agents": {
        "agent": "tests.fixtures.mock_openai_agents_app:safe_agent",
        "capabilities": ["web", "workspace", "mcp"],
        "input_mode": "prompt",
        "max_turns": 12,
        "use_session": True,
        "session_backend": "sqlite",
        "use_temp_session_dir": True,
        "tracing_disabled": True,
    },
}


CLAUDE_AGENT_SDK_TARGET = {
    "kind": "claude_agent_sdk",
    "cwd": str(ROOT),
    "env": {"PYTHONPATH": CLAUDE_AGENT_SDK_PYTHONPATH},
    "claude_agent_sdk": {
        "capabilities": ["web", "workspace", "mcp"],
        "input_mode": "prompt",
        "allowed_tools": ["Read", "Glob", "Grep"],
        "permission_mode": "bypassPermissions",
        "max_turns": 8,
        "use_session": True,
        "use_temp_home": True,
        "inject_mcp_config": True,
    },
}


def _write_config(
    tmp_path: Path, raw: dict[str, object], name: str = "tddf.yaml"
) -> Path:
    config_path = tmp_path / name
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    return config_path


def test_load_default_config_exposes_expected_capabilities() -> None:
    config = load_config(Path("tddf.yaml"))

    assert config.target.kind == "command"
    assert config.target_capabilities == {
        "web",
        "document",
        "deputy",
        "workspace",
        "mcp",
    }
    assert config.harness_capabilities == {"mcp"}
    assert [scenario.id for scenario in config.scenario_definitions] == [
        "hidden-content-exfiltration",
        "metadata-obfuscation-demo",
        "markdown-masking-demo",
        "poisoned-workspace-search",
        "confused-deputy-finance-demo",
        "oversight-evasion-security-audit",
        "multi-turn-context-poisoning",
    ]
    assert [
        scenario.required_capabilities for scenario in config.scenario_definitions
    ] == [
        {"web", "mcp"},
        {"web", "mcp"},
        {"document", "mcp"},
        {"workspace", "mcp"},
        {"deputy"},
        {"deputy"},
        {"web", "mcp"},
    ]
    assert all(scenario.severity == "high" for scenario in config.scenario_definitions)
    assert all(scenario.frameworks for scenario in config.scenario_definitions)
    assert all(
        any(ref.startswith("owasp:") for ref in scenario.frameworks)
        for scenario in config.scenario_definitions
    )


def test_load_config_rejects_invalid_framework_reference(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["scenarios"][0]["frameworks"] = ["llm01"]
    config_path = _write_config(tmp_path, raw, "invalid-framework.yaml")

    with pytest.raises(ConfigError, match="invalid framework references"):
        load_config(config_path)


def test_load_config_rejects_hermes_mcp_injection_without_temp_home(
    tmp_path: Path,
) -> None:
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
    assert config.target_capabilities == {
        "web",
        "document",
        "deputy",
        "workspace",
        "mcp",
    }


def test_load_config_rejects_openclaw_mcp_injection_without_temp_home(
    tmp_path: Path,
) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = {
        "kind": "openclaw",
        "cwd": str(ROOT),
        "env": {},
        "openclaw": {
            "command_prefix": ["python", "tests/fixtures/mock_openclaw.py"],
            "local": True,
            "use_temp_home": False,
            "inject_mcp_config": True,
        },
    }
    config_path = _write_config(tmp_path, raw, "invalid-openclaw.yaml")

    with pytest.raises(ConfigError, match="use_temp_home"):
        load_config(config_path)


def test_load_config_accepts_mcp_capable_openclaw_target(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = OPENCLAW_TARGET
    config_path = _write_config(tmp_path, raw, "openclaw.yaml")

    config = load_config(config_path)

    assert config.target.kind == "openclaw"
    assert config.target_capabilities == {
        "web",
        "document",
        "deputy",
        "workspace",
        "mcp",
    }


def test_load_config_accepts_openai_agents_target(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = OPENAI_AGENTS_TARGET
    raw["scenarios"] = [raw["scenarios"][0], raw["scenarios"][3]]
    config_path = _write_config(tmp_path, raw, "openai-agents.yaml")

    config = load_config(config_path)

    assert config.target.kind == "openai_agents"
    assert config.target_capabilities == {"web", "workspace", "mcp"}


def test_load_config_accepts_claude_agent_sdk_target(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = CLAUDE_AGENT_SDK_TARGET
    raw["scenarios"] = [raw["scenarios"][0], raw["scenarios"][3]]
    config_path = _write_config(tmp_path, raw, "claude-agent-sdk.yaml")

    config = load_config(config_path)

    assert config.target.kind == "claude_agent_sdk"
    assert config.target_capabilities == {"web", "workspace", "mcp"}


def test_load_config_accepts_claude_agent_sdk_transport_reference(
    tmp_path: Path,
) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = {
        "kind": "claude_agent_sdk",
        "cwd": str(ROOT),
        "env": {},
        "claude_agent_sdk": {
            "transport": "tests.fixtures.real_claude_agent_transport",
        },
    }
    config_path = _write_config(tmp_path, raw, "invalid-claude-agent-sdk.yaml")

    config = load_config(config_path)

    assert config.target.kind == "claude_agent_sdk"


def test_load_config_rejects_invalid_openai_agents_reference(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = {
        "kind": "openai_agents",
        "cwd": str(ROOT),
        "env": {},
        "openai_agents": {
            "agent": "tests.fixtures.mock_openai_agents_app",
        },
    }
    config_path = _write_config(tmp_path, raw, "invalid-openai-agents.yaml")

    with pytest.raises(ConfigError, match="module.path:object_name"):
        load_config(config_path)


def test_load_config_accepts_langgraph_target(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = LANGGRAPH_TARGET
    raw["scenarios"] = [raw["scenarios"][0], raw["scenarios"][3]]
    config_path = _write_config(tmp_path, raw, "langgraph.yaml")

    config = load_config(config_path)

    assert config.target.kind == "langgraph"
    assert config.target_capabilities == {"web", "workspace", "mcp"}


def test_load_config_rejects_invalid_langgraph_graph_reference(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["target"] = {
        "kind": "langgraph",
        "cwd": str(ROOT),
        "env": {},
        "langgraph": {
            "graph": "tests.fixtures.mock_langgraph",
        },
    }
    config_path = _write_config(tmp_path, raw, "invalid-langgraph.yaml")

    with pytest.raises(ConfigError, match="module.path:object_name"):
        load_config(config_path)


def test_mcp_required_scenario_rejects_disabled_harness(tmp_path: Path) -> None:
    raw = yaml.safe_load(Path("tddf.yaml").read_text())
    raw["mcp"]["enabled"] = False
    raw["scenarios"][0]["requires_mcp"] = True
    config_path = _write_config(tmp_path, raw, "mcp-disabled.yaml")

    with pytest.raises(ConfigError, match="TDDF harness lacks 'mcp' capability"):
        load_config(config_path)
