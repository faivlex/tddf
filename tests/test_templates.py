from __future__ import annotations

from tddf.config_loader import load_config
from tddf.templates import TemplateAdapter, render_config


def test_render_command_template_loads(tmp_path) -> None:
    config_path = tmp_path / "command.yaml"
    config_path.write_text(render_config(TemplateAdapter.COMMAND))

    config = load_config(config_path)

    assert config.target.kind == "command"
    assert config.target.command == ["tddf-safe-agent"]
    assert config.scenario_definitions[0].requires_mcp is True


def test_render_hermes_template_loads(tmp_path) -> None:
    config_path = tmp_path / "hermes.yaml"
    config_path.write_text(render_config(TemplateAdapter.HERMES))

    config = load_config(config_path)

    assert config.target.kind == "hermes"
    assert config.scenario_definitions[0].requires_mcp is False


def test_render_openclaw_template_loads(tmp_path) -> None:
    config_path = tmp_path / "openclaw.yaml"
    config_path.write_text(render_config(TemplateAdapter.OPENCLAW))

    config = load_config(config_path)

    assert config.target.kind == "openclaw"
    assert config.scenario_definitions[0].requires_mcp is False


def test_render_langgraph_template_loads(tmp_path) -> None:
    config_path = tmp_path / "langgraph.yaml"
    config_path.write_text(render_config(TemplateAdapter.LANGGRAPH))

    config = load_config(config_path)

    assert config.target.kind == "langgraph"
    assert config.target.langgraph.graph == "your_package.your_graph_module:graph"
    assert config.scenario_definitions[0].requires_mcp is True


def test_render_claude_agent_sdk_template_loads(tmp_path) -> None:
    config_path = tmp_path / "claude-agent-sdk.yaml"
    config_path.write_text(render_config(TemplateAdapter.CLAUDE_AGENT_SDK))

    config = load_config(config_path)

    assert config.target.kind == "claude_agent_sdk"
    assert config.target.claude_agent_sdk.permission_mode == "bypassPermissions"
    assert config.scenario_definitions[0].requires_mcp is True
