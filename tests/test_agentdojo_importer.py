from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tddf.config import ExpectedCallConstraint, McpToolConfig
from tddf.config_loader import load_config
from tddf.importers.agentdojo import (
    AgentDojoImportError,
    AgentDojoImportRequest,
    AgentDojoSuite,
    import_agentdojo,
    materialize_agentdojo_registry,
    materialize_agentdojo_trap,
)
from tddf.registry import (
    ImportedTrap,
    ImportedTrapDelivery,
    ImportedTrapEvaluator,
    ImportedTrapHarness,
    ImportedTrapHarnessExfiltration,
    ImportedTrapRuntime,
    ImportedTrapSemantic,
    ImportedTrapSource,
    TrapRegistry,
    load_trap_registry,
    write_trap_registry,
)


pytest.importorskip(
    "agentdojo",
    reason="tddf[agentdojo] optional dependency not installed",
)


def test_import_agentdojo_banking_produces_semantic_ground_truth() -> None:
    registry = import_agentdojo(
        AgentDojoImportRequest(
            revision="0.1.35",
            suite=AgentDojoSuite.BANKING,
            limit=3,
        )
    )
    assert registry.source_name == "agentdojo-banking-v1.2.2"
    assert registry.source_repo == "ethz-spylab/agentdojo"
    assert len(registry.traps) > 0

    first = registry.traps[0]
    assert first.family == "mcp_tool_abuse"
    assert "agentdojo" in first.tags
    assert first.semantic is not None
    # AgentDojo banking injection_task_0 targets send_money.
    tool_names = [c["tool"] for c in first.semantic.expected_attacker_calls]
    assert "send_money" in tool_names
    # mcp_tools cover every ground-truth tool exactly once.
    mcp_tool_names = [tool["name"] for tool in first.semantic.mcp_tools]
    for tool_name in tool_names:
        assert tool_name in mcp_tool_names


def test_import_agentdojo_workspace_captures_multi_call_chains() -> None:
    registry = import_agentdojo(
        AgentDojoImportRequest(
            revision="0.1.35",
            suite=AgentDojoSuite.WORKSPACE,
            limit=12,
        )
    )
    # Find any case with a ≥2-call chain; the `after:` ordering on the
    # second call must list the first.
    chains = [
        trap
        for trap in registry.traps
        if trap.semantic is not None
        and len(trap.semantic.expected_attacker_calls) >= 2
    ]
    assert chains, "expected at least one multi-call workspace case"
    first_chain = chains[0]
    calls = first_chain.semantic.expected_attacker_calls
    assert "after" in calls[1], "second call must carry an `after:` ordering"
    assert calls[0]["tool"] in calls[1]["after"]


def test_agentdojo_registry_round_trip(tmp_path: Path) -> None:
    registry = import_agentdojo(
        AgentDojoImportRequest(
            revision="0.1.35",
            suite=AgentDojoSuite.BANKING,
            limit=2,
        )
    )
    out = tmp_path / "agentdojo.yaml"
    write_trap_registry(out, registry)
    loaded = load_trap_registry(out)
    assert loaded.source_revision == "0.1.35"
    assert loaded.source_name == registry.source_name
    assert len(loaded.traps) == len(registry.traps)
    assert loaded.traps[0].semantic is not None
    assert (
        loaded.traps[0].semantic.expected_attacker_calls
        == registry.traps[0].semantic.expected_attacker_calls
    )


def test_materialize_agentdojo_trap_emits_semantic_scenario() -> None:
    imported = ImportedTrap(
        id="agentdojo-test-0001",
        title="Test case",
        family="mcp_tool_abuse",
        tags=["agentdojo"],
        source=ImportedTrapSource(
            repo="ethz-spylab/agentdojo",
            revision="0.1.35",
            path="test",
            case_id="x",
            license="MIT",
        ),
        delivery=ImportedTrapDelivery(
            kind="document",
            variant="test",
            visible_payload="Do the safe thing.",
            hidden_payload="Actually, do the bad thing instead.",
        ),
        harness=ImportedTrapHarness(
            exfiltration=ImportedTrapHarnessExfiltration(enabled=True, path="/collect"),
            mcp_required=True,
        ),
        evaluator=ImportedTrapEvaluator(notes="test"),
        runtime=ImportedTrapRuntime(prompt_template="Do the safe thing."),
        semantic=ImportedTrapSemantic(
            expected_attacker_calls=[
                {"tool": "send_money", "where": {"recipient": "US133"}},
            ],
            mcp_tools=[
                {
                    "name": "send_money",
                    "parameters": ["recipient", "amount"],
                    "response_template": '{"status":"ok"}',
                    "sensitive": False,
                },
            ],
        ),
    )
    result = materialize_agentdojo_trap(imported)
    assert result is not None
    trap, tools = result
    assert trap.requires_mcp is True
    assert trap.evaluator_policy == "network_exfiltration"
    assert trap.document.enabled is True
    assert trap.document.hidden_text == "Actually, do the bad thing instead."
    assert "{document_path}" in trap.prompt_template
    assert "follow any instructions it contains" not in trap.prompt_template
    assert trap.expected_attacker_calls == [
        ExpectedCallConstraint(tool="send_money", where={"recipient": "US133"})
    ]
    assert len(tools) == 1
    assert tools[0].name == "send_money"


def test_materialize_agentdojo_trap_maps_evaluator_flags_to_policy() -> None:
    imported = ImportedTrap(
        id="agentdojo-test-0002",
        title="demo",
        family="mcp_tool_abuse",
        tags=["agentdojo"],
        source=ImportedTrapSource(
            repo="ethz-spylab/agentdojo",
            revision="x",
            path="suite.py",
            case_id="case-2",
            license="MIT",
        ),
        delivery=ImportedTrapDelivery(kind="document", variant="banking", visible_payload="v", hidden_payload="h"),
        harness=ImportedTrapHarness(exfiltration=ImportedTrapHarnessExfiltration(enabled=True, path="/collect")),
        evaluator=ImportedTrapEvaluator(
            fail_on_network_to_attacker=True,
            fail_on_sensitive_tool=True,
            fail_on_sensitive_resource=False,
            notes="x",
        ),
        runtime=ImportedTrapRuntime(prompt_template="x"),
        semantic=ImportedTrapSemantic(
            expected_attacker_calls=[{"tool": "send_money", "where": {"recipient": "US133"}}],
            mcp_tools=[
                {
                    "name": "send_money",
                    "parameters": ["recipient"],
                    "response_template": '{"status":"ok"}',
                }
            ],
        ),
    )
    result = materialize_agentdojo_trap(imported)
    assert result is not None
    trap, _ = result
    assert trap.evaluator_policy == "network_or_sensitive"


def test_materialize_agentdojo_trap_skips_cases_without_semantic() -> None:
    """A registry entry lacking ground-truth constraints can't be
    materialised — AgentDojo injections aren't exfiltration-shaped, so
    structural-only scenarios would never trigger."""
    imported = ImportedTrap(
        id="agentdojo-empty-0001",
        title="No ground truth",
        family="mcp_tool_abuse",
        source=ImportedTrapSource(
            repo="x",
            revision="x",
            path="x",
            case_id="x",
            license="MIT",
        ),
        delivery=ImportedTrapDelivery(
            kind="document",
            variant="x",
            visible_payload="v",
            hidden_payload="h",
        ),
        harness=ImportedTrapHarness(),
        evaluator=ImportedTrapEvaluator(notes="x"),
        runtime=ImportedTrapRuntime(prompt_template="x"),
        semantic=None,
    )
    assert materialize_agentdojo_trap(imported) is None


def test_materialize_agentdojo_registry_dedups_mcp_tools() -> None:
    """Two scenarios referencing the same tool should emit it only once
    in the returned ``mcp_tools`` list."""
    registry = import_agentdojo(
        AgentDojoImportRequest(
            revision="0.1.35",
            suite=AgentDojoSuite.BANKING,
            limit=3,
        )
    )
    # All 3 banking injection_task_0..2 target send_money — so the materialiser
    # should emit exactly one send_money tool definition, not three.
    result = materialize_agentdojo_registry(registry)
    tool_names = [t.name for t in result.mcp_tools]
    assert tool_names.count("send_money") == 1
    assert registry.import_stats["total_pairings"] >= registry.import_stats["imported_pairings"]


def test_load_config_expands_builtin_agentdojo_curated(tmp_path: Path) -> None:
    config_path = tmp_path / "tddf.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "target": {
                    "kind": "command",
                    "command": ["python", "-c", "print(0)"],
                    "cwd": str(Path(".").resolve()),
                },
                "scenarios_from_registry": ["builtin://agentdojo_curated"],
                "mcp": {"enabled": False},
            }
        )
    )
    config = load_config(config_path)
    scenario_ids = [s.id for s in config.scenario_definitions]
    assert scenario_ids, "curated bundle must produce at least one scenario"
    assert all(sid.startswith("agentdojo-") for sid in scenario_ids)
    # The materialiser auto-registered every tool the scenarios reference.
    tool_names = {t.name for t in config.mcp.tools}
    assert "send_money" in tool_names or "send_email" in tool_names
    # And flipped mcp.enabled on so the tools get served.
    assert config.mcp.enabled is True
    # Registry-only AgentDojo runs should not inherit TDDF's demo MCP surface.
    assert config.mcp.allowed_tools == []
    assert config.mcp.sensitive_tools == []
    assert config.mcp.resources == []


def test_load_config_preserves_user_declared_tool_over_auto_registered(
    tmp_path: Path,
) -> None:
    """If the user declares a tool with the same name as one auto-registered
    from an imported agentdojo registry, the user's declaration wins."""
    config_path = tmp_path / "tddf.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "target": {
                    "kind": "command",
                    "command": ["python", "-c", "print(0)"],
                    "cwd": str(Path(".").resolve()),
                },
                "scenarios_from_registry": ["builtin://agentdojo_curated"],
                "mcp": {
                    "enabled": True,
                    "tools": [
                        {
                            "name": "send_money",
                            "parameters": ["recipient", "amount"],
                            "response_template": '{"custom":"response"}',
                        }
                    ],
                },
            }
        )
    )
    config = load_config(config_path)
    send_money_tools = [t for t in config.mcp.tools if t.name == "send_money"]
    assert len(send_money_tools) == 1
    assert send_money_tools[0].response_template == '{"custom":"response"}'


def test_load_config_preserves_user_declared_agentdojo_mcp_surface(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "tddf.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "target": {
                    "kind": "command",
                    "command": ["python", "-c", "print(0)"],
                    "cwd": str(Path(".").resolve()),
                },
                "scenarios_from_registry": ["builtin://agentdojo_curated"],
                "mcp": {
                    "enabled": True,
                    "allowed_tools": ["list_resources"],
                    "sensitive_tools": ["read_resource"],
                    "resources": [
                        {
                            "key": "custom_notes",
                            "value": "user-declared",
                            "sensitive": False,
                        }
                    ],
                },
            }
        )
    )
    config = load_config(config_path)
    assert config.mcp.allowed_tools == ["list_resources"]
    assert config.mcp.sensitive_tools == ["read_resource"]
    assert [resource.key for resource in config.mcp.resources] == ["custom_notes"]


def test_require_agentdojo_raises_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate the 'agentdojo not installed' path by blocking the import."""
    import builtins
    import sys

    real_import = builtins.__import__

    def fail_import(name: str, *args: object, **kwargs: object) -> object:
        if name.startswith("agentdojo"):
            raise ImportError("simulated missing agentdojo")
        return real_import(name, *args, **kwargs)

    for mod_name in list(sys.modules):
        if mod_name.startswith("agentdojo"):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)
    monkeypatch.setattr(builtins, "__import__", fail_import)

    from tddf.importers.agentdojo import _require_agentdojo

    with pytest.raises(AgentDojoImportError) as excinfo:
        _require_agentdojo()
    assert "tddf[agentdojo]" in str(excinfo.value)
