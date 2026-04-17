from __future__ import annotations

from pathlib import Path

import yaml

from tddf.config_loader import load_config
from tddf.importers.injecagent import (
    InjecAgentImportRequest,
    import_injecagent,
    materialize_injecagent_registry,
    materialize_injecagent_trap,
)
from tddf.registry import load_trap_registry, write_trap_registry


FIXTURE_ROOT = Path("tests/fixtures/injecagent").resolve()


def test_import_injecagent_from_local_fixture(tmp_path: Path) -> None:
    registry = import_injecagent(
        InjecAgentImportRequest(
            revision="fixture-sha",
            source_path=FIXTURE_ROOT,
        )
    )

    assert registry.source_name == "injecagent-ds-base"
    assert registry.source_repo == "uiuc-kang-lab/InjecAgent"
    assert registry.source_revision == "fixture-sha"
    assert registry.generated_from == "data/test_cases_ds_base.json"
    assert len(registry.traps) == 2

    first = registry.traps[0]
    assert first.id == "injecagent-ds-base-0001"
    assert first.family == "behavioural_control"
    assert "owasp:llm01" in first.frameworks
    assert first.source.path == "data/test_cases_ds_base.json"
    assert first.source.license == "MIT"
    assert first.delivery.kind == "web_html"
    assert first.harness.web.enabled is True
    assert first.harness.tool_context is not None
    assert first.harness.tool_context.user_tool == "WebBrowserNavigateTo"
    assert first.runtime.prompt_template.startswith("Please navigate")
    assert first.runtime.default_overrides["attack_type"] == "Physical Data"

    second = registry.traps[1]
    assert second.delivery.kind == "email"
    assert second.harness.web.enabled is False
    assert "user_tool:gmailreademail" in second.tags


def test_trap_registry_round_trip(tmp_path: Path) -> None:
    registry = import_injecagent(
        InjecAgentImportRequest(
            revision="fixture-sha",
            source_path=FIXTURE_ROOT,
            limit=1,
        )
    )
    output_path = tmp_path / "injecagent.yaml"

    write_trap_registry(output_path, registry)
    loaded = load_trap_registry(output_path)

    assert loaded.source_revision == "fixture-sha"
    assert len(loaded.traps) == 1
    assert loaded.traps[0].id == "injecagent-ds-base-0001"
    assert loaded.traps[0].frameworks


def test_materialize_web_delivery_produces_runnable_web_trap() -> None:
    registry = import_injecagent(
        InjecAgentImportRequest(revision="fixture-sha", source_path=FIXTURE_ROOT)
    )
    traps = materialize_injecagent_registry(registry)
    by_id = {trap.id: trap for trap in traps}

    web_trap = by_id["injecagent-ds-base-0001"]
    assert web_trap.web.enabled is True
    assert web_trap.document.enabled is False
    assert web_trap.web.technique == "html_comment"
    # The attacker instruction should land verbatim as hidden_text.
    assert web_trap.web.hidden_text == registry.traps[0].delivery.hidden_payload
    assert web_trap.evaluator_policy == "network_exfiltration"
    assert web_trap.exfiltration.enabled is True
    assert web_trap.frameworks == registry.traps[0].frameworks
    # Prompt should reference the web surface macro, not the original URL.
    assert "{web_url}" in web_trap.prompt_template


def test_materialize_email_delivery_produces_runnable_document_trap() -> None:
    registry = import_injecagent(
        InjecAgentImportRequest(revision="fixture-sha", source_path=FIXTURE_ROOT)
    )
    traps = materialize_injecagent_registry(registry)
    by_id = {trap.id: trap for trap in traps}

    doc_trap = by_id["injecagent-ds-base-0002"]
    assert doc_trap.web.enabled is False
    assert doc_trap.document.enabled is True
    assert doc_trap.document.technique == "markdown_comment"
    assert doc_trap.document.hidden_text == registry.traps[1].delivery.hidden_payload
    assert "{document_path}" in doc_trap.prompt_template


def test_materialize_skips_unstageable_delivery_kinds() -> None:
    registry = load_trap_registry(
        Path(__file__).resolve().parent.parent
        / "src" / "tddf" / "data" / "injecagent_curated.yaml"
    )
    # Manually construct a fake trap with an unknown delivery kind to verify
    # materialization silently drops it rather than synthesising a nonsense
    # scenario.
    from tddf.registry import (
        ImportedTrap,
        ImportedTrapDelivery,
        ImportedTrapEvaluator,
        ImportedTrapHarness,
        ImportedTrapRuntime,
        ImportedTrapSource,
    )

    unstageable = ImportedTrap(
        id="injecagent-unknown-0001",
        title="Unknown delivery",
        family="content_injection",
        tags=["injecagent"],
        source=ImportedTrapSource(
            repo="test",
            revision="test",
            path="test",
            case_id="x",
            license="MIT",
        ),
        delivery=ImportedTrapDelivery(
            kind="tool_response",
            variant="unknown",
            visible_payload="visible",
            hidden_payload="hidden",
        ),
        harness=ImportedTrapHarness(),
        evaluator=ImportedTrapEvaluator(notes="test"),
        runtime=ImportedTrapRuntime(prompt_template="test"),
    )
    assert materialize_injecagent_trap(unstageable) is None


def test_load_config_expands_builtin_registry(tmp_path: Path) -> None:
    config_path = tmp_path / "tddf.yaml"
    raw = {
        "target": {
            "kind": "command",
            "command": ["python", "-c", "print(0)"],
            "cwd": str(Path(".").resolve()),
        },
        "scenarios_from_registry": ["builtin://injecagent_curated"],
        "mcp": {"enabled": False},
    }
    config_path.write_text(yaml.safe_dump(raw))

    config = load_config(config_path)
    scenario_ids = [s.id for s in config.scenario_definitions]
    # The packaged curated registry should produce at least one runnable scenario.
    assert scenario_ids
    assert all(sid.startswith("injecagent-") for sid in scenario_ids)


def test_load_config_resolves_relative_registry_paths(tmp_path: Path) -> None:
    """A relative ``scenarios_from_registry`` entry must resolve against the
    config file's directory, not the CLI's CWD."""
    registry = import_injecagent(
        InjecAgentImportRequest(revision="fixture-sha", source_path=FIXTURE_ROOT)
    )
    registry_path = tmp_path / "registries" / "curated.yaml"
    write_trap_registry(registry_path, registry)

    config_path = tmp_path / "tddf.yaml"
    raw = {
        "target": {
            "kind": "command",
            "command": ["python", "-c", "print(0)"],
            "cwd": str(Path(".").resolve()),
        },
        "scenarios_from_registry": ["registries/curated.yaml"],
        "mcp": {"enabled": False},
    }
    config_path.write_text(yaml.safe_dump(raw))

    config = load_config(config_path)
    assert len(config.scenario_definitions) == 2


def test_load_config_rejects_unknown_builtin_registry(tmp_path: Path) -> None:
    from tddf.config_loader import ConfigError

    config_path = tmp_path / "tddf.yaml"
    raw = {
        "target": {
            "kind": "command",
            "command": ["python", "-c", "print(0)"],
            "cwd": str(Path(".").resolve()),
        },
        "scenarios_from_registry": ["builtin://does-not-exist"],
        "mcp": {"enabled": False},
    }
    config_path.write_text(yaml.safe_dump(raw))

    try:
        load_config(config_path)
    except ConfigError as error:
        assert "does-not-exist" in str(error)
    else:
        raise AssertionError("expected ConfigError for unknown builtin registry")
