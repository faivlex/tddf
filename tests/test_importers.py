from __future__ import annotations

from pathlib import Path

from tddf.importers.injecagent import (
    InjecAgentImportRequest,
    import_injecagent,
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
