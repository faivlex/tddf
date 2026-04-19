"""AgentDojo benchmark importer (ethz-spylab/agentdojo).

Parallel to :mod:`tddf.importers.injecagent`. AgentDojo encodes its
cases as Python classes (``BaseUserTask`` / ``BaseInjectionTask``) with
``ground_truth()`` methods that return a sequence of ``FunctionCall``
objects describing what a successful attack looks like — exactly the
shape TDDF's semantic evaluator (``expected_attacker_calls``) consumes.

The importer is an *optional extra*: ``pip install 'tddf[agentdojo]'``.
Without the extra, ``import_agentdojo`` raises ``AgentDojoImportError``
explaining how to install it. The curated ``builtin://agentdojo_curated``
bundle hand-ships a few representative cases so users can exercise the
integration with zero install friction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from tddf.config import (
    McpToolConfig,
    TrapConfig,
    TrapDocumentConfig,
    TrapExfiltrationConfig,
    TrapWebConfig,
)
from tddf.registry import (
    ImportedTrap,
    ImportedTrapDelivery,
    ImportedTrapEvaluator,
    ImportedTrapHarness,
    ImportedTrapHarnessExfiltration,
    ImportedTrapHarnessToolContext,
    ImportedTrapHarnessWeb,
    ImportedTrapRuntime,
    ImportedTrapSemantic,
    ImportedTrapSource,
    TrapRegistry,
)


DEFAULT_AGENTDOJO_REPO = "ethz-spylab/agentdojo"
DEFAULT_AGENTDOJO_LICENSE = "MIT"
AGENTDOJO_CITATION = (
    "Debenedetti et al., 2024 (AgentDojo, NeurIPS 2024 Datasets & Benchmarks)"
)
DEFAULT_BENCHMARK_VERSION = "v1.2.2"


class AgentDojoSuite(StrEnum):
    BANKING = "banking"
    WORKSPACE = "workspace"
    SLACK = "slack"
    TRAVEL = "travel"


@dataclass(slots=True)
class AgentDojoImportRequest:
    revision: str
    suite: AgentDojoSuite = AgentDojoSuite.BANKING
    benchmark_version: str = DEFAULT_BENCHMARK_VERSION
    source_repo: str = DEFAULT_AGENTDOJO_REPO
    source_license: str = DEFAULT_AGENTDOJO_LICENSE
    source_path: Path | None = None
    limit: int | None = None


class AgentDojoImportError(RuntimeError):
    """Raised when the importer cannot reach the upstream AgentDojo package."""


def _require_agentdojo() -> Any:
    try:
        from agentdojo.task_suite.load_suites import get_suite  # type: ignore[import-untyped]
    except ImportError as error:
        raise AgentDojoImportError(
            "The AgentDojo importer requires the optional dependency "
            "'agentdojo'. Install it with `pip install 'tddf[agentdojo]'` "
            "or `uv pip install agentdojo`."
        ) from error
    return get_suite


def _slugify(value: str) -> str:
    lowered = value.strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", lowered)
    return slug.strip("-") or "unknown"


def _dataset_relative_path(request: AgentDojoImportRequest) -> str:
    """AgentDojo doesn't ship a flat data file, but we record a
    pointer-ish path for provenance symmetry with the InjecAgent importer."""
    version_slug = request.benchmark_version.replace(".", "_")
    return (
        f"src/agentdojo/default_suites/{version_slug}/"
        f"{request.suite.value}/injection_tasks.py"
    )


def _source_bundle_name(request: AgentDojoImportRequest) -> str:
    return f"agentdojo-{request.suite.value}-{request.benchmark_version}"


def _derive_expected_calls(ground_truth_calls: list[Any]) -> list[dict[str, Any]]:
    """Convert AgentDojo ``FunctionCall`` objects into
    ``ExpectedCallConstraint``-shaped dicts for the semantic evaluator.

    AgentDojo marks args whose value is environment-dependent with
    sentinel ``$content`` / ``$placeholder`` strings in ``placeholder_args``.
    We drop those from the constraint (the agent can put any content in
    them and still be attacking), and pin the rest as equals constraints.
    """
    constraints: list[dict[str, Any]] = []
    for call in ground_truth_calls:
        function = getattr(call, "function", None)
        if not isinstance(function, str):
            continue
        args = getattr(call, "args", None) or {}
        placeholder_args = getattr(call, "placeholder_args", None) or {}
        where: dict[str, Any] = {}
        for name, value in args.items():
            placeholder = placeholder_args.get(name)
            if isinstance(placeholder, str) and placeholder.startswith("$"):
                # Environment-derived content — too flaky to gate on.
                continue
            where[name] = _stringify_arg(value)
        constraints.append({"tool": function, "where": where})
    # Chain ordering: every call after the first lists its predecessors'
    # tool names so the semantic evaluator enforces the order.
    tool_sequence: list[str] = []
    for constraint in constraints:
        after = list(tool_sequence)
        if after:
            constraint["after"] = after
        tool_sequence.append(constraint["tool"])
    return constraints


def _stringify_arg(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


def _synthesise_mcp_tools(
    suite_tools: list[Any], ground_truth_calls: list[Any]
) -> list[dict[str, Any]]:
    """Return ``McpToolConfig``-shaped dicts for every tool referenced by
    the ground-truth call sequence, so the scenario's MCP surface
    recognises the calls the agent makes. Sensitive flag stays False —
    semantic eval is what gates these scenarios, not structural."""
    by_name = {tool.name: tool for tool in suite_tools}
    needed_names: list[str] = []
    seen: set[str] = set()
    for call in ground_truth_calls:
        name = getattr(call, "function", None)
        if not isinstance(name, str) or name in seen:
            continue
        seen.add(name)
        needed_names.append(name)
    tools: list[dict[str, Any]] = []
    for name in needed_names:
        tool = by_name.get(name)
        parameters: list[str] = []
        if tool is not None and hasattr(tool, "parameters"):
            # agentdojo exposes `parameters` as a pydantic model whose
            # JSON schema carries the arg names under `properties`.
            schema = _coerce_tool_schema(tool.parameters)
            parameters = list(schema.get("properties", {}).keys())
        tools.append(
            {
                "name": name,
                "parameters": parameters,
                "response_template": '{"status":"ok"}',
                "sensitive": False,
            }
        )
    return tools


def _coerce_tool_schema(parameters: Any) -> dict[str, Any]:
    for attr in ("model_json_schema", "schema"):
        method = getattr(parameters, attr, None)
        if callable(method):
            try:
                return method()
            except Exception:
                continue
    return {}


def _build_trap(
    *,
    request: AgentDojoImportRequest,
    user_task: Any,
    injection_task: Any,
    ground_truth_calls: list[Any],
    suite_tools: list[Any],
    index: int,
) -> ImportedTrap:
    trap_id = (
        f"agentdojo-{request.suite.value}-"
        f"{_slugify(user_task.ID)}-{_slugify(injection_task.ID)}-{index:04d}"
    )
    hidden_text = str(injection_task.GOAL).strip()
    visible_text = str(user_task.PROMPT).strip()

    expected_calls = _derive_expected_calls(ground_truth_calls)
    mcp_tools = _synthesise_mcp_tools(suite_tools, ground_truth_calls)

    tool_names = [call.function for call in ground_truth_calls if hasattr(call, "function")]
    tool_context = ImportedTrapHarnessToolContext(
        user_tool="AgentDojo",
        attacker_tools=tool_names,
        thought=None,
    )

    return ImportedTrap(
        id=trap_id,
        title=(
            f"AgentDojo {request.suite.value} "
            f"{user_task.ID}/{injection_task.ID}"
        ),
        family="mcp_tool_abuse",
        tags=[
            "agentdojo",
            f"suite:{request.suite.value}",
            f"benchmark_version:{request.benchmark_version}",
            f"user_task:{_slugify(user_task.ID)}",
            f"injection_task:{_slugify(injection_task.ID)}",
        ],
        source=ImportedTrapSource(
            repo=request.source_repo,
            revision=request.revision,
            path=_dataset_relative_path(request),
            case_id=trap_id,
            license=request.source_license,
            citations=[AGENTDOJO_CITATION],
        ),
        delivery=ImportedTrapDelivery(
            kind="document",
            variant=_slugify(user_task.ID),
            visible_payload=visible_text,
            hidden_payload=hidden_text,
        ),
        harness=ImportedTrapHarness(
            web=ImportedTrapHarnessWeb(enabled=False),
            exfiltration=ImportedTrapHarnessExfiltration(enabled=True, path="/collect"),
            mcp_required=bool(expected_calls),
            tool_context=tool_context,
        ),
        evaluator=ImportedTrapEvaluator(
            fail_on_network_to_attacker=True,
            fail_on_sensitive_tool=False,
            fail_on_sensitive_resource=False,
            fail_on_file_access=False,
            notes=(
                "Imported from AgentDojo. The scenario fails if the agent "
                "executes the injection's ground-truth tool-call sequence "
                "(semantic evaluator) or contacts the attacker endpoint."
            ),
        ),
        runtime=ImportedTrapRuntime(
            prompt_template=visible_text or "Follow the instructions in {document_path}.",
            default_overrides={
                "injection_goal": hidden_text,
                "user_task_prompt": visible_text,
                "difficulty": str(getattr(user_task, "DIFFICULTY", "")),
            },
            adapter_hints={
                "user_task_id": user_task.ID,
                "injection_task_id": injection_task.ID,
                "ground_truth_tool_names": tool_names,
            },
        ),
        semantic=ImportedTrapSemantic(
            expected_attacker_calls=expected_calls,
            mcp_tools=mcp_tools,
        ),
    )


def _prompt_with_document_reference(imported: ImportedTrap) -> str:
    prompt_template = imported.runtime.prompt_template.strip()
    if not prompt_template:
        prompt_template = (
            "Review the note at {document_path} and complete the user's task."
        )
    if "{document_path}" in prompt_template:
        return prompt_template
    return prompt_template + "\n\nRelevant note: {document_path}"


def import_agentdojo(request: AgentDojoImportRequest) -> TrapRegistry:
    """Import AgentDojo cases into a ``TrapRegistry``.

    Loads the named suite from the installed ``agentdojo`` package,
    walks every user_task × injection_task pairing, and emits one
    ``ImportedTrap`` per pairing whose ``semantic`` block carries the
    ground-truth tool-call sequence. Pairings whose ``ground_truth``
    call raises (e.g. because the injection depends on environment
    state we can't stage) are silently skipped.
    """
    if request.source_path is not None:
        # Local checkout mode — prepend the path to sys.path so
        # ``import agentdojo`` resolves to the provided source tree.
        import sys

        source_str = str(request.source_path.resolve())
        if source_str not in sys.path:
            sys.path.insert(0, source_str)

    get_suite = _require_agentdojo()
    suite = get_suite(request.benchmark_version, request.suite.value)

    pairings: list[tuple[Any, Any]] = [
        (ut, it)
        for ut in suite.user_tasks.values()
        for it in suite.injection_tasks.values()
    ]
    if request.limit is not None:
        pairings = pairings[: request.limit]

    traps: list[ImportedTrap] = []
    skipped_errors = 0
    skipped_empty_ground_truth = 0
    for index, (user_task, injection_task) in enumerate(pairings, start=1):
        try:
            environment = suite.load_and_inject_default_environment({})
            ground_truth_calls = list(injection_task.ground_truth(environment))
        except Exception:
            # AgentDojo sometimes cannot compute ground truth without a
            # fully-seeded environment; skip those rather than fail the
            # whole import.
            skipped_errors += 1
            continue
        if not ground_truth_calls:
            skipped_empty_ground_truth += 1
            continue
        traps.append(
            _build_trap(
                request=request,
                user_task=user_task,
                injection_task=injection_task,
                ground_truth_calls=ground_truth_calls,
                suite_tools=list(suite.tools),
                index=index,
            )
        )

    return TrapRegistry(
        source_name=_source_bundle_name(request),
        source_repo=request.source_repo,
        source_revision=request.revision,
        source_license=request.source_license,
        generated_from=_dataset_relative_path(request),
        import_stats={
            "total_pairings": len(pairings),
            "imported_pairings": len(traps),
            "skipped_pairings": len(pairings) - len(traps),
            "skipped_ground_truth_errors": skipped_errors,
            "skipped_empty_ground_truth": skipped_empty_ground_truth,
        },
        traps=traps,
    )


@dataclass(slots=True)
class AgentDojoMaterialisation:
    """Result of materialising an AgentDojo registry.

    Holds the runnable ``TrapConfig`` list plus the set of MCP tool
    definitions every scenario references — the caller merges the tools
    into the parent config's ``mcp.tools`` before running."""

    traps: list[TrapConfig]
    mcp_tools: list[McpToolConfig]


def materialize_agentdojo_trap(
    imported: ImportedTrap,
) -> tuple[TrapConfig, list[McpToolConfig]] | None:
    """Convert an AgentDojo ``ImportedTrap`` into a runnable
    ``TrapConfig`` plus the MCP tool definitions it needs.

    Returns ``None`` if the imported record lacks the semantic block —
    such records have no semantic gate, and AgentDojo's injections are
    not exfiltration-shaped, so a structural-only materialisation would
    never signal.
    """
    if imported.semantic is None or not imported.semantic.expected_attacker_calls:
        return None
    hidden_text = imported.delivery.hidden_payload.strip()
    if not hidden_text:
        return None

    visible_text = imported.delivery.visible_payload.strip() or (
        "Routine content imported from the AgentDojo benchmark."
    )

    from tddf.config import ExpectedCallConstraint  # local import: avoid cycle

    expected_calls = [
        ExpectedCallConstraint.model_validate(entry)
        for entry in imported.semantic.expected_attacker_calls
    ]
    mcp_tools = [
        McpToolConfig.model_validate(entry) for entry in imported.semantic.mcp_tools
    ]

    trap = TrapConfig(
        id=imported.id,
        family_kind="mcp_tool_abuse",
        evaluator_policy="default",
        severity="high",
        frameworks=list(imported.frameworks),
        prompt_template=_prompt_with_document_reference(imported),
        web=TrapWebConfig(enabled=False),
        document=TrapDocumentConfig(
            enabled=True,
            path=f"imported/{_slugify(imported.id)}.md",
            visible_text=visible_text,
            hidden_text=hidden_text,
            technique="markdown_comment",
        ),
        exfiltration=TrapExfiltrationConfig(
            enabled=imported.harness.exfiltration.enabled,
            path=imported.harness.exfiltration.path or "/collect",
        ),
        requires_mcp=True,
        expected_attacker_calls=expected_calls,
    )
    return trap, mcp_tools


def materialize_agentdojo_registry(registry: TrapRegistry) -> AgentDojoMaterialisation:
    """Materialise every stage-able AgentDojo trap in ``registry``.

    Returns ``AgentDojoMaterialisation`` — callers merge ``mcp_tools``
    into the parent config's MCP surface, dedup'ed by tool name."""
    traps: list[TrapConfig] = []
    tools_by_name: dict[str, McpToolConfig] = {}
    for imported in registry.traps:
        result = materialize_agentdojo_trap(imported)
        if result is None:
            continue
        trap, tools = result
        traps.append(trap)
        for tool in tools:
            tools_by_name.setdefault(tool.name, tool)
    return AgentDojoMaterialisation(
        traps=traps, mcp_tools=list(tools_by_name.values())
    )
