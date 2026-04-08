from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from tddf.compliance import default_frameworks_for_family, validate_framework_references


class ImportedTrapSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo: str
    revision: str
    path: str
    case_id: str
    license: str
    citations: list[str] = Field(default_factory=list)


class ImportedTrapDelivery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str
    variant: str
    visible_payload: str
    hidden_payload: str
    templated_fields: list[str] = Field(default_factory=list)


class ImportedTrapHarnessWeb(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    path: str | None = None
    title: str | None = None


class ImportedTrapHarnessExfiltration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    path: str = "/collect"


class ImportedTrapHarnessToolContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_tool: str
    attacker_tools: list[str] = Field(default_factory=list)
    tool_parameters: str | None = None
    tool_response_template: str | None = None
    thought: str | None = None


class ImportedTrapHarness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    web: ImportedTrapHarnessWeb = Field(default_factory=ImportedTrapHarnessWeb)
    exfiltration: ImportedTrapHarnessExfiltration = Field(
        default_factory=ImportedTrapHarnessExfiltration
    )
    mcp_required: bool = False
    filesystem: dict[str, str] = Field(default_factory=dict)
    tool_context: ImportedTrapHarnessToolContext | None = None


class ImportedTrapEvaluator(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fail_on_network_to_attacker: bool = True
    fail_on_sensitive_tool: bool = False
    fail_on_sensitive_resource: bool = False
    fail_on_file_access: bool = False
    notes: str


class ImportedTrapRuntime(BaseModel):
    model_config = ConfigDict(extra="forbid")

    prompt_template: str
    default_overrides: dict[str, object] = Field(default_factory=dict)
    adapter_hints: dict[str, object] = Field(default_factory=dict)


class ImportedTrap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    family: str
    frameworks: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    source: ImportedTrapSource
    delivery: ImportedTrapDelivery
    harness: ImportedTrapHarness
    evaluator: ImportedTrapEvaluator
    runtime: ImportedTrapRuntime

    @model_validator(mode="after")
    def validate_frameworks(self) -> "ImportedTrap":
        if not self.frameworks:
            self.frameworks = default_frameworks_for_family(self.family)
        validate_framework_references(self.frameworks, f"Imported trap '{self.id}'")
        return self


class TrapRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    source_name: str
    source_repo: str
    source_revision: str
    source_license: str
    generated_from: str
    traps: list[ImportedTrap] = Field(default_factory=list)


def load_trap_registry(path: Path) -> TrapRegistry:
    return TrapRegistry.model_validate(yaml.safe_load(path.read_text()))


def write_trap_registry(path: Path, registry: TrapRegistry) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(registry.model_dump(mode="python"), sort_keys=False))
