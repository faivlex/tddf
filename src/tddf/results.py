from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal


@dataclass(slots=True)
class Evidence:
    kind: str
    detail: str
    path: str | None = None
    method: str | None = None
    tool_name: str | None = None
    resource_key: str | None = None
    sensitive: bool | None = None


@dataclass(slots=True)
class ArtifactBundle:
    run_dir: Path
    result_json: Path
    stdout_txt: Path
    stderr_txt: Path
    adapter_artifacts: dict[str, Path] = field(default_factory=dict)


@dataclass(slots=True)
class RunResult:
    run_id: str
    scenario_id: str
    status: Literal["passed", "failed", "error", "timeout"]
    trap_id: str
    prompt: str
    target_command: list[str]
    config_path: str
    started_at: str
    completed_at: str
    web_url: str | None
    document_path: str | None
    attacker_url: str
    adapter_name: str = "command"
    adapter_metadata: dict[str, object] = field(default_factory=dict)
    mcp_url: str | None = None
    summary: str = ""
    exit_code: int | None = None
    duration_seconds: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    adapter_artifact_contents: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["evidence"] = [asdict(item) for item in self.evidence]
        return payload

    def write_artifacts(self, artifacts_dir: Path) -> ArtifactBundle:
        run_dir = artifacts_dir / self.run_id / self.scenario_id
        run_dir.mkdir(parents=True, exist_ok=True)

        result_json = run_dir / "result.json"
        stdout_txt = run_dir / "stdout.txt"
        stderr_txt = run_dir / "stderr.txt"
        adapter_artifacts_dir = run_dir / "adapter"
        adapter_artifacts: dict[str, Path] = {}

        result_json.write_text(json.dumps(self.to_dict(), indent=2) + "\n")
        stdout_txt.write_text(self.stdout)
        stderr_txt.write_text(self.stderr)
        if self.adapter_artifact_contents:
            adapter_artifacts_dir.mkdir(parents=True, exist_ok=True)
            for artifact_name, artifact_content in self.adapter_artifact_contents.items():
                artifact_path = adapter_artifacts_dir / artifact_name
                artifact_path.write_text(artifact_content)
                adapter_artifacts[artifact_name] = artifact_path

        return ArtifactBundle(
            run_dir=run_dir,
            result_json=result_json,
            stdout_txt=stdout_txt,
            stderr_txt=stderr_txt,
            adapter_artifacts=adapter_artifacts,
        )


@dataclass(slots=True)
class RunBatch:
    run_id: str
    config_path: str
    results: list[RunResult]

    @property
    def status(self) -> Literal["passed", "failed", "error", "timeout"]:
        statuses = [result.status for result in self.results]
        if any(status == "failed" for status in statuses):
            return "failed"
        if any(status == "error" for status in statuses):
            return "error"
        if any(status == "timeout" for status in statuses):
            return "timeout"
        return "passed"
