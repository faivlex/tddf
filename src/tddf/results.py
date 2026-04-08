from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Literal
from xml.etree import ElementTree as ET


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
class StepEvidence:
    step_index: int
    step_label: str | None
    prompt: str
    evidence: list[Evidence]
    stdout: str
    stderr: str
    exit_code: int | None
    duration_seconds: float | None


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
    workspace_path: str | None
    attacker_url: str
    adapter_name: str = "command"
    adapter_metadata: dict[str, object] = field(default_factory=dict)
    mcp_url: str | None = None
    summary: str = ""
    exit_code: int | None = None
    duration_seconds: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    step_evidence: list[StepEvidence] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    adapter_artifact_contents: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["evidence"] = [asdict(item) for item in self.evidence]
        payload["step_evidence"] = [
            {**asdict(step), "evidence": [asdict(e) for e in step.evidence]}
            for step in self.step_evidence
        ]
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
            for (
                artifact_name,
                artifact_content,
            ) in self.adapter_artifact_contents.items():
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

    def write_junit_xml(self, artifacts_dir: Path) -> Path:
        run_dir = artifacts_dir / self.run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        junit_xml = run_dir / "junit.xml"

        tests = len(self.results)
        failures = sum(1 for result in self.results if result.status == "failed")
        errors = sum(
            1 for result in self.results if result.status in {"error", "timeout"}
        )
        total_time = sum(result.duration_seconds or 0.0 for result in self.results)

        root = ET.Element("testsuites")
        suite = ET.SubElement(
            root,
            "testsuite",
            {
                "name": "tddf",
                "tests": str(tests),
                "failures": str(failures),
                "errors": str(errors),
                "skipped": "0",
                "time": f"{total_time:.3f}",
                "timestamp": self.results[0].started_at if self.results else "",
            },
        )
        properties = ET.SubElement(suite, "properties")
        ET.SubElement(properties, "property", {"name": "run_id", "value": self.run_id})
        ET.SubElement(
            properties,
            "property",
            {"name": "config_path", "value": self.config_path},
        )

        for result in self.results:
            testcase = ET.SubElement(
                suite,
                "testcase",
                {
                    "classname": f"tddf.{result.adapter_name}",
                    "name": result.scenario_id,
                    "file": result.config_path,
                    "time": f"{(result.duration_seconds or 0.0):.3f}",
                },
            )
            if result.status == "failed":
                failure = ET.SubElement(
                    testcase,
                    "failure",
                    {
                        "message": result.summary or "Scenario failed.",
                        "type": "policy_violation",
                    },
                )
                failure.text = _build_junit_detail(result)
            elif result.status in {"error", "timeout"}:
                error = ET.SubElement(
                    testcase,
                    "error",
                    {
                        "message": result.summary or "Scenario errored.",
                        "type": result.status,
                    },
                )
                error.text = _build_junit_detail(result)
            if result.stdout:
                system_out = ET.SubElement(testcase, "system-out")
                system_out.text = result.stdout
            if result.stderr:
                system_err = ET.SubElement(testcase, "system-err")
                system_err.text = result.stderr

        ET.indent(root, space="  ")
        junit_xml.write_text(
            ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"
        )
        return junit_xml


def _build_junit_detail(result: RunResult) -> str:
    detail_lines = [
        f"status: {result.status}",
        f"summary: {result.summary}",
        f"adapter: {result.adapter_name}",
        f"target: {' '.join(result.target_command)}",
    ]
    if result.exit_code is not None:
        detail_lines.append(f"exit_code: {result.exit_code}")
    if result.evidence:
        detail_lines.append("evidence:")
        detail_lines.extend(f"- {item.kind}: {item.detail}" for item in result.evidence)
    if result.step_evidence:
        detail_lines.append("steps:")
        for step in result.step_evidence:
            label = step.step_label or f"step-{step.step_index}"
            detail_lines.append(f"  [{step.step_index}] {label}: {len(step.evidence)} evidence items")
            detail_lines.extend(f"    - {item.kind}: {item.detail}" for item in step.evidence)
    return "\n".join(detail_lines)
