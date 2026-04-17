from __future__ import annotations

from pathlib import Path

import yaml


def test_action_yaml_is_valid_and_composite() -> None:
    action = yaml.safe_load(Path("action.yml").read_text())

    assert action["name"] == "Run TDDF"
    assert action["runs"]["using"] == "composite"
    assert any(step.get("id") == "run-tddf" for step in action["runs"]["steps"])
    assert "fail-severity" in action["inputs"]
    assert "extra-args" in action["inputs"]
    assert "artifacts-path" in action["outputs"]


def test_action_run_step_threads_extra_args_into_tddf_run() -> None:
    """``extra-args`` must reach the actual ``tddf run`` invocation so callers
    can pass ``--baseline`` / ``--snapshot`` through without forking the
    action."""
    action = yaml.safe_load(Path("action.yml").read_text())
    run_step = next(
        step for step in action["runs"]["steps"] if step.get("id") == "run-tddf"
    )
    assert "${{ inputs.extra-args }}" in run_step["run"]


def test_example_workflow_is_valid_yaml() -> None:
    workflow = yaml.safe_load(Path("examples/github-actions/tddf.yml").read_text())

    assert workflow["name"] == "TDDF"
    assert "jobs" in workflow
    assert "tddf" in workflow["jobs"]


def test_github_actions_docs_mentions_fail_severity_and_artifacts() -> None:
    docs = Path("docs/github-actions.md").read_text()

    assert "fail-severity" in docs
    assert "actions/upload-artifact" in docs
    assert "junit.xml" in docs
