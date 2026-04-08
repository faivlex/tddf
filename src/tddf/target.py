from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from tddf.config import CommandTargetConfig, HermesTargetConfig, TddfConfig


@dataclass(slots=True)
class TargetInvocation:
    command: list[str]
    cwd: Path
    env: dict[str, str]
    cleanup_dirs: list[TemporaryDirectory[str]]
    adapter_name: str
    adapter_metadata: dict[str, object]
    adapter_artifact_contents: dict[str, str]


@dataclass(slots=True)
class AdapterObservability:
    adapter_name: str
    adapter_metadata: dict[str, object]
    adapter_artifact_contents: dict[str, str]


def _copy_tree_if_exists(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    if source.is_dir():
        for child in source.iterdir():
            child_destination = destination / child.name
            if child.is_dir():
                shutil.copytree(child, child_destination, dirs_exist_ok=True)
            else:
                child_destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(child, child_destination)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _build_hermes_command(target: HermesTargetConfig, prompt: str) -> list[str]:
    command = [*target.hermes.command_prefix, "chat", "-q", prompt]
    if target.hermes.toolsets:
        command.extend(["--toolsets", ",".join(target.hermes.toolsets)])
    if target.hermes.model:
        command.extend(["--model", target.hermes.model])
    if target.hermes.provider:
        command.extend(["--provider", target.hermes.provider])
    command.extend(target.hermes.extra_args)
    return command


def _maybe_prepare_hermes_home(
    config: TddfConfig,
    mcp_url: str | None,
) -> tuple[dict[str, str], list[TemporaryDirectory[str]], dict[str, object], dict[str, str]]:
    if not isinstance(config.target, HermesTargetConfig) or not config.target.hermes.use_temp_home:
        return {}, [], {}, {}

    cleanup_dirs: list[TemporaryDirectory[str]] = []
    temp_home = TemporaryDirectory(prefix="tddf-hermes-home-")
    cleanup_dirs.append(temp_home)
    temp_home_path = Path(temp_home.name)

    base_home = config.target.hermes.base_home_dir
    if base_home is None and "HERMES_HOME" in os.environ:
        base_home = Path(os.environ["HERMES_HOME"])
    if base_home is None:
        base_home = Path.home() / ".hermes"

    _copy_tree_if_exists(base_home, temp_home_path)

    config_path = temp_home_path / "config.yaml"
    if config.target.hermes.inject_mcp_config and mcp_url is not None:
        config_payload: dict[str, object] = {}
        if config_path.exists():
            existing = yaml.safe_load(config_path.read_text())
            if isinstance(existing, dict):
                config_payload = existing
        mcp_servers = config_payload.setdefault("mcp_servers", {})
        if isinstance(mcp_servers, dict):
            mcp_servers["tddf"] = {
                "url": mcp_url,
                "enabled": True,
            }
        config_path.write_text(yaml.safe_dump(config_payload, sort_keys=False))

    artifact_contents: dict[str, str] = {}
    if config_path.exists():
        artifact_contents["hermes_config.yaml"] = config_path.read_text()

    metadata = {
        "command_prefix": list(config.target.hermes.command_prefix),
        "toolsets": list(config.target.hermes.toolsets),
        "model": config.target.hermes.model,
        "provider": config.target.hermes.provider,
        "extra_args": list(config.target.hermes.extra_args),
        "use_temp_home": config.target.hermes.use_temp_home,
        "inject_mcp_config": config.target.hermes.inject_mcp_config,
        "temp_home_dir": str(temp_home_path),
        "mcp_config_path": str(config_path) if config_path.exists() else None,
        "mcp_config_present": config_path.exists(),
    }

    return {"HERMES_HOME": str(temp_home_path)}, cleanup_dirs, metadata, artifact_contents


def build_target_invocation(
    config: TddfConfig,
    config_path: Path,
    prompt: str,
    web_url: str | None,
    attacker_url: str,
    mcp_url: str | None,
    document_path: Path | None,
    deputy_workspace_dir: Path | None,
    deputy_secret_env_key: str | None,
    deputy_secret_env_value: str | None,
) -> TargetInvocation:
    env = os.environ.copy()
    env.update(
        build_target_environment(
            config,
            prompt,
            web_url,
            attacker_url,
            mcp_url,
            document_path,
            deputy_workspace_dir,
            deputy_secret_env_key,
            deputy_secret_env_value,
        )
    )
    cwd = resolve_target_cwd(config, config_path)
    cleanup_dirs: list[TemporaryDirectory[str]] = []
    adapter_name = "command"
    adapter_metadata: dict[str, object] = {"kind": "command"}
    adapter_artifact_contents: dict[str, str] = {}

    if isinstance(config.target, CommandTargetConfig):
        command = config.target.command
    else:
        adapter_name = "hermes"
        hermes_env, hermes_cleanup_dirs, adapter_metadata, adapter_artifact_contents = (
            _maybe_prepare_hermes_home(config, mcp_url)
        )
        env.update(hermes_env)
        cleanup_dirs.extend(hermes_cleanup_dirs)
        command = _build_hermes_command(config.target, prompt)

    return TargetInvocation(
        command=command,
        cwd=cwd,
        env=env,
        cleanup_dirs=cleanup_dirs,
        adapter_name=adapter_name,
        adapter_metadata=adapter_metadata,
        adapter_artifact_contents=adapter_artifact_contents,
    )


def _extract_trace(stdout: str, prefix: str) -> tuple[dict[str, object] | None, str | None]:
    for line in reversed(stdout.splitlines()):
        if not line.startswith(prefix):
            continue
        try:
            payload = json.loads(line[len(prefix) :])
        except json.JSONDecodeError as error:
            return None, str(error)
        if isinstance(payload, dict):
            return payload, None
        return {"value": payload}, None
    return None, None


def _extract_hermes_trace(stdout: str) -> tuple[dict[str, object] | None, str | None]:
    return _extract_trace(stdout, "TDDF_HERMES_TRACE=")


def collect_adapter_observability(
    invocation: TargetInvocation,
    stdout: str,
    stderr: str,
) -> AdapterObservability:
    adapter_metadata = dict(invocation.adapter_metadata)
    adapter_artifact_contents = dict(invocation.adapter_artifact_contents)

    if invocation.adapter_name == "hermes":
        trace_payload, trace_error = _extract_hermes_trace(stdout)
        adapter_metadata["stdout_line_count"] = len(stdout.splitlines())
        adapter_metadata["stderr_line_count"] = len(stderr.splitlines())
        adapter_metadata["trace_captured"] = trace_payload is not None
        if trace_error is not None:
            adapter_metadata["trace_parse_error"] = trace_error
        if trace_payload is not None:
            adapter_artifact_contents["hermes_trace.json"] = json.dumps(trace_payload, indent=2) + "\n"

    return AdapterObservability(
        adapter_name=invocation.adapter_name,
        adapter_metadata=adapter_metadata,
        adapter_artifact_contents=adapter_artifact_contents,
    )


def describe_target(config: TddfConfig) -> str:
    if isinstance(config.target, CommandTargetConfig):
        return " ".join(config.target.command)
    return " ".join(config.target.hermes.command_prefix + ["chat", "-q", "<prompt>"])


def build_target_environment(
    config: TddfConfig,
    prompt: str,
    web_url: str | None,
    attacker_url: str,
    mcp_url: str | None,
    document_path: Path | None,
    deputy_workspace_dir: Path | None,
    deputy_secret_env_key: str | None,
    deputy_secret_env_value: str | None,
) -> dict[str, str]:
    env = {
        "TDDF_PROMPT": prompt,
        "TDDF_ATTACKER_URL": attacker_url,
    }
    if web_url is not None:
        env["TDDF_WEB_URL"] = web_url
    if mcp_url is not None:
        env["TDDF_MCP_URL"] = mcp_url
    if document_path is not None:
        env["TDDF_DOCUMENT_PATH"] = str(document_path)
    if deputy_workspace_dir is not None:
        env["TDDF_DEPUTY_WORKSPACE_DIR"] = str(deputy_workspace_dir)
    if deputy_secret_env_key is not None and deputy_secret_env_value is not None:
        env["TDDF_DEPUTY_SECRET_ENV_KEY"] = deputy_secret_env_key
        env[deputy_secret_env_key] = deputy_secret_env_value
    env.update(config.target.env)
    return env


def resolve_target_cwd(config: TddfConfig, config_path: Path) -> Path:
    if config.target.cwd is None:
        return config_path.parent.resolve()
    if config.target.cwd.is_absolute():
        return config.target.cwd
    return (config_path.parent / config.target.cwd).resolve()


def resolve_artifacts_dir(config: TddfConfig, config_path: Path) -> Path:
    artifacts_dir = config.output.artifacts_dir
    if artifacts_dir.is_absolute():
        return artifacts_dir
    return (config_path.parent / artifacts_dir).resolve()
