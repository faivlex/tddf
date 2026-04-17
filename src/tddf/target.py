from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

from tddf.config import (
    ClaudeAgentSDKTargetConfig,
    CommandTargetConfig,
    HermesTargetConfig,
    LangGraphTargetConfig,
    OpenAIAgentsTargetConfig,
    OpenClawTargetConfig,
    TddfConfig,
)


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


def _build_hermes_command(
    target: HermesTargetConfig,
    prompt: str,
    session_id: str | None = None,
    step_index: int = 0,
) -> list[str]:
    command = [*target.hermes.command_prefix, "chat", "-q", prompt]
    if target.hermes.toolsets:
        command.extend(["--toolsets", ",".join(target.hermes.toolsets)])
    if target.hermes.skills:
        command.extend(["--skills", ",".join(target.hermes.skills)])
    if target.hermes.model:
        command.extend(["--model", target.hermes.model])
    if target.hermes.provider:
        command.extend(["--provider", target.hermes.provider])
    if session_id is not None and step_index > 0:
        command.append("--continue")
    command.extend(target.hermes.extra_args)
    return command


def _build_openclaw_command(
    target: OpenClawTargetConfig,
    prompt: str,
    session_id: str | None = None,
    step_index: int = 0,
) -> list[str]:
    command = [*target.openclaw.command_prefix, "agent", "--message", prompt]
    if target.openclaw.local:
        command.append("--local")
    command.append("--json")
    if target.openclaw.agent:
        command.extend(["--agent", target.openclaw.agent])
    if session_id is not None:
        command.extend(["--session-id", session_id])
    if target.openclaw.thinking:
        command.extend(["--thinking", target.openclaw.thinking])
    if target.openclaw.verbose:
        command.extend(["--verbose", target.openclaw.verbose])
    if target.openclaw.timeout_seconds is not None:
        command.extend(["--timeout", str(target.openclaw.timeout_seconds)])
    command.extend(target.openclaw.extra_args)
    return command


def _normalize_for_json(payload: object) -> object:
    if isinstance(payload, Path):
        return str(payload)
    if isinstance(payload, dict):
        return {str(key): _normalize_for_json(value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_normalize_for_json(item) for item in payload]
    return payload


def _build_langgraph_command(target: LangGraphTargetConfig) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "tddf.langgraph_runner",
        "--graph",
        target.langgraph.graph,
        "--input-mode",
        target.langgraph.input_mode,
        "--stream-modes",
        ",".join(target.langgraph.stream_modes),
        "--configurable",
        json.dumps(_normalize_for_json(target.langgraph.configurable), sort_keys=True),
        "--context",
        json.dumps(_normalize_for_json(target.langgraph.context), sort_keys=True),
    ]
    if target.langgraph.input_template is not None:
        command.extend(
            [
                "--input-template",
                json.dumps(
                    _normalize_for_json(target.langgraph.input_template),
                    sort_keys=True,
                    ensure_ascii=False,
                ),
            ]
        )
    if target.langgraph.use_thread_id:
        command.append("--use-thread-id")
    return command


def _build_openai_agents_command(target: OpenAIAgentsTargetConfig) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "tddf.openai_agents_runner",
        "--agent",
        target.openai_agents.agent,
        "--input-mode",
        target.openai_agents.input_mode,
        "--max-turns",
        str(target.openai_agents.max_turns),
        "--run-config",
        json.dumps(
            _normalize_for_json(target.openai_agents.run_config),
            sort_keys=True,
            ensure_ascii=False,
        ),
    ]
    if target.openai_agents.input_template is not None:
        command.extend(
            [
                "--input-template",
                json.dumps(
                    _normalize_for_json(target.openai_agents.input_template),
                    sort_keys=True,
                    ensure_ascii=False,
                ),
            ]
        )
    if target.openai_agents.use_session:
        command.extend(
            [
                "--use-session",
                "--session-backend",
                target.openai_agents.session_backend,
            ]
        )
    if target.openai_agents.tracing_disabled:
        command.append("--tracing-disabled")
    return command


def _build_claude_agent_sdk_command(target: ClaudeAgentSDKTargetConfig) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "tddf.claude_agent_sdk_runner",
        "--input-mode",
        target.claude_agent_sdk.input_mode,
        "--allowed-tools",
        json.dumps(target.claude_agent_sdk.allowed_tools, ensure_ascii=False),
        "--disallowed-tools",
        json.dumps(target.claude_agent_sdk.disallowed_tools, ensure_ascii=False),
        "--extra-args",
        json.dumps(
            _normalize_for_json(target.claude_agent_sdk.extra_args),
            sort_keys=True,
            ensure_ascii=False,
        ),
    ]
    if target.claude_agent_sdk.input_template is not None:
        command.extend(
            [
                "--input-template",
                json.dumps(
                    _normalize_for_json(target.claude_agent_sdk.input_template),
                    sort_keys=True,
                    ensure_ascii=False,
                ),
            ]
        )
    if target.claude_agent_sdk.permission_mode is not None:
        command.extend(["--permission-mode", target.claude_agent_sdk.permission_mode])
    if target.claude_agent_sdk.system_prompt is not None:
        command.extend(["--system-prompt", target.claude_agent_sdk.system_prompt])
    if target.claude_agent_sdk.model is not None:
        command.extend(["--model", target.claude_agent_sdk.model])
    if target.claude_agent_sdk.max_turns is not None:
        command.extend(["--max-turns", str(target.claude_agent_sdk.max_turns)])
    if target.claude_agent_sdk.include_partial_messages:
        command.append("--include-partial-messages")
    if target.claude_agent_sdk.cli_path is not None:
        command.extend(["--cli-path", str(target.claude_agent_sdk.cli_path)])
    if target.claude_agent_sdk.setting_sources is not None:
        command.extend(
            [
                "--setting-sources",
                ",".join(target.claude_agent_sdk.setting_sources),
            ]
        )
    if target.claude_agent_sdk.use_session:
        command.append("--use-session")
    if target.claude_agent_sdk.transport is not None:
        command.extend(["--transport", target.claude_agent_sdk.transport])
    return command


def _load_mapping_file(path: Path) -> tuple[dict[str, object], str | None]:
    if not path.exists():
        return {}, None
    try:
        payload = yaml.safe_load(path.read_text())
    except yaml.YAMLError as error:
        return {}, str(error)
    if payload is None:
        return {}, None
    if isinstance(payload, dict):
        return payload, None
    return {}, "Config root must be a mapping."


def _maybe_prepare_hermes_home(
    config: TddfConfig,
    mcp_url: str | None,
) -> tuple[
    dict[str, str], list[TemporaryDirectory[str]], dict[str, object], dict[str, str]
]:
    if (
        not isinstance(config.target, HermesTargetConfig)
        or not config.target.hermes.use_temp_home
    ):
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
        "skills": list(config.target.hermes.skills),
        "model": config.target.hermes.model,
        "provider": config.target.hermes.provider,
        "extra_args": list(config.target.hermes.extra_args),
        "use_temp_home": config.target.hermes.use_temp_home,
        "inject_mcp_config": config.target.hermes.inject_mcp_config,
        "temp_home_dir": str(temp_home_path),
        "mcp_config_path": str(config_path) if config_path.exists() else None,
        "mcp_config_present": config_path.exists(),
    }

    return (
        {"HERMES_HOME": str(temp_home_path)},
        cleanup_dirs,
        metadata,
        artifact_contents,
    )


def _maybe_prepare_openclaw_home(
    config: TddfConfig,
    mcp_url: str | None,
    cwd: Path,
    workspace_path: Path | None,
) -> tuple[
    dict[str, str], list[TemporaryDirectory[str]], dict[str, object], dict[str, str]
]:
    if not isinstance(config.target, OpenClawTargetConfig):
        return {}, [], {}, {}

    metadata: dict[str, object] = {
        "kind": "openclaw",
        "command_prefix": list(config.target.openclaw.command_prefix),
        "agent": config.target.openclaw.agent,
        "thinking": config.target.openclaw.thinking,
        "verbose": config.target.openclaw.verbose,
        "timeout_seconds": config.target.openclaw.timeout_seconds,
        "local": config.target.openclaw.local,
        "extra_args": list(config.target.openclaw.extra_args),
        "use_temp_home": config.target.openclaw.use_temp_home,
        "inject_mcp_config": config.target.openclaw.inject_mcp_config,
    }
    if not config.target.openclaw.use_temp_home:
        return {}, [], metadata, {}

    cleanup_dirs: list[TemporaryDirectory[str]] = []
    temp_home = TemporaryDirectory(prefix="tddf-openclaw-home-")
    cleanup_dirs.append(temp_home)
    temp_home_path = Path(temp_home.name)
    state_dir = temp_home_path / ".openclaw"
    state_dir.mkdir(parents=True, exist_ok=True)

    base_home = config.target.openclaw.base_home_dir
    if base_home is None and "OPENCLAW_HOME" in os.environ:
        base_home = Path(os.environ["OPENCLAW_HOME"])
    if base_home is None:
        base_home = Path.home()

    copied_state_dir = base_home / ".openclaw"
    _copy_tree_if_exists(copied_state_dir, state_dir)

    config_path = state_dir / "openclaw.json"
    config_payload, parse_error = _load_mapping_file(config_path)
    if parse_error is not None:
        metadata["config_parse_error"] = parse_error
    if not isinstance(config_payload.get("agents"), dict):
        config_payload["agents"] = {}
    agents_payload = config_payload["agents"]
    if isinstance(agents_payload, dict):
        defaults_payload = agents_payload.setdefault("defaults", {})
        if isinstance(defaults_payload, dict):
            defaults_payload["workspace"] = str(workspace_path or cwd)
    if config.target.openclaw.inject_mcp_config and mcp_url is not None:
        mcp_payload = config_payload.setdefault("mcp", {})
        if isinstance(mcp_payload, dict):
            servers_payload = mcp_payload.setdefault("servers", {})
            if isinstance(servers_payload, dict):
                servers_payload["tddf"] = {"url": mcp_url}
    config_path.write_text(json.dumps(config_payload, indent=2) + "\n")

    artifact_contents: dict[str, str] = {}
    if config_path.exists():
        artifact_contents["openclaw_config.json"] = config_path.read_text()

    metadata.update(
        {
            "temp_home_dir": str(temp_home_path),
            "state_dir": str(state_dir),
            "config_path": str(config_path),
            "config_present": config_path.exists(),
        }
    )

    env = {
        "OPENCLAW_HOME": str(temp_home_path),
        "OPENCLAW_STATE_DIR": str(state_dir),
        "OPENCLAW_CONFIG_PATH": str(config_path),
    }
    return env, cleanup_dirs, metadata, artifact_contents


def _maybe_prepare_openai_agents_session(
    config: TddfConfig,
) -> tuple[
    dict[str, str], list[TemporaryDirectory[str]], dict[str, object], dict[str, str]
]:
    if not isinstance(config.target, OpenAIAgentsTargetConfig):
        return {}, [], {}, {}

    metadata: dict[str, object] = {
        "kind": "openai_agents",
        "agent": config.target.openai_agents.agent,
        "input_mode": config.target.openai_agents.input_mode,
        "max_turns": config.target.openai_agents.max_turns,
        "use_session": config.target.openai_agents.use_session,
        "session_backend": config.target.openai_agents.session_backend,
        "tracing_disabled": config.target.openai_agents.tracing_disabled,
    }
    if not config.target.openai_agents.use_session:
        return {}, [], metadata, {}

    cleanup_dirs: list[TemporaryDirectory[str]] = []
    if config.target.openai_agents.use_temp_session_dir:
        temp_dir = TemporaryDirectory(prefix="tddf-openai-agents-")
        cleanup_dirs.append(temp_dir)
        session_dir = Path(temp_dir.name)
        base_dir = config.target.openai_agents.base_session_dir
        if base_dir is not None:
            _copy_tree_if_exists(base_dir, session_dir)
    else:
        session_dir = config.target.openai_agents.base_session_dir
        if session_dir is None:
            return {}, cleanup_dirs, metadata, {}
        session_dir.mkdir(parents=True, exist_ok=True)

    session_db_path = session_dir / "sessions.sqlite3"
    metadata.update(
        {
            "session_dir": str(session_dir),
            "session_db_path": str(session_db_path),
            "session_db_present": session_db_path.exists(),
        }
    )
    env = {"TDDF_OPENAI_AGENTS_SESSION_DB_PATH": str(session_db_path)}
    return env, cleanup_dirs, metadata, {}


def _maybe_prepare_claude_agent_sdk_home(
    config: TddfConfig,
    config_path: Path,
    mcp_url: str | None,
    mcp_capture_file: Path | None,
) -> tuple[
    dict[str, str], list[TemporaryDirectory[str]], dict[str, object], dict[str, str]
]:
    if not isinstance(config.target, ClaudeAgentSDKTargetConfig):
        return {}, [], {}, {}

    metadata: dict[str, object] = {
        "kind": "claude_agent_sdk",
        "input_mode": config.target.claude_agent_sdk.input_mode,
        "allowed_tools": list(config.target.claude_agent_sdk.allowed_tools),
        "disallowed_tools": list(config.target.claude_agent_sdk.disallowed_tools),
        "permission_mode": config.target.claude_agent_sdk.permission_mode,
        "model": config.target.claude_agent_sdk.model,
        "max_turns": config.target.claude_agent_sdk.max_turns,
        "use_session": config.target.claude_agent_sdk.use_session,
        "use_temp_home": config.target.claude_agent_sdk.use_temp_home,
        "inject_mcp_config": config.target.claude_agent_sdk.inject_mcp_config,
        "transport": config.target.claude_agent_sdk.transport,
    }

    cleanup_dirs: list[TemporaryDirectory[str]] = []
    env: dict[str, str] = {}
    artifact_contents: dict[str, str] = {}

    temp_home_path: Path | None = None
    if config.target.claude_agent_sdk.use_temp_home:
        temp_home = TemporaryDirectory(prefix="tddf-claude-agent-home-")
        cleanup_dirs.append(temp_home)
        temp_home_path = Path(temp_home.name)

        base_home = config.target.claude_agent_sdk.base_home_dir
        if base_home is None:
            base_home = Path.home() / ".claude"
        claude_dir = temp_home_path / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        _copy_tree_if_exists(base_home, claude_dir)
        env["HOME"] = str(temp_home_path)
        metadata["temp_home_dir"] = str(temp_home_path)
        metadata["claude_dir"] = str(claude_dir)

    if config.target.claude_agent_sdk.use_session:
        if "HOME" in env:
            state_root = Path(env["HOME"]) / ".claude"
        else:
            state_root = Path.home() / ".claude"
        state_root.mkdir(parents=True, exist_ok=True)
        session_state_path = state_root / "tddf-session.json"
        env["TDDF_CLAUDE_AGENT_SESSION_FILE"] = str(session_state_path)
        metadata["session_state_path"] = str(session_state_path)

    if config.target.claude_agent_sdk.inject_mcp_config and mcp_url is not None:
        env["TDDF_CLAUDE_AGENT_MCP_URL"] = mcp_url
        # Write a real .mcp.json pointing at `tddf mcp-server` so the SDK
        # discovers TDDF as an MCP server over stdio. Falls back to the
        # existing HTTP URL env var above for agents that prefer HTTP.
        if temp_home_path is not None:
            mcp_json_path = temp_home_path / ".mcp.json"
            mcp_env: dict[str, str] = {}
            if mcp_capture_file is not None:
                mcp_env["TDDF_MCP_CAPTURE_FILE"] = str(mcp_capture_file)
            mcp_json = {
                "mcpServers": {
                    "tddf": {
                        "command": sys.executable,
                        "args": [
                            "-m",
                            "tddf",
                            "mcp-server",
                            "--config",
                            str(config_path),
                        ],
                        "env": mcp_env,
                    }
                }
            }
            mcp_json_path.write_text(json.dumps(mcp_json, indent=2) + "\n")
            artifact_contents["mcp.json"] = mcp_json_path.read_text()
            metadata["mcp_config_path"] = str(mcp_json_path)

    return env, cleanup_dirs, metadata, artifact_contents


@dataclass(slots=True)
class AdapterHome:
    env: dict[str, str]
    cleanup_dirs: list[TemporaryDirectory[str]]
    adapter_name: str
    adapter_metadata: dict[str, object]
    adapter_artifact_contents: dict[str, str]


def prepare_adapter_home(
    config: TddfConfig,
    config_path: Path,
    mcp_url: str | None,
    workspace_path: Path | None = None,
    mcp_capture_file: Path | None = None,
) -> AdapterHome:
    cwd = resolve_target_cwd(config, config_path)
    if isinstance(config.target, CommandTargetConfig):
        return AdapterHome(
            env={},
            cleanup_dirs=[],
            adapter_name="command",
            adapter_metadata={"kind": "command"},
            adapter_artifact_contents={},
        )
    if isinstance(config.target, ClaudeAgentSDKTargetConfig):
        env, cleanup_dirs, metadata, artifacts = _maybe_prepare_claude_agent_sdk_home(
            config, config_path, mcp_url, mcp_capture_file
        )
        return AdapterHome(
            env=env,
            cleanup_dirs=cleanup_dirs,
            adapter_name="claude_agent_sdk",
            adapter_metadata=metadata,
            adapter_artifact_contents=artifacts,
        )
    if isinstance(config.target, OpenAIAgentsTargetConfig):
        env, cleanup_dirs, metadata, artifacts = _maybe_prepare_openai_agents_session(
            config
        )
        return AdapterHome(
            env=env,
            cleanup_dirs=cleanup_dirs,
            adapter_name="openai_agents",
            adapter_metadata=metadata,
            adapter_artifact_contents=artifacts,
        )
    if isinstance(config.target, LangGraphTargetConfig):
        return AdapterHome(
            env={},
            cleanup_dirs=[],
            adapter_name="langgraph",
            adapter_metadata={
                "kind": "langgraph",
                "graph": config.target.langgraph.graph,
                "input_mode": config.target.langgraph.input_mode,
                "stream_modes": list(config.target.langgraph.stream_modes),
                "use_thread_id": config.target.langgraph.use_thread_id,
            },
            adapter_artifact_contents={},
        )
    if isinstance(config.target, HermesTargetConfig):
        hermes_env, cleanup_dirs, metadata, artifacts = _maybe_prepare_hermes_home(
            config, mcp_url
        )
        return AdapterHome(
            env=hermes_env,
            cleanup_dirs=cleanup_dirs,
            adapter_name="hermes",
            adapter_metadata=metadata,
            adapter_artifact_contents=artifacts,
        )
    openclaw_env, cleanup_dirs, metadata, artifacts = _maybe_prepare_openclaw_home(
        config, mcp_url, cwd, workspace_path
    )
    metadata.setdefault("config_present", False)
    return AdapterHome(
        env=openclaw_env,
        cleanup_dirs=cleanup_dirs,
        adapter_name="openclaw",
        adapter_metadata=metadata,
        adapter_artifact_contents=artifacts,
    )


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
    workspace_path: Path | None = None,
    session_id: str | None = None,
    step_index: int = 0,
    adapter_home: AdapterHome | None = None,
    mcp_capture_file: Path | None = None,
) -> TargetInvocation:
    env = os.environ.copy()
    cwd = resolve_target_cwd(config, config_path)
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
            workspace_path,
            mcp_capture_file=mcp_capture_file,
            config_path=config_path,
        )
    )

    if session_id is not None:
        env["TDDF_SESSION_ID"] = session_id
        env["TDDF_STEP_INDEX"] = str(step_index)

    if adapter_home is None:
        adapter_home = prepare_adapter_home(
            config, config_path, mcp_url, workspace_path
        )

    env.update(adapter_home.env)
    cleanup_dirs = list(adapter_home.cleanup_dirs)

    if isinstance(config.target, CommandTargetConfig):
        command = config.target.command
    elif isinstance(config.target, ClaudeAgentSDKTargetConfig):
        command = _build_claude_agent_sdk_command(config.target)
    elif isinstance(config.target, OpenAIAgentsTargetConfig):
        command = _build_openai_agents_command(config.target)
    elif isinstance(config.target, LangGraphTargetConfig):
        command = _build_langgraph_command(config.target)
    elif isinstance(config.target, HermesTargetConfig):
        command = _build_hermes_command(config.target, prompt, session_id, step_index)
    else:
        command = _build_openclaw_command(config.target, prompt, session_id, step_index)

    return TargetInvocation(
        command=command,
        cwd=cwd,
        env=env,
        cleanup_dirs=cleanup_dirs,
        adapter_name=adapter_home.adapter_name,
        adapter_metadata=adapter_home.adapter_metadata,
        adapter_artifact_contents=adapter_home.adapter_artifact_contents,
    )


def _extract_trace(
    stdout: str, prefix: str
) -> tuple[dict[str, object] | None, str | None]:
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


def _extract_langgraph_trace(
    stdout: str,
) -> tuple[dict[str, object] | None, str | None]:
    return _extract_trace(stdout, "TDDF_LANGGRAPH_TRACE=")


def _extract_openai_agents_trace(
    stdout: str,
) -> tuple[dict[str, object] | None, str | None]:
    return _extract_trace(stdout, "TDDF_OPENAI_AGENTS_TRACE=")


def _extract_claude_agent_sdk_trace(
    stdout: str,
) -> tuple[dict[str, object] | None, str | None]:
    return _extract_trace(stdout, "TDDF_CLAUDE_AGENT_SDK_TRACE=")


def _extract_openclaw_result(
    stdout: str,
) -> tuple[dict[str, object] | None, str | None]:
    text = stdout.strip()
    if not text:
        return None, None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as error:
        return None, str(error)
    if isinstance(payload, dict):
        return payload, None
    return {"value": payload}, None


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
            adapter_artifact_contents["hermes_trace.json"] = (
                json.dumps(trace_payload, indent=2) + "\n"
            )
    elif invocation.adapter_name == "claude_agent_sdk":
        trace_payload, trace_error = _extract_claude_agent_sdk_trace(stdout)
        adapter_metadata["stdout_line_count"] = len(stdout.splitlines())
        adapter_metadata["stderr_line_count"] = len(stderr.splitlines())
        adapter_metadata["trace_captured"] = trace_payload is not None
        if trace_error is not None:
            adapter_metadata["trace_parse_error"] = trace_error
        if trace_payload is not None:
            adapter_metadata["message_count"] = trace_payload.get("message_count")
            adapter_metadata["session_id"] = trace_payload.get("session_id")
            adapter_metadata["result_subtype"] = trace_payload.get("result_subtype")
            adapter_metadata["used_resume"] = trace_payload.get("used_resume")
            adapter_artifact_contents["claude_agent_sdk_trace.json"] = (
                json.dumps(trace_payload, indent=2) + "\n"
            )
    elif invocation.adapter_name == "openai_agents":
        trace_payload, trace_error = _extract_openai_agents_trace(stdout)
        adapter_metadata["stdout_line_count"] = len(stdout.splitlines())
        adapter_metadata["stderr_line_count"] = len(stderr.splitlines())
        adapter_metadata["trace_captured"] = trace_payload is not None
        if trace_error is not None:
            adapter_metadata["trace_parse_error"] = trace_error
        if trace_payload is not None:
            adapter_metadata["event_count"] = trace_payload.get("event_count")
            adapter_metadata["new_item_count"] = trace_payload.get("new_item_count")
            adapter_metadata["last_agent_name"] = trace_payload.get("last_agent_name")
            adapter_metadata["session_id"] = trace_payload.get("session_id")
            adapter_metadata["last_response_id"] = trace_payload.get("last_response_id")
            adapter_artifact_contents["openai_agents_trace.json"] = (
                json.dumps(trace_payload, indent=2) + "\n"
            )
    elif invocation.adapter_name == "langgraph":
        trace_payload, trace_error = _extract_langgraph_trace(stdout)
        adapter_metadata["stdout_line_count"] = len(stdout.splitlines())
        adapter_metadata["stderr_line_count"] = len(stderr.splitlines())
        adapter_metadata["trace_captured"] = trace_payload is not None
        if trace_error is not None:
            adapter_metadata["trace_parse_error"] = trace_error
        if trace_payload is not None:
            adapter_metadata["stream_part_count"] = trace_payload.get(
                "stream_part_count"
            )
            adapter_metadata["used_streaming"] = trace_payload.get("used_streaming")
            adapter_metadata["thread_id"] = trace_payload.get("thread_id")
            adapter_artifact_contents["langgraph_trace.json"] = (
                json.dumps(trace_payload, indent=2) + "\n"
            )
    elif invocation.adapter_name == "openclaw":
        result_payload, result_error = _extract_openclaw_result(stdout)
        adapter_metadata["stdout_line_count"] = len(stdout.splitlines())
        adapter_metadata["stderr_line_count"] = len(stderr.splitlines())
        adapter_metadata["json_captured"] = result_payload is not None
        if result_error is not None:
            adapter_metadata["json_parse_error"] = result_error
        if result_payload is not None:
            adapter_metadata["response_status"] = result_payload.get("status")
            result_section = result_payload.get("result")
            if isinstance(result_section, dict):
                payloads = result_section.get("payloads")
                if isinstance(payloads, list):
                    adapter_metadata["payload_count"] = len(payloads)
                meta = result_section.get("meta")
                if isinstance(meta, dict) and "mcp_server_count" in meta:
                    adapter_metadata["mcp_server_count"] = meta["mcp_server_count"]
            adapter_artifact_contents["openclaw_result.json"] = (
                json.dumps(result_payload, indent=2) + "\n"
            )

    return AdapterObservability(
        adapter_name=invocation.adapter_name,
        adapter_metadata=adapter_metadata,
        adapter_artifact_contents=adapter_artifact_contents,
    )


def describe_target(config: TddfConfig) -> str:
    if isinstance(config.target, CommandTargetConfig):
        return " ".join(config.target.command)
    if isinstance(config.target, ClaudeAgentSDKTargetConfig):
        return "claude_agent_sdk"
    if isinstance(config.target, OpenAIAgentsTargetConfig):
        return f"openai_agents:{config.target.openai_agents.agent}"
    if isinstance(config.target, LangGraphTargetConfig):
        return f"langgraph:{config.target.langgraph.graph}"
    if isinstance(config.target, HermesTargetConfig):
        return " ".join(
            config.target.hermes.command_prefix + ["chat", "-q", "<prompt>"]
        )
    return " ".join(_build_openclaw_command(config.target, "<prompt>"))


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
    workspace_path: Path | None = None,
    mcp_capture_file: Path | None = None,
    config_path: Path | None = None,
) -> dict[str, str]:
    env = {
        "TDDF_PROMPT": prompt,
        "TDDF_ATTACKER_URL": attacker_url,
    }
    if config_path is not None:
        # Lets any agent that wants to spawn ``tddf mcp-server`` itself
        # find the same config the scenario was loaded from.
        env["TDDF_CONFIG_PATH"] = str(config_path)
    if web_url is not None:
        env["TDDF_WEB_URL"] = web_url
    if mcp_url is not None:
        env["TDDF_MCP_URL"] = mcp_url
    if mcp_capture_file is not None:
        # Any agent (or adapter) that spawns ``tddf mcp-server`` inherits
        # this path and appends captured tool calls for the parent run
        # to merge after the scenario exits.
        env["TDDF_MCP_CAPTURE_FILE"] = str(mcp_capture_file)
    if document_path is not None:
        env["TDDF_DOCUMENT_PATH"] = str(document_path)
    if deputy_workspace_dir is not None:
        env["TDDF_DEPUTY_WORKSPACE_DIR"] = str(deputy_workspace_dir)
    if deputy_secret_env_key is not None and deputy_secret_env_value is not None:
        env["TDDF_DEPUTY_SECRET_ENV_KEY"] = deputy_secret_env_key
        env[deputy_secret_env_key] = deputy_secret_env_value
    if workspace_path is not None:
        env["TDDF_WORKSPACE_PATH"] = str(workspace_path)
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
