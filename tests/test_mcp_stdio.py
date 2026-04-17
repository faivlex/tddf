from __future__ import annotations

import json
import os
import subprocess
import sys
from io import StringIO
from pathlib import Path

import yaml

from tddf.config import McpConfig, McpToolConfig
from tddf.mcp_stdio import load_captures_from_file, run_stdio_server


def _run_loop(
    requests: list[dict], config: McpConfig, capture_file: Path | None = None
) -> list[dict]:
    """Feed ``requests`` to ``run_stdio_server`` as newline-delimited JSON,
    capture stdout, and return parsed responses (notification requests
    produce no response, so the list may be shorter than ``requests``)."""
    stdin = StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    stdout = StringIO()
    run_stdio_server(config, capture_file, stdin=stdin, stdout=stdout)
    return [
        json.loads(line)
        for line in stdout.getvalue().splitlines()
        if line.strip()
    ]


def test_stdio_loop_responds_to_initialize_and_tools_list() -> None:
    config = McpConfig(tools=[McpToolConfig(name="ping", parameters=["x"])])
    responses = _run_loop(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ],
        config,
    )
    assert len(responses) == 2
    assert responses[0]["result"]["serverInfo"]["name"] == "tddf-mock"
    tool_names = [t["name"] for t in responses[1]["result"]["tools"]]
    assert "ping" in tool_names


def test_stdio_loop_appends_captured_calls_to_file(tmp_path: Path) -> None:
    capture_file = tmp_path / "cap.jsonl"
    capture_file.touch()
    config = McpConfig(
        tools=[
            McpToolConfig(
                name="get_contact",
                parameters=["name"],
                response_template='{"name":"{name}"}',
            )
        ],
    )
    _run_loop(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "get_contact", "arguments": {"name": "bob"}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "get_contact", "arguments": {"name": "alice"}},
            },
        ],
        config,
        capture_file=capture_file,
    )
    calls = load_captures_from_file(capture_file)
    assert len(calls) == 2
    assert calls[0].tool_name == "get_contact"
    assert calls[0].query_arguments == {"name": "bob"}
    assert calls[1].query_arguments == {"name": "alice"}


def test_stdio_loop_skips_notifications() -> None:
    """Notifications (no id) are silently accepted; no response emitted."""
    config = McpConfig()
    responses = _run_loop(
        [
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        ],
        config,
    )
    # Only tools/list responded.
    assert len(responses) == 1
    assert responses[0]["id"] == 1


def test_stdio_loop_returns_parse_error_for_malformed_request() -> None:
    stdin = StringIO("{not json\n")
    stdout = StringIO()
    run_stdio_server(McpConfig(), None, stdin=stdin, stdout=stdout)
    [response] = [
        json.loads(line)
        for line in stdout.getvalue().splitlines()
        if line.strip()
    ]
    assert response["error"]["code"] == -32700


def test_load_captures_from_missing_file_returns_empty(tmp_path: Path) -> None:
    assert load_captures_from_file(tmp_path / "nope.jsonl") == []


def test_mcp_server_cli_subprocess_roundtrip(tmp_path: Path) -> None:
    """End-to-end proof that `tddf mcp-server` spawns, speaks JSON-RPC,
    and appends captured calls to the file named by --capture-file."""
    config_path = tmp_path / "tddf.yaml"
    capture_file = tmp_path / "cap.jsonl"
    config_path.write_text(
        yaml.safe_dump(
            {
                "target": {
                    "kind": "command",
                    "command": ["true"],
                    "env": {},
                },
                "scenarios": [
                    {
                        "id": "s1",
                        "prompt_template": "x",
                        "exfiltration": {"enabled": True, "path": "/collect"},
                    }
                ],
                "mcp": {
                    "enabled": True,
                    "tools": [
                        {
                            "name": "get_contact",
                            "parameters": ["name"],
                            "response_template": '{"phone":"555-1234"}',
                        }
                    ],
                },
            },
            sort_keys=False,
        )
    )

    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_contact",
                "arguments": {"name": "bob"},
            },
        },
    ]
    stdin_payload = "\n".join(json.dumps(r) for r in requests) + "\n"

    env = os.environ.copy()
    env.pop("TDDF_CONFIG_PATH", None)
    env.pop("TDDF_MCP_CAPTURE_FILE", None)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "tddf",
            "mcp-server",
            "--config",
            str(config_path),
            "--capture-file",
            str(capture_file),
        ],
        input=stdin_payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr

    responses = [
        json.loads(line) for line in completed.stdout.splitlines() if line.strip()
    ]
    assert len(responses) == 3
    assert responses[0]["result"]["serverInfo"]["name"] == "tddf-mock"
    tool_names = [t["name"] for t in responses[1]["result"]["tools"]]
    assert "get_contact" in tool_names
    assert responses[2]["id"] == 3
    assert "result" in responses[2]

    calls = load_captures_from_file(capture_file)
    assert len(calls) == 1
    assert calls[0].tool_name == "get_contact"
    assert calls[0].query_arguments == {"name": "bob"}


def test_mcp_server_cli_picks_up_config_from_env(tmp_path: Path) -> None:
    """If --config is not given, the CLI falls back to $TDDF_CONFIG_PATH
    (how `tddf run` hands off to its subprocess children)."""
    config_path = tmp_path / "tddf.yaml"
    capture_file = tmp_path / "cap.jsonl"
    config_path.write_text(
        yaml.safe_dump(
            {
                "target": {"kind": "command", "command": ["true"], "env": {}},
                "scenarios": [
                    {
                        "id": "s1",
                        "prompt_template": "x",
                        "exfiltration": {"enabled": True, "path": "/collect"},
                    }
                ],
                "mcp": {
                    "enabled": True,
                    "tools": [{"name": "ping", "parameters": []}],
                },
            },
            sort_keys=False,
        )
    )

    env = os.environ.copy()
    env["TDDF_CONFIG_PATH"] = str(config_path)
    env["TDDF_MCP_CAPTURE_FILE"] = str(capture_file)

    stdin_payload = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
    )
    completed = subprocess.run(
        [sys.executable, "-m", "tddf", "mcp-server"],
        input=stdin_payload,
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    [response] = [
        json.loads(line) for line in completed.stdout.splitlines() if line.strip()
    ]
    tool_names = [t["name"] for t in response["result"]["tools"]]
    assert "ping" in tool_names


def test_load_captures_tolerates_unknown_fields(tmp_path: Path) -> None:
    """Forward-compat: future McpCall fields don't break replay."""
    path = tmp_path / "cap.jsonl"
    path.write_text(
        json.dumps(
            {
                "tool_name": "ping",
                "resource_key": None,
                "sensitive": False,
                "allowed": True,
                "tool_sensitive": False,
                "resource_sensitive": False,
                "query_arguments": {},
                "some_future_field": "ignored",
            }
        )
        + "\n"
    )
    [call] = load_captures_from_file(path)
    assert call.tool_name == "ping"
