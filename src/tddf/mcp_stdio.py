"""Stdio transport for TDDF's mock MCP server.

The stdio transport is the dominant MCP transport for local tool servers
(Claude Agent SDK spawns MCP servers as subprocesses and communicates
via stdin/stdout). The parent ``tddf run`` process sets up a capture
file and exports its path to the subprocess env. The stdio server (this
module, invoked via ``tddf mcp-server``) appends each captured call to
the file as a JSON line. After the agent exits, the parent process
merges the file's contents back into its in-memory
``McpCapture.calls``, and the structural / semantic evaluators see the
same view they'd see over HTTP.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import TextIO

from tddf.config import McpConfig
from tddf.mcp_protocol import (
    JsonRpcResponse,
    ServerState,
    dispatch,
    parse_jsonrpc_request,
)
from tddf.servers import McpCall, McpCapture


def run_stdio_server(
    config: McpConfig,
    capture_file: Path | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> None:
    """Run TDDF as an MCP server over stdio.

    Reads one JSON-RPC request per line from ``stdin`` (default:
    ``sys.stdin``), dispatches via :mod:`tddf.mcp_protocol`, writes the
    response JSON plus trailing newline to ``stdout`` (default:
    ``sys.stdout``). Notifications (requests without an ``id``) receive
    no response. Captured tool-call records are appended as JSON Lines
    to ``capture_file`` so the parent ``tddf run`` process can observe
    them.

    The loop exits cleanly on EOF; callers typically don't need to
    handle shutdown explicitly — the MCP client closes its end of the
    pipe when it's done.
    """
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout

    resources = {item.key: item for item in config.resources}
    capture = McpCapture()
    state = ServerState(config=config, resources=resources, capture=capture)

    # Track how many records have been flushed to the capture file so we
    # only append new ones each tick rather than rewriting the whole list.
    flushed = 0

    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        request, parse_error = parse_jsonrpc_request(line)
        if parse_error is not None:
            response = JsonRpcResponse(id=None, error=parse_error)
            out_stream.write(json.dumps(response.to_dict()) + "\n")
            out_stream.flush()
            continue
        assert request is not None
        response = dispatch(request, state)
        _flush_new_captures(capture, capture_file, flushed)
        flushed = len(capture.calls)
        if response is None:
            # Notification — no response body per JSON-RPC spec.
            continue
        out_stream.write(json.dumps(response.to_dict()) + "\n")
        out_stream.flush()


def _flush_new_captures(
    capture: McpCapture, capture_file: Path | None, already_flushed: int
) -> None:
    if capture_file is None:
        return
    new_calls = capture.calls[already_flushed:]
    if not new_calls:
        return
    capture_file.parent.mkdir(parents=True, exist_ok=True)
    with capture_file.open("a", encoding="utf-8") as handle:
        for call in new_calls:
            handle.write(json.dumps(asdict(call)) + "\n")


def load_captures_from_file(path: Path) -> list[McpCall]:
    """Read a stdio-server capture file (JSON Lines) and reconstruct the
    ``McpCall`` records. Missing or empty files return ``[]``."""
    if not path.exists():
        return []
    calls: list[McpCall] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        data = json.loads(line)
        # Tolerate older or future fields by filtering to known keys.
        allowed = {
            "tool_name",
            "resource_key",
            "sensitive",
            "allowed",
            "tool_sensitive",
            "resource_sensitive",
            "query_arguments",
        }
        kwargs = {k: v for k, v in data.items() if k in allowed}
        calls.append(McpCall(**kwargs))
    return calls
