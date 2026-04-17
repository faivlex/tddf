from __future__ import annotations

import json
from urllib.request import Request, urlopen

import asyncio
import pytest

from tddf.config import McpConfig, McpResourceConfig, McpToolConfig
from tddf.mcp_protocol import (
    ERROR_INVALID_REQUEST,
    ERROR_METHOD_NOT_FOUND,
    ERROR_PARSE,
    ServerState,
    dispatch,
    parse_jsonrpc_request,
)
from tddf.servers import McpCapture, start_mcp_server


# ---------------------------------------------------------------------------
# Unit tests for parse_jsonrpc_request + dispatch.
# ---------------------------------------------------------------------------


def _state() -> ServerState:
    config = McpConfig(
        tools=[
            McpToolConfig(
                name="get_contact",
                parameters=["name"],
                response_template='{"name":"{name}","phone":"555-1234"}',
            ),
            McpToolConfig(
                name="send_email",
                parameters=["to", "body"],
                response_template='{"status":"sent"}',
                sensitive=True,
            ),
        ],
    )
    resources = {item.key: item for item in config.resources}
    return ServerState(config=config, resources=resources, capture=McpCapture())


def test_parse_accepts_well_formed_request() -> None:
    parsed, err = parse_jsonrpc_request(
        '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
    )
    assert err is None
    assert parsed and parsed["method"] == "initialize"


def test_parse_rejects_non_object_payload() -> None:
    _, err = parse_jsonrpc_request("[1, 2, 3]")
    assert err is not None
    assert err.code == ERROR_INVALID_REQUEST


def test_parse_rejects_wrong_jsonrpc_version() -> None:
    _, err = parse_jsonrpc_request('{"jsonrpc":"1.0","id":1,"method":"foo"}')
    assert err is not None
    assert err.code == ERROR_INVALID_REQUEST


def test_parse_rejects_missing_method() -> None:
    _, err = parse_jsonrpc_request('{"jsonrpc":"2.0","id":1}')
    assert err is not None
    assert err.code == ERROR_INVALID_REQUEST


def test_parse_reports_parse_error_on_invalid_json() -> None:
    _, err = parse_jsonrpc_request("{not json")
    assert err is not None
    assert err.code == ERROR_PARSE


def test_dispatch_initialize_negotiates_supported_version() -> None:
    state = _state()
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        },
        state,
    )
    assert response is not None
    result = response.to_dict()["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert state.negotiated_protocol_version == "2025-06-18"


def test_dispatch_initialize_falls_back_to_newest_on_unknown_version() -> None:
    state = _state()
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "9999-01-01"},
        },
        state,
    )
    assert response is not None
    version = response.to_dict()["result"]["protocolVersion"]
    # Newest in the supported list.
    assert version == "2025-06-18"


def test_dispatch_tools_list_includes_builtins_and_configured_tools() -> None:
    state = _state()
    response = dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, state
    )
    assert response is not None
    tools = {tool["name"]: tool for tool in response.to_dict()["result"]["tools"]}
    assert {"list_resources", "read_resource", "get_contact", "send_email"} <= set(
        tools
    )
    # Configured tool carries a generated JSON Schema.
    schema = tools["get_contact"]["inputSchema"]
    assert schema["type"] == "object"
    assert schema["required"] == ["name"]
    assert schema["properties"]["name"]["type"] == "string"


def test_dispatch_tools_list_uses_input_schema_escape_hatch() -> None:
    state = _state()
    # Replace the tool with one that supplies its own schema.
    custom_schema = {
        "type": "object",
        "properties": {"temperature": {"type": "number"}},
        "required": ["temperature"],
    }
    state.config.tools[0] = McpToolConfig(
        name="get_contact",
        parameters=["temperature"],
        input_schema=custom_schema,
        response_template='{"ok":true}',
    )
    response = dispatch(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, state
    )
    tools = {tool["name"]: tool for tool in response.to_dict()["result"]["tools"]}
    assert tools["get_contact"]["inputSchema"] == custom_schema


def test_dispatch_tools_call_records_configured_tool() -> None:
    state = _state()
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_contact", "arguments": {"name": "bob"}},
        },
        state,
    )
    assert response is not None
    result = response.to_dict()["result"]
    assert result["isError"] is False
    assert '"name":"bob"' in result["content"][0]["text"]
    assert len(state.capture.calls) == 1
    assert state.capture.calls[0].query_arguments == {"name": "bob"}


def test_dispatch_tools_call_marks_sensitive_invocations() -> None:
    state = _state()
    dispatch(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "send_email",
                "arguments": {"to": "a@x.com", "body": "hi"},
            },
        },
        state,
    )
    assert state.capture.calls[0].sensitive is True


def test_dispatch_tools_call_rejects_unknown_tool_with_is_error() -> None:
    state = _state()
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        },
        state,
    )
    result = response.to_dict()["result"]
    assert result["isError"] is True
    # The disallowed attempt is still recorded so evaluators can see it.
    assert state.capture.calls[0].allowed is False


def test_dispatch_returns_method_not_found_for_unknown_method() -> None:
    state = _state()
    response = dispatch(
        {"jsonrpc": "2.0", "id": 5, "method": "prompts/list"}, state
    )
    payload = response.to_dict()
    assert payload["error"]["code"] == ERROR_METHOD_NOT_FOUND


def test_dispatch_returns_none_for_notifications() -> None:
    state = _state()
    # Notification — no id field.
    response = dispatch(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}, state
    )
    assert response is None


def test_dispatch_resources_read_by_uri() -> None:
    state = _state()
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": {"uri": "mcp://tddf/demo_secret"},
        },
        state,
    )
    result = response.to_dict()["result"]
    assert result["contents"][0]["uri"] == "mcp://tddf/demo_secret"
    assert "TDDF_DEMO_SECRET" in result["contents"][0]["text"]


def test_dispatch_resources_read_invalid_uri_returns_error() -> None:
    state = _state()
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": {"uri": "mcp://tddf/unknown_key"},
        },
        state,
    )
    # InvalidParams maps to -32602.
    assert response.to_dict()["error"]["code"] == -32602


# ---------------------------------------------------------------------------
# Integration tests — real HTTP against a running mock MCP server.
# ---------------------------------------------------------------------------


@pytest.fixture
def running_mcp_server():
    async def _start():
        config = McpConfig(
            tools=[
                McpToolConfig(
                    name="get_contact",
                    parameters=["name"],
                    response_template='{"name":"{name}","phone":"555-1234"}',
                ),
            ],
        )
        return await start_mcp_server(config), config

    server, config = asyncio.run(_start())
    try:
        yield server, config
    finally:
        server.stop()


def _post_jsonrpc(url: str, body: dict) -> dict:
    req = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urlopen(req) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def test_http_jsonrpc_initialize_records_protocol_version(running_mcp_server):
    server, config = running_mcp_server
    url = f"{server.base_url}{config.endpoint_path}"
    _post_jsonrpc(
        url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        },
    )
    assert getattr(server.httpd, "mcp_negotiated_version", None) == "2024-11-05"


def test_http_jsonrpc_tools_call_captures_invocation(running_mcp_server):
    server, config = running_mcp_server
    url = f"{server.base_url}{config.endpoint_path}"
    response = _post_jsonrpc(
        url,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_contact", "arguments": {"name": "bob"}},
        },
    )
    assert response["result"]["isError"] is False
    with server.mcp_capture.lock:
        calls = list(server.mcp_capture.calls)
    assert len(calls) == 1
    assert calls[0].tool_name == "get_contact"
    assert calls[0].query_arguments == {"name": "bob"}


def test_http_legacy_query_param_path_still_works(running_mcp_server):
    """The original ``GET /mcp?tool=<name>&<args>`` path survives alongside
    JSON-RPC so fixture agents don't need to be rewritten."""
    server, config = running_mcp_server
    url = f"{server.base_url}{config.endpoint_path}?tool=get_contact&name=carol"
    with urlopen(url) as r:  # noqa: S310
        body = json.loads(r.read().decode("utf-8"))
    assert body == {"name": "carol", "phone": "555-1234"}
    with server.mcp_capture.lock:
        assert any(c.query_arguments == {"name": "carol"} for c in server.mcp_capture.calls)
