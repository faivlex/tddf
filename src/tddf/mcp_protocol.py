"""JSON-RPC 2.0 core + MCP method dispatch.

TDDF's mock MCP surface previously accepted a homegrown HTTP shape
(``GET /mcp?tool=<name>&<args>``). This module adds real MCP protocol
handling: JSON-RPC 2.0 envelopes, the five methods TDDF supports
(``initialize`` / ``tools/list`` / ``tools/call`` / ``resources/list`` /
``resources/read``), and a dispatch function the transport layer calls
for each incoming request.

The plain-HTTP query-param path is preserved at the transport layer for
backward-compatibility with fixture agents and pedagogical examples.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from tddf.config import McpConfig, McpResourceConfig, McpToolConfig
from tddf.servers import McpCall, McpCapture, _render_tool_response


# TDDF-declared server metadata returned on ``initialize``.
TDDF_MCP_SERVER_NAME = "tddf-mock"
TDDF_MCP_SERVER_VERSION = "1"

# Protocol versions TDDF advertises support for (newest first). MCP clients
# negotiate by offering their preferred version; TDDF echoes back the first
# one in this list that the client also supports, or the client's offered
# version if that's the only thing we can do.
_SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")


# JSON-RPC 2.0 standard error codes.
ERROR_PARSE = -32700
ERROR_INVALID_REQUEST = -32600
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INVALID_PARAMS = -32602
ERROR_INTERNAL = -32603


@dataclass(slots=True)
class JsonRpcError:
    code: int
    message: str
    data: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            payload["data"] = self.data
        return payload


@dataclass(slots=True)
class JsonRpcResponse:
    id: int | str | None
    result: dict[str, Any] | None = None
    error: JsonRpcError | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self.id}
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        else:
            payload["result"] = self.result or {}
        return payload


@dataclass(slots=True)
class ServerState:
    """State the dispatcher needs access to on every request."""

    config: McpConfig
    resources: dict[str, McpResourceConfig]
    capture: McpCapture
    negotiated_protocol_version: str | None = field(default=None)


def parse_jsonrpc_request(raw: str) -> tuple[dict[str, Any] | None, JsonRpcError | None]:
    """Return ``(parsed, None)`` on success or ``(None, error)`` if the bytes
    are not a well-formed JSON-RPC 2.0 request."""
    payload, error = parse_jsonrpc_payload(raw)
    if error is not None:
        return None, error
    if not isinstance(payload, dict):
        return None, JsonRpcError(
            ERROR_INVALID_REQUEST,
            "Invalid Request: top-level JSON must be an object",
        )
    return validate_jsonrpc_request_obj(payload)


def parse_jsonrpc_payload(
    raw: str,
) -> tuple[dict[str, Any] | list[dict[str, Any]] | None, JsonRpcError | None]:
    """Parse a single JSON-RPC message or batch payload."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, JsonRpcError(ERROR_PARSE, f"Parse error: {exc}")
    if isinstance(data, list):
        if not data:
            return None, JsonRpcError(
                ERROR_INVALID_REQUEST,
                "Invalid Request: batch payload must not be empty",
            )
        if not all(isinstance(item, dict) for item in data):
            return None, JsonRpcError(
                ERROR_INVALID_REQUEST,
                "Invalid Request: batch items must be objects",
            )
        return data, None
    if isinstance(data, dict):
        return data, None
    return None, JsonRpcError(
        ERROR_INVALID_REQUEST,
        "Invalid Request: top-level JSON must be an object",
    )


def validate_jsonrpc_request_obj(
    data: Any,
) -> tuple[dict[str, Any] | None, JsonRpcError | None]:
    if not isinstance(data, dict):
        return None, JsonRpcError(
            ERROR_INVALID_REQUEST,
            "Invalid Request: top-level JSON must be an object",
        )
    if data.get("jsonrpc") != "2.0":
        return None, JsonRpcError(
            ERROR_INVALID_REQUEST,
            "Invalid Request: missing or non-'2.0' jsonrpc field",
        )
    if "method" not in data or not isinstance(data["method"], str):
        return None, JsonRpcError(
            ERROR_INVALID_REQUEST,
            "Invalid Request: missing or non-string method field",
        )
    return data, None


def is_jsonrpc_response(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and data.get("jsonrpc") == "2.0"
        and "method" not in data
        and ("result" in data or "error" in data)
    )


def dispatch_payload(
    payload: dict[str, Any] | list[dict[str, Any]],
    state: ServerState,
) -> list[JsonRpcResponse]:
    """Dispatch a single JSON-RPC payload or batch.

    Client responses are accepted and ignored; notifications produce no
    response entries.
    """
    items = payload if isinstance(payload, list) else [payload]
    responses: list[JsonRpcResponse] = []
    for item in items:
        if is_jsonrpc_response(item):
            continue
        request, error = validate_jsonrpc_request_obj(item)
        if error is not None:
            item_id = item.get("id") if isinstance(item, dict) else None
            responses.append(JsonRpcResponse(id=item_id, error=error))
            continue
        assert request is not None
        response = dispatch(request, state)
        if response is not None:
            responses.append(response)
    return responses


def is_supported_protocol_version(version: str) -> bool:
    return version in _SUPPORTED_PROTOCOL_VERSIONS


def dispatch(
    request: dict[str, Any], state: ServerState
) -> JsonRpcResponse | None:
    """Dispatch a parsed JSON-RPC request to its method handler.

    Returns ``None`` for JSON-RPC *notifications* (requests without an
    ``id`` field — no response is expected). Returns a ``JsonRpcResponse``
    for requests.
    """
    request_id = request.get("id")
    is_notification = "id" not in request
    method = request["method"]
    params = request.get("params") or {}

    try:
        handler = _METHOD_HANDLERS.get(method)
        if handler is None:
            if is_notification:
                # Unknown notifications are silently ignored per spec.
                return None
            return JsonRpcResponse(
                id=request_id,
                error=JsonRpcError(
                    ERROR_METHOD_NOT_FOUND, f"Method not found: {method}"
                ),
            )
        result = handler(params, state)
    except InvalidParams as exc:
        if is_notification:
            return None
        return JsonRpcResponse(
            id=request_id,
            error=JsonRpcError(ERROR_INVALID_PARAMS, str(exc)),
        )
    except Exception as exc:  # noqa: BLE001 — surfacing internal errors
        if is_notification:
            return None
        return JsonRpcResponse(
            id=request_id,
            error=JsonRpcError(ERROR_INTERNAL, f"Internal error: {exc}"),
        )

    if is_notification:
        return None
    return JsonRpcResponse(id=request_id, result=result)


class InvalidParams(ValueError):
    """Raised inside a method handler to signal bad params — dispatched to
    JSON-RPC error code -32602."""


# ---------------------------------------------------------------------------
# Method handlers.
# ---------------------------------------------------------------------------


def _handle_initialize(params: dict[str, Any], state: ServerState) -> dict[str, Any]:
    client_version = params.get("protocolVersion")
    # Negotiate: echo the client's version if we support it; otherwise pick
    # our newest and let the client decide whether to proceed.
    if isinstance(client_version, str) and client_version in _SUPPORTED_PROTOCOL_VERSIONS:
        negotiated = client_version
    else:
        negotiated = _SUPPORTED_PROTOCOL_VERSIONS[0]
    state.negotiated_protocol_version = negotiated
    capabilities: dict[str, dict[str, Any]] = {"tools": {}}
    if any(
        name in state.config.allowed_tools for name in ("list_resources", "read_resource")
    ):
        capabilities["resources"] = {}
    return {
        "protocolVersion": negotiated,
        "capabilities": capabilities,
        "serverInfo": {
            "name": TDDF_MCP_SERVER_NAME,
            "version": TDDF_MCP_SERVER_VERSION,
        },
    }


def _handle_tools_list(params: dict[str, Any], state: ServerState) -> dict[str, Any]:
    tools = [_tool_descriptor(tool) for tool in state.config.tools]
    # Expose the legacy built-in tools too so MCP clients see the full
    # surface the handler supports.
    builtin = _builtin_tool_descriptors(state.config)
    return {"tools": builtin + tools}


def _handle_tools_call(
    params: dict[str, Any], state: ServerState
) -> dict[str, Any]:
    name = params.get("name")
    if not isinstance(name, str):
        raise InvalidParams("tools/call requires a string 'name' field")
    raw_args = params.get("arguments") or {}
    if not isinstance(raw_args, dict):
        raise InvalidParams("tools/call 'arguments' must be an object")
    arguments = {str(k): v for k, v in raw_args.items()}

    sensitive = state.config.is_sensitive_tool(name)
    builtin_allowed = name in state.config.allowed_tools

    # Built-in surface stays as-is.
    if name == "list_resources":
        if not builtin_allowed:
            return _disallowed_tool_response(state, name, arguments, sensitive)
        return _call_list_resources(state, arguments, sensitive)
    if name == "read_resource":
        if not builtin_allowed:
            return _disallowed_tool_response(state, name, arguments, sensitive)
        return _call_read_resource(state, arguments, sensitive)

    custom_tool = next(
        (tool for tool in state.config.tools if tool.name == name), None
    )
    if custom_tool is None:
        return _disallowed_tool_response(state, name, arguments, sensitive)

    rendered = _render_tool_response(custom_tool.response_template, arguments)
    _record_call(
        state,
        McpCall(
            tool_name=name,
            resource_key=None,
            sensitive=sensitive,
            allowed=True,
            tool_sensitive=sensitive,
            resource_sensitive=False,
            query_arguments=arguments,
        ),
    )
    return _text_content(rendered)


def _handle_resources_list(
    params: dict[str, Any], state: ServerState
) -> dict[str, Any]:
    _require_allowed_resource_method(state, "list_resources")
    sensitive = state.config.is_sensitive_tool("list_resources")
    _record_call(
        state,
        McpCall(
            tool_name="list_resources",
            resource_key=None,
            sensitive=sensitive,
            allowed=True,
            tool_sensitive=sensitive,
            resource_sensitive=False,
            query_arguments={},
        ),
    )
    entries = [
        {
            "uri": f"mcp://tddf/{resource.key}",
            "name": resource.key,
            "description": None,
            "mimeType": "application/json",
        }
        for resource in state.resources.values()
    ]
    return {"resources": entries}


def _handle_resources_read(
    params: dict[str, Any], state: ServerState
) -> dict[str, Any]:
    uri = params.get("uri")
    if not isinstance(uri, str):
        raise InvalidParams("resources/read requires a string 'uri' field")
    # Accept either ``mcp://tddf/<key>`` or bare ``<key>`` for ergonomic wins.
    key = uri.split("/")[-1] if "://" in uri else uri
    _require_allowed_resource_method(state, "read_resource", {"key": key})
    resource = state.resources.get(key)
    if resource is None:
        raise InvalidParams(f"Unknown resource: {uri}")
    sensitive = state.config.is_sensitive_tool("read_resource") or resource.sensitive
    _record_call(
        state,
        McpCall(
            tool_name="read_resource",
            resource_key=key,
            sensitive=sensitive,
            allowed=True,
            tool_sensitive=state.config.is_sensitive_tool("read_resource"),
            resource_sensitive=resource.sensitive,
            query_arguments={"key": key},
        ),
    )
    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": "application/json",
                "text": json.dumps(
                    {
                        "key": resource.key,
                        "value": resource.value,
                        "sensitive": resource.sensitive,
                    }
                ),
            }
        ]
    }


_METHOD_HANDLERS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
    "resources/list": _handle_resources_list,
    "resources/read": _handle_resources_read,
}


# ---------------------------------------------------------------------------
# Helpers for method handlers.
# ---------------------------------------------------------------------------


def _tool_descriptor(tool: McpToolConfig) -> dict[str, Any]:
    """Build an MCP tools/list entry for a configured tool."""
    if tool.input_schema is not None:
        schema = dict(tool.input_schema)
    else:
        properties: dict[str, dict[str, Any]] = {}
        for parameter in tool.parameters:
            entry: dict[str, Any] = {"type": "string"}
            if tool.parameter_descriptions.get(parameter):
                entry["description"] = tool.parameter_descriptions[parameter]
            properties[parameter] = entry
        schema = {
            "type": "object",
            "properties": properties,
            "required": list(tool.parameters),
        }
    descriptor: dict[str, Any] = {"name": tool.name, "inputSchema": schema}
    if tool.description:
        descriptor["description"] = tool.description
    return descriptor


def _builtin_tool_descriptors(config: McpConfig) -> list[dict[str, Any]]:
    """Descriptors for ``list_resources`` / ``read_resource`` so real MCP
    clients can discover the legacy surface via ``tools/list``."""
    descriptors: list[dict[str, Any]] = []
    if "list_resources" in config.allowed_tools:
        descriptors.append(
            {
                "name": "list_resources",
                "description": "List MCP resources declared in the TDDF config.",
                "inputSchema": {"type": "object", "properties": {}, "required": []},
            }
        )
    if "read_resource" in config.allowed_tools:
        descriptors.append(
            {
                "name": "read_resource",
                "description": "Read a named MCP resource by its key.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"key": {"type": "string"}},
                    "required": ["key"],
                },
            }
        )
    return descriptors


def _call_list_resources(
    state: ServerState, arguments: dict[str, object], sensitive: bool
) -> dict[str, Any]:
    _record_call(
        state,
        McpCall(
            tool_name="list_resources",
            resource_key=None,
            sensitive=sensitive,
            allowed=True,
            tool_sensitive=sensitive,
            resource_sensitive=False,
            query_arguments=arguments,
        ),
    )
    payload = {
        "tool": "list_resources",
        "resources": [
            {"key": resource.key, "sensitive": resource.sensitive}
            for resource in state.resources.values()
        ],
    }
    return _text_content(json.dumps(payload))


def _call_read_resource(
    state: ServerState, arguments: dict[str, object], tool_sensitive: bool
) -> dict[str, Any]:
    key = arguments.get("key")
    if not isinstance(key, str) or not key:
        raise InvalidParams("read_resource requires a 'key' argument")
    resource = state.resources.get(key)
    if resource is None:
        raise InvalidParams(f"Unknown resource: {key}")
    sensitive = tool_sensitive or resource.sensitive
    _record_call(
        state,
        McpCall(
            tool_name="read_resource",
            resource_key=key,
            sensitive=sensitive,
            allowed=True,
            tool_sensitive=tool_sensitive,
            resource_sensitive=resource.sensitive,
            query_arguments=arguments,
        ),
    )
    payload = {
        "tool": "read_resource",
        "resource": {
            "key": resource.key,
            "value": resource.value,
            "sensitive": resource.sensitive,
        },
    }
    return _text_content(json.dumps(payload))


def _disallowed_tool_response(
    state: ServerState,
    name: str,
    arguments: dict[str, object],
    sensitive: bool,
) -> dict[str, Any]:
    # Record the disallowed attempt so evaluators can still see it.
    _record_call(
        state,
        McpCall(
            tool_name=name,
            resource_key=None,
            sensitive=sensitive,
            allowed=False,
            tool_sensitive=sensitive,
            resource_sensitive=False,
            query_arguments=arguments,
        ),
    )
    return _text_content(f"Tool not allowed: {name}", is_error=True)


def _require_allowed_resource_method(
    state: ServerState,
    tool_name: str,
    arguments: dict[str, object] | None = None,
) -> None:
    if tool_name in state.config.allowed_tools:
        return
    sensitive = state.config.is_sensitive_tool(tool_name)
    _record_call(
        state,
        McpCall(
            tool_name=tool_name,
            resource_key=(arguments or {}).get("key") if arguments else None,
            sensitive=sensitive,
            allowed=False,
            tool_sensitive=sensitive,
            resource_sensitive=False,
            query_arguments=arguments or {},
        ),
    )
    raise InvalidParams(f"{tool_name} is not allowed")


def _record_call(state: ServerState, entry: McpCall) -> None:
    with state.capture.lock:
        state.capture.calls.append(entry)


def _text_content(text: str, *, is_error: bool = False) -> dict[str, Any]:
    """Wrap a string in MCP's ``tools/call`` response envelope."""
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }
