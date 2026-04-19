from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from tddf.config import McpConfig, McpResourceConfig, McpToolConfig


_TOOL_TEMPLATE_TOKEN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def _render_tool_response(template: str, args: dict[str, object]) -> str:
    """Substitute ``{arg_name}`` tokens in ``template`` with the caller's
    argument values. Missing args render as ``<missing:arg_name>`` so the
    misconfiguration shows up in the response rather than silently emitting
    a half-rendered template."""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        value = args.get(key, f"<missing:{key}>")
        if isinstance(value, str):
            start, end = match.span()
            if start > 0 and end < len(template):
                if template[start - 1] == '"' and template[end] == '"':
                    return json.dumps(value, ensure_ascii=True)[1:-1]
            return value
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))

    return _TOOL_TEMPLATE_TOKEN.sub(replace, template)

if TYPE_CHECKING:
    from tddf.results import Evidence


@dataclass(slots=True)
class CapturedRequest:
    path: str
    method: str
    body: str
    observed_at_ns: int
    headers: dict[str, str] = field(default_factory=dict)
    body_size: int = 0


@dataclass(slots=True)
class RequestCapture:
    requests: list[CapturedRequest] = field(default_factory=list)
    ready: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)


@dataclass(slots=True)
class McpCall:
    tool_name: str
    resource_key: str | None
    sensitive: bool
    allowed: bool
    tool_sensitive: bool = False
    resource_sensitive: bool = False
    query_arguments: dict[str, object] = field(default_factory=dict)
    observed_at_ns: int = field(default_factory=time.time_ns)


@dataclass(slots=True)
class McpCapture:
    calls: list[McpCall] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _BaseHandler(BaseHTTPRequestHandler):
    server_version = "TDDF/0.1"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


class _ArticleHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        html_body = getattr(server, "html_body")
        path = getattr(server, "article_path")
        if self.path != path:
            self.send_error(404)
            return
        body = html_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CaptureHandler(_BaseHandler):
    def _captured_headers(self) -> dict[str, str]:
        return {key: value for key, value in self.headers.items()}

    def _store(self, body: str, body_size: int) -> None:
        server = self.server
        capture = getattr(server, "capture")
        entry = CapturedRequest(
            path=self.path,
            method=self.command,
            body=body,
            observed_at_ns=time.time_ns(),
            headers=self._captured_headers(),
            body_size=body_size,
        )
        with capture.lock:
            capture.requests.append(entry)
        capture.ready.set()

    def do_GET(self) -> None:  # noqa: N802
        self._store("", 0)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b""
        body = raw.decode("utf-8", errors="replace")
        self._store(body, len(raw))
        response = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class _McpHandler(_BaseHandler):
    def _send_json(self, payload: Any, status_code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_empty(self, status_code: int = 204) -> None:
        self.send_response(status_code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _origin_is_allowed(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return parsed.hostname in {"127.0.0.1", "localhost"}

    def _protocol_version_is_allowed(self) -> bool:
        version = self.headers.get("MCP-Protocol-Version")
        if version is None:
            return True
        from tddf.mcp_protocol import is_supported_protocol_version

        return is_supported_protocol_version(version)

    def do_POST(self) -> None:  # noqa: N802
        """Handle an MCP JSON-RPC 2.0 request (streamable-HTTP transport).

        Reads a JSON-RPC payload from the body (single request or batch),
        dispatches it via the method handlers in ``tddf.mcp_protocol``, and
        writes the JSON-RPC response payload. Notifications / client-response
        payloads with no server responses receive ``202 Accepted``.
        """
        parsed = urlparse(self.path)
        config: McpConfig = getattr(self.server, "mcp_config")
        if parsed.path != config.endpoint_path:
            self.send_error(404)
            return
        if not self._origin_is_allowed():
            self.send_error(403, "Origin not allowed")
            return
        if not self._protocol_version_is_allowed():
            self.send_error(400, "Unsupported MCP-Protocol-Version")
            return

        # Deferred import to keep the module graph layered — protocol depends
        # on this module's McpCall / McpCapture types.
        from tddf.mcp_protocol import (
            ServerState,
            dispatch_payload,
            parse_jsonrpc_payload,
        )

        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length).decode("utf-8") if content_length else ""

        capture: McpCapture = getattr(self.server, "mcp_capture")
        resources: dict[str, McpResourceConfig] = getattr(
            self.server, "mcp_resources"
        )
        state = ServerState(config=config, resources=resources, capture=capture)
        # Preserve any previously-negotiated protocol version across requests
        # on the same server — the handler may be invoked per-request, but
        # the server object persists the negotiated value for the run.
        negotiated = getattr(self.server, "mcp_negotiated_version", None)
        if negotiated:
            state.negotiated_protocol_version = negotiated

        payload, parse_error = parse_jsonrpc_payload(raw)
        if parse_error is not None:
            self._send_json(
                {"jsonrpc": "2.0", "id": None, "error": parse_error.to_dict()},
                status_code=400,
            )
            return

        assert payload is not None
        responses = dispatch_payload(payload, state)

        # Persist any negotiated protocol version back onto the server.
        if state.negotiated_protocol_version:
            setattr(
                self.server,
                "mcp_negotiated_version",
                state.negotiated_protocol_version,
            )

        if not responses:
            # Notifications / client responses are accepted with no body.
            self._send_empty(status_code=202)
            return
        if isinstance(payload, list):
            self._send_json([response.to_dict() for response in responses])
            return
        self._send_json(responses[0].to_dict())

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        capture: McpCapture = getattr(self.server, "mcp_capture")
        config: McpConfig = getattr(self.server, "mcp_config")
        resources: dict[str, McpResourceConfig] = getattr(self.server, "mcp_resources")

        if parsed.path != config.endpoint_path:
            self.send_error(404)
            return
        if not self._origin_is_allowed():
            self.send_error(403, "Origin not allowed")
            return
        if not self._protocol_version_is_allowed():
            self.send_error(400, "Unsupported MCP-Protocol-Version")
            return

        query = parse_qs(parsed.query)
        if "tool" not in query and "key" not in query:
            self.send_error(405)
            return
        # The ``tool`` and ``key`` query keys are already surfaced as structured
        # fields (``tool_name`` / ``resource_key``) on the evidence record;
        # omit them from ``query_arguments`` to avoid echoing them back twice
        # in the rendered ``args:`` line.
        flat_query = {
            key: values[0]
            for key, values in query.items()
            if values and key not in {"tool", "key"}
        }
        default_tool = "read_resource" if "key" in query else "list_resources"
        tool_name = query.get("tool", [default_tool])[0]
        resource_key = query.get("key", [None])[0]
        custom_tool: McpToolConfig | None = next(
            (tool for tool in config.tools if tool.name == tool_name), None
        )
        # A tool is allowed if it's in ``allowed_tools`` OR explicitly
        # configured via ``tools:`` (configuring a tool implies allowing it).
        allowed = tool_name in config.allowed_tools or custom_tool is not None
        tool_sensitive = config.is_sensitive_tool(tool_name)

        if not allowed:
            entry = McpCall(
                tool_name=tool_name,
                resource_key=resource_key,
                sensitive=False,
                allowed=False,
                tool_sensitive=tool_sensitive,
                resource_sensitive=False,
                query_arguments=flat_query,
            )
            with capture.lock:
                capture.calls.append(entry)
            self._send_json({"error": f"Tool not allowed: {tool_name}"}, status_code=403)
            return

        if tool_name == "list_resources":
            entry = McpCall(
                tool_name=tool_name,
                resource_key=None,
                sensitive=tool_sensitive,
                allowed=True,
                tool_sensitive=tool_sensitive,
                resource_sensitive=False,
                query_arguments=flat_query,
            )
            with capture.lock:
                capture.calls.append(entry)
            self._send_json(
                {
                    "tool": tool_name,
                    "resources": [
                        {"key": item.key, "sensitive": item.sensitive}
                        for item in resources.values()
                    ],
                }
            )
            return

        if tool_name == "read_resource":
            if resource_key is None or resource_key not in resources:
                self._send_json({"error": "Unknown resource"}, status_code=404)
                return
            resource = resources[resource_key]
            resource_sensitive = resource.sensitive
            entry = McpCall(
                tool_name=tool_name,
                resource_key=resource_key,
                sensitive=tool_sensitive or resource_sensitive,
                allowed=True,
                tool_sensitive=tool_sensitive,
                resource_sensitive=resource_sensitive,
                query_arguments=flat_query,
            )
            with capture.lock:
                capture.calls.append(entry)
            self._send_json(
                {
                    "tool": tool_name,
                    "resource": {
                        "key": resource.key,
                        "value": resource.value,
                        "sensitive": resource.sensitive,
                    },
                }
            )
            return

        if custom_tool is not None:
            rendered = _render_tool_response(
                custom_tool.response_template, flat_query
            )
            try:
                payload = json.loads(rendered)
            except json.JSONDecodeError:
                payload = {"raw_response": rendered}
            entry = McpCall(
                tool_name=tool_name,
                resource_key=resource_key,
                sensitive=tool_sensitive,
                allowed=True,
                tool_sensitive=tool_sensitive,
                resource_sensitive=False,
                query_arguments=flat_query,
            )
            with capture.lock:
                capture.calls.append(entry)
            self._send_json(payload)
            return

        self._send_json({"error": f"Unsupported tool: {tool_name}"}, status_code=400)


@dataclass(slots=True)
class RunningServer:
    httpd: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str
    capture: RequestCapture | None = None
    mcp_capture: McpCapture | None = None

    def stop(self) -> None:
        self.httpd.shutdown()
        self.thread.join(timeout=5)
        self.httpd.server_close()


async def start_article_server(html_body: str, path: str) -> RunningServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _ArticleHandler)
    setattr(httpd, "html_body", html_body)
    setattr(httpd, "article_path", path)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    return RunningServer(httpd=httpd, thread=thread, base_url=f"http://{host}:{port}")


async def start_capture_server() -> RunningServer:
    capture = RequestCapture()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
    setattr(httpd, "capture", capture)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    return RunningServer(
        httpd=httpd,
        thread=thread,
        base_url=f"http://{host}:{port}",
        capture=capture,
    )


async def start_mcp_server(config: McpConfig) -> RunningServer:
    capture = McpCapture()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _McpHandler)
    setattr(httpd, "mcp_capture", capture)
    setattr(httpd, "mcp_config", config)
    setattr(httpd, "mcp_resources", {item.key: item for item in config.resources})
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    return RunningServer(
        httpd=httpd,
        thread=thread,
        base_url=f"http://{host}:{port}",
        mcp_capture=capture,
    )


def snapshot_capture_count(server: RunningServer) -> int:
    if server.capture is None:
        return 0
    with server.capture.lock:
        return len(server.capture.requests)


def snapshot_mcp_count(server: RunningServer) -> int:
    if server.mcp_capture is None:
        return 0
    with server.mcp_capture.lock:
        return len(server.mcp_capture.calls)


def _split_path_query(path: str) -> tuple[str, str | None]:
    parsed = urlparse(path)
    return parsed.path, (parsed.query or None)


def build_capture_evidence(server: RunningServer) -> list[Evidence]:
    if server.capture is None:
        return []

    from tddf.results import Evidence

    with server.capture.lock:
        requests_snapshot = list(server.capture.requests)

    items: list[Evidence] = []
    for request in requests_snapshot:
        _path_only, query = _split_path_query(request.path)
        items.append(
            Evidence(
                kind="network_request",
                detail=(
                    f"{request.method} {request.path} "
                    f"({request.body_size} bytes)"
                    if request.body_size
                    else f"{request.method} {request.path}"
                ),
                path=request.path,
                method=request.method,
                query_string=query,
                headers=dict(request.headers),
                body_preview=request.body or None,
                body_size=request.body_size,
                observed_at_ns=request.observed_at_ns,
            )
        )
    return items


def build_mcp_evidence(server: RunningServer) -> list[Evidence]:
    if server.mcp_capture is None:
        return []

    from tddf.results import Evidence

    with server.mcp_capture.lock:
        calls_snapshot = list(server.mcp_capture.calls)

    return [
        Evidence(
            kind="tool_call",
            detail=(
                f"Sensitive MCP tool invoked: {call.tool_name}"
                if call.tool_sensitive and not call.resource_sensitive
                else f"Sensitive MCP tool invoked: {call.tool_name} on {call.resource_key}"
                if call.tool_sensitive and call.resource_key is not None and not call.resource_sensitive
                else f"Sensitive MCP resource accessed: {call.resource_key}"
                if call.resource_sensitive and not call.tool_sensitive
                else f"Sensitive MCP tool and resource access: {call.tool_name} -> {call.resource_key}"
                if call.tool_sensitive and call.resource_sensitive
                else f"MCP tool invoked: {call.tool_name}"
            ),
            path=None,
            method="GET",
            tool_name=call.tool_name,
            resource_key=call.resource_key,
            sensitive=call.sensitive,
            tool_arguments=dict(call.query_arguments) if call.query_arguments else None,
            observed_at_ns=call.observed_at_ns,
        )
        for call in calls_snapshot
    ]
