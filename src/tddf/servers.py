from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse

from tddf.config import McpConfig, McpResourceConfig

if TYPE_CHECKING:
    from tddf.results import Evidence


@dataclass(slots=True)
class CapturedRequest:
    path: str
    method: str
    body: str


@dataclass(slots=True)
class RequestCapture:
    requests: list[CapturedRequest] = field(default_factory=list)
    ready: threading.Event = field(default_factory=threading.Event)


@dataclass(slots=True)
class McpCall:
    tool_name: str
    resource_key: str | None
    sensitive: bool
    allowed: bool
    tool_sensitive: bool = False
    resource_sensitive: bool = False


@dataclass(slots=True)
class McpCapture:
    calls: list[McpCall] = field(default_factory=list)


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
    def _store(self, body: str) -> None:
        server = self.server
        capture = getattr(server, "capture")
        capture.requests.append(CapturedRequest(path=self.path, method=self.command, body=body))
        capture.ready.set()

    def do_GET(self) -> None:  # noqa: N802
        self._store("")
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8") if content_length else ""
        self._store(body)
        response = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class _McpHandler(_BaseHandler):
    def _send_json(self, payload: dict[str, Any], status_code: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        capture: McpCapture = getattr(self.server, "mcp_capture")
        config: McpConfig = getattr(self.server, "mcp_config")
        resources: dict[str, McpResourceConfig] = getattr(self.server, "mcp_resources")

        if parsed.path != config.endpoint_path:
            self.send_error(404)
            return

        query = parse_qs(parsed.query)
        tool_name = query.get("tool", ["list_resources"])[0]
        resource_key = query.get("key", [None])[0]
        allowed = tool_name in config.allowed_tools
        tool_sensitive = tool_name in config.sensitive_tools

        if not allowed:
            capture.calls.append(
                McpCall(
                    tool_name=tool_name,
                    resource_key=resource_key,
                    sensitive=False,
                    allowed=False,
                    tool_sensitive=tool_sensitive,
                    resource_sensitive=False,
                )
            )
            self._send_json({"error": f"Tool not allowed: {tool_name}"}, status_code=403)
            return

        if tool_name == "list_resources":
            capture.calls.append(
                McpCall(
                    tool_name=tool_name,
                    resource_key=None,
                    sensitive=tool_sensitive,
                    allowed=True,
                    tool_sensitive=tool_sensitive,
                    resource_sensitive=False,
                )
            )
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
            capture.calls.append(
                McpCall(
                    tool_name=tool_name,
                    resource_key=resource_key,
                    sensitive=tool_sensitive or resource_sensitive,
                    allowed=True,
                    tool_sensitive=tool_sensitive,
                    resource_sensitive=resource_sensitive,
                )
            )
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


def build_capture_evidence(server: RunningServer) -> list[Evidence]:
    if server.capture is None:
        return []

    from tddf.results import Evidence

    return [
        Evidence(
            kind="network_request",
            detail=request.body or "Attacker endpoint contacted",
            path=request.path,
            method=request.method,
        )
        for request in server.capture.requests
    ]


def build_mcp_evidence(server: RunningServer) -> list[Evidence]:
    if server.mcp_capture is None:
        return []

    from tddf.results import Evidence

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
        )
        for call in server.mcp_capture.calls
    ]
