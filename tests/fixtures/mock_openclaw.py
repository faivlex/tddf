from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import urlopen


def _read_option(argv: list[str], flag: str) -> str | None:
    if flag not in argv:
        return None
    return argv[argv.index(flag) + 1]


def main() -> int:
    argv = os.sys.argv[1:]
    assert argv and argv[0] == "agent"
    assert "--message" in argv
    assert "--json" in argv

    prompt = _read_option(argv, "--message") or ""
    config_path = Path(os.environ["OPENCLAW_CONFIG_PATH"])
    config_payload = json.loads(config_path.read_text()) if config_path.exists() else {}
    mcp_servers = config_payload.get("mcp", {}).get("servers", {})
    workspace_config = (
        config_payload.get("agents", {}).get("defaults", {}).get("workspace")
    )

    trace: dict[str, object] = {
        "prompt": prompt,
        "agent": _read_option(argv, "--agent"),
        "thinking": _read_option(argv, "--thinking"),
        "verbose": _read_option(argv, "--verbose"),
        "timeout": _read_option(argv, "--timeout"),
        "local": "--local" in argv,
        "config_present": config_path.exists(),
        "config_path": str(config_path),
        "mcp_server_count": len(mcp_servers) if isinstance(mcp_servers, dict) else 0,
        "workspace": workspace_config,
        "used_web": False,
        "used_document": False,
        "used_deputy": False,
        "used_workspace": False,
        "mcp_resource_count": 0,
    }

    if "TDDF_WEB_URL" in os.environ:
        with urlopen(os.environ["TDDF_WEB_URL"]) as response:  # noqa: S310
            _ = response.read().decode("utf-8")
        trace["used_web"] = True
    if "TDDF_DOCUMENT_PATH" in os.environ:
        _ = Path(os.environ["TDDF_DOCUMENT_PATH"]).read_text()
        trace["used_document"] = True
    if "TDDF_DEPUTY_WORKSPACE_DIR" in os.environ:
        workspace_dir = Path(os.environ["TDDF_DEPUTY_WORKSPACE_DIR"])
        _ = [path.name for path in workspace_dir.rglob("*") if path.is_file()]
        trace["used_deputy"] = True
    if "TDDF_WORKSPACE_PATH" in os.environ:
        workspace_path = Path(os.environ["TDDF_WORKSPACE_PATH"])
        _ = [
            path.relative_to(workspace_path)
            for path in workspace_path.rglob("*")
            if path.is_file()
        ]
        trace["used_workspace"] = True
    if "TDDF_MCP_URL" in os.environ:
        with urlopen(os.environ["TDDF_MCP_URL"] + "?tool=list_resources") as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
        trace["mcp_resource_count"] = len(payload.get("resources", []))

    result = {
        "runId": "mock-openclaw-run",
        "status": "completed",
        "summary": "Mock OpenClaw completed safely.",
        "result": {
            "payloads": [{"text": prompt}],
            "meta": trace,
        },
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
