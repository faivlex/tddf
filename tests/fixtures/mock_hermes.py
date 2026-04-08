from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.request import urlopen


def _read_prompt_argument(argv: list[str]) -> str:
    query_index = argv.index("-q")
    return argv[query_index + 1]


def _parse_toolsets(argv: list[str]) -> list[str]:
    if "--toolsets" not in argv:
        return []
    value = argv[argv.index("--toolsets") + 1]
    return [item for item in value.split(",") if item]


def main() -> int:
    argv = os.sys.argv[1:]
    assert argv[:2] == ["chat", "-q"]

    prompt = _read_prompt_argument(argv)
    toolsets = _parse_toolsets(argv)
    trace: dict[str, object] = {
        "prompt": prompt,
        "toolsets": toolsets,
        "used_web": False,
        "used_file": False,
        "used_terminal": False,
        "mcp_resource_count": 0,
    }

    if "web" in toolsets and "TDDF_WEB_URL" in os.environ:
        with urlopen(os.environ["TDDF_WEB_URL"]) as response:  # noqa: S310
            _ = response.read().decode("utf-8")
        trace["used_web"] = True
    if "file" in toolsets and "TDDF_DOCUMENT_PATH" in os.environ:
        _ = Path(os.environ["TDDF_DOCUMENT_PATH"]).read_text()
        trace["used_file"] = True
    if "terminal" in toolsets and "TDDF_DEPUTY_WORKSPACE_DIR" in os.environ:
        workspace_dir = Path(os.environ["TDDF_DEPUTY_WORKSPACE_DIR"])
        _ = [path.name for path in workspace_dir.rglob("*") if path.is_file()]
        trace["used_terminal"] = True

    mcp_payload: dict[str, object] | None = None
    if "TDDF_MCP_URL" in os.environ:
        with urlopen(os.environ["TDDF_MCP_URL"] + "?tool=list_resources") as response:  # noqa: S310
            mcp_payload = json.loads(response.read().decode("utf-8"))
            trace["mcp_resource_count"] = len(mcp_payload.get("resources", []))

    hermes_home = Path(os.environ["HERMES_HOME"])
    config_path = hermes_home / "config.yaml"
    config_text = config_path.read_text() if config_path.exists() else ""
    trace["hermes_home"] = str(hermes_home)
    trace["config_present"] = config_path.exists()

    print(prompt)
    print(toolsets)
    print(config_text)
    if mcp_payload is not None:
        print(mcp_payload["resources"])
    print("TDDF_HERMES_TRACE=" + json.dumps(trace, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
