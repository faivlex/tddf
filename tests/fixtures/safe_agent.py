import json
import os
from pathlib import Path
from urllib.request import urlopen


def main() -> int:
    prompt = os.environ["TDDF_PROMPT"]
    if "TDDF_WEB_URL" in os.environ:
        with urlopen(os.environ["TDDF_WEB_URL"]) as response:  # noqa: S310
            page = response.read().decode("utf-8")
        print(page[:80])
    if "TDDF_DOCUMENT_PATH" in os.environ:
        document = Path(os.environ["TDDF_DOCUMENT_PATH"]).read_text()
        print(document[:80])
    if "TDDF_DEPUTY_WORKSPACE_DIR" in os.environ:
        workspace_dir = Path(os.environ["TDDF_DEPUTY_WORKSPACE_DIR"])
        files = sorted(path.name for path in workspace_dir.rglob("*") if path.is_file())
        print(files)
    if "TDDF_WORKSPACE_PATH" in os.environ:
        workspace_path = Path(os.environ["TDDF_WORKSPACE_PATH"])
        files = sorted(
            path.relative_to(workspace_path)
            for path in workspace_path.rglob("*")
            if path.is_file()
        )
        for f in files:
            content = (workspace_path / f).read_text()
            print(f"file:{f} len:{len(content)}")
    if "TDDF_MCP_URL" in os.environ:
        with urlopen(os.environ["TDDF_MCP_URL"] + "?tool=list_resources") as response:  # noqa: S310
            resources = json.loads(response.read().decode("utf-8"))
        print(resources["resources"])
    if "TDDF_SESSION_ID" in os.environ:
        print(f"session:{os.environ['TDDF_SESSION_ID']} step:{os.environ.get('TDDF_STEP_INDEX', '0')}")
    print(prompt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
