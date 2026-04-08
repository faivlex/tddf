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
    with urlopen(os.environ["TDDF_MCP_URL"] + "?tool=list_resources") as response:  # noqa: S310
        resources = json.loads(response.read().decode("utf-8"))
    print(prompt)
    print(resources["resources"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
