from __future__ import annotations

import json
import os


def main() -> int:
    prompt = os.environ["TDDF_PROMPT"]
    if "TDDF capability discovery" in prompt:
        print(
            json.dumps(
                {
                    "web": True,
                    "document": False,
                    "deputy": False,
                    "workspace": True,
                    "mcp": False,
                }
            )
        )
        return 0
    print(prompt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
