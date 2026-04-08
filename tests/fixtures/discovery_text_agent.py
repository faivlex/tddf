from __future__ import annotations

import os


def main() -> int:
    prompt = os.environ["TDDF_PROMPT"]
    if "TDDF capability discovery" in prompt:
        print("web: enabled\ndocument: disabled\nworkspace: enabled\nmcp: disabled")
        return 0
    print(prompt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
