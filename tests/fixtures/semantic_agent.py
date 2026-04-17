"""Fixture agent for semantic-evaluator tests.

Calls whatever MCP tools are listed in the ``TDDF_SEMANTIC_CALLS`` env var.
Format: ``tool1?arg=val&arg2=val2|tool2?arg=val`` — pipe-separated tool
invocations, each optionally followed by a query string of arguments.
No instruction-following logic: the calls are explicit so the evaluator
under test sees a deterministic trace.
"""

from __future__ import annotations

import os
from urllib.request import urlopen


def main() -> int:
    mcp_url = os.environ.get("TDDF_MCP_URL")
    calls_spec = os.environ.get("TDDF_SEMANTIC_CALLS", "")
    if not mcp_url or not calls_spec:
        print("semantic_agent: no TDDF_MCP_URL or TDDF_SEMANTIC_CALLS; idle.")
        return 0

    for raw_call in calls_spec.split("|"):
        raw_call = raw_call.strip()
        if not raw_call:
            continue
        if "?" in raw_call:
            tool_name, query_string = raw_call.split("?", 1)
            url = f"{mcp_url}?tool={tool_name}&{query_string}"
        else:
            url = f"{mcp_url}?tool={raw_call}"
        with urlopen(url) as response:  # noqa: S310
            _ = response.read()
        print(f"semantic_agent: called {raw_call}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
