"""Entry point for ``python -m tddf`` — used by subprocess spawners
that can't rely on the ``tddf`` console script being on PATH (notably
the ``.mcp.json`` that targets the Claude Agent SDK)."""

from __future__ import annotations

from tddf.cli import app


if __name__ == "__main__":
    app()
