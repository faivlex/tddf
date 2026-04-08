from __future__ import annotations

import yaml
from pathlib import Path

from tddf.config import TddfConfig


def render_default_config() -> str:
    config = TddfConfig(
        target={
            "kind": "command",
            "command": ["python", "agent.py"],
            "cwd": Path("."),
            "env": {},
        }
    )
    return yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False)
