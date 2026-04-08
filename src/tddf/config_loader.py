from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from tddf.config import TddfConfig


class ConfigError(ValueError):
    pass


DEFAULT_CONFIG_PATH = Path("tddf.yaml")


def load_config(path: Path) -> TddfConfig:
    try:
        raw = yaml.safe_load(path.read_text())
    except FileNotFoundError as error:
        raise ConfigError(f"Config file not found: {path}") from error
    except OSError as error:
        raise ConfigError(f"Could not read config file: {path}") from error

    if raw is None:
        raise ConfigError(f"Config file is empty: {path}")

    try:
        return TddfConfig.model_validate(raw)
    except ValidationError as error:
        raise ConfigError(str(error)) from error
