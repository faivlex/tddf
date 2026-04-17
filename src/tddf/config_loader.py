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

    if isinstance(raw, dict):
        refs = raw.get("scenarios_from_registry")
        if isinstance(refs, list):
            raw["scenarios_from_registry"] = [
                _absolutize_registry_ref(ref, path.resolve().parent) for ref in refs
            ]

    try:
        return TddfConfig.model_validate(raw)
    except ValidationError as error:
        raise ConfigError(str(error)) from error


def _absolutize_registry_ref(ref: object, config_dir: Path) -> str:
    """Registry references in ``scenarios_from_registry`` may be relative
    paths, absolute paths, or ``builtin://<name>`` URIs. Relative paths are
    resolved against the config's directory so they remain valid when the
    CLI is invoked from anywhere."""
    text = str(ref)
    if text.startswith("builtin://"):
        return text
    candidate = Path(text)
    if candidate.is_absolute():
        return str(candidate)
    return str((config_dir / candidate).resolve())
