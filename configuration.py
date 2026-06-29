"""INI configuration loading shared by both anomaly detector CLIs."""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Any


def _convert(value: str, template: Any) -> Any:
    if isinstance(template, bool):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"invalid boolean value: {value!r}")
    if isinstance(template, int):
        return int(value)
    if isinstance(template, float):
        return float(value)
    if isinstance(template, Path):
        return Path(value).expanduser()
    return value


def load_settings(
    path: Path,
    section: str,
    defaults: dict[str, Any],
) -> dict[str, Any]:
    """Load common, output, and detector-specific values with strict keys."""
    if not path.is_file():
        raise FileNotFoundError(f"configuration file not found: {path}")
    parser = configparser.ConfigParser()
    with path.open("r", encoding="utf-8") as handle:
        parser.read_file(handle)

    result = dict(defaults)
    allowed_sections = {"common", "output", section}
    unknown_sections = set(parser.sections()) - {
        "common",
        "output",
        "multi_protocol",
    }
    if unknown_sections:
        raise ValueError(
            "unknown configuration section(s): "
            + ", ".join(sorted(unknown_sections))
        )
    for current in ("common", "output", section):
        if current not in parser:
            continue
        for key, raw_value in parser[current].items():
            normalized = key.replace("-", "_")
            if normalized not in result:
                if current in allowed_sections:
                    raise ValueError(
                        f"unknown setting [{current}] {key}"
                    )
                continue
            result[normalized] = _convert(raw_value, defaults[normalized])
    return result
