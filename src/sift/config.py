"""Configuration, read from ``[tool.sift]`` in pyproject.toml or a .sift.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    use_entropy: bool = True
    baseline: str | None = None


def load_config(start: Path | None = None) -> Config:
    start = start or Path.cwd()
    for name in (".sift.toml", "pyproject.toml"):
        path = start / name
        if not path.exists():
            continue
        with path.open("rb") as fh:
            data = tomllib.load(fh)
        if name == "pyproject.toml":
            section = data.get("tool", {}).get("sift", {})
        else:
            section = data.get("sift", data)
        if not section:
            continue
        return Config(
            exclude=list(section.get("exclude", [])),
            use_entropy=bool(section.get("entropy", True)),
            baseline=section.get("baseline"),
        )
    return Config()
