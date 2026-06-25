"""Walk a path, read text files, and collect findings."""

from __future__ import annotations

import concurrent.futures
import fnmatch
import os
from pathlib import Path

from .config import Config
from .detectors import DETECTORS
from .entropy import iter_high_entropy
from .findings import Finding

# Things that are either noise or not worth reading.
_DEFAULT_EXCLUDES = [
    ".git/*", "*/.git/*",
    ".venv/*", "venv/*", "*/.venv/*",
    "node_modules/*", "*/node_modules/*",
    "__pycache__/*", "*/__pycache__/*",
    ".pytest_cache/*", "*/.pytest_cache/*",
    ".ruff_cache/*", "*/.ruff_cache/*",
    ".mypy_cache/*", "*/.mypy_cache/*",
    "*.egg-info/*",
    "build/*", "dist/*",
    "*.min.js", "*.map", "*.lock",
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico", "*.pdf",
    "*.zip", "*.gz", "*.tar", "*.whl", "*.so", "*.pyc",
]

# Inline markers that tell sift to skip a line, same spirit as detect-secrets.
_ALLOWLIST_MARKERS = ("pragma: allowlist secret", "sift:allow")

_MAX_BYTES = 2 * 1024 * 1024


def _looks_binary(chunk: bytes) -> bool:
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    printable = bytes(range(32, 127)) + b"\n\r\t\f\b"
    nontext = sum(b not in printable for b in chunk)
    return nontext / len(chunk) > 0.30


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in patterns)


def _scan_text(path: str, text: str, use_entropy: bool) -> list[Finding]:
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if any(marker in line for marker in _ALLOWLIST_MARKERS):
            continue
        for det in DETECTORS:
            for secret, col in det.scan(line):
                out.append(Finding(path, lineno, col + 1, det.name, secret))
        if use_entropy:
            for token, col in iter_high_entropy(line):
                out.append(Finding(path, lineno, col + 1, "High Entropy String", token))
    return out


def _iter_files(paths, excludes, root):
    for base in paths:
        p = Path(base)
        candidates = [p] if p.is_file() else (f for f in p.rglob("*") if f.is_file())
        for f in candidates:
            rel = os.path.relpath(f, root)
            if not _excluded(rel, excludes):
                yield f, rel


def scan_paths(paths, config: Config | None = None) -> list[Finding]:
    config = config or Config()
    excludes = _DEFAULT_EXCLUDES + list(config.exclude)
    root = Path.cwd()
    targets = list(_iter_files(paths, excludes, root))

    def work(item):
        f, rel = item
        try:
            raw = f.read_bytes()
        except OSError:
            return []
        if len(raw) > _MAX_BYTES or _looks_binary(raw[:1024]):
            return []
        return _scan_text(rel, raw.decode("utf-8", errors="replace"), config.use_entropy)

    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor() as pool:
        for chunk in pool.map(work, targets):
            findings.extend(chunk)

    # Drop exact duplicates and sort so output is deterministic.
    unique = {(f.path, f.line, f.column, f.detector, f.secret): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f.path, f.line, f.column, f.detector))
