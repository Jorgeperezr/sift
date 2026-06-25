"""Read and write the baseline file used to suppress already-reviewed findings.

The baseline stores fingerprints, not secrets, so it is safe to commit.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .findings import Finding

BASELINE_VERSION = 1


def write_baseline(findings: list[Finding], path: str) -> None:
    payload = {
        "version": BASELINE_VERSION,
        "generated": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        "findings": {
            f.fingerprint: {"path": f.path, "line": f.line, "detector": f.detector}
            for f in findings
        },
    }
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load_baseline(path: str) -> set[str]:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return set()
    return set(data.get("findings", {}))


def filter_findings(findings: list[Finding], known: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint not in known]
