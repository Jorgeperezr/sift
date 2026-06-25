"""Regex detectors for well-known secret formats.

Patterns with a named ``secret`` group report just that group; the rest report
the whole match. Keeping the list small and specific keeps the false-positive
rate low — generic/unknown secrets are left to the entropy pass.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern[str]

    def scan(self, line: str) -> Iterator[tuple[str, int]]:
        named = "secret" in self.pattern.groupindex
        for m in self.pattern.finditer(line):
            if named:
                yield m.group("secret"), m.start("secret")
            else:
                yield m.group(), m.start()


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


DETECTORS: list[Detector] = [
    Detector("AWS Access Key ID", _c(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b")),
    Detector(
        "AWS Secret Access Key",
        _c(
            r"(?i)aws[_\- ]?secret[_\- ]?access[_\- ]?key"
            r"""[\"'\s:=]{1,4}(?P<secret>[A-Za-z0-9/+=]{40})"""
        ),
    ),
    Detector("GitHub Token", _c(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    Detector("GitHub Fine-grained PAT", _c(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    Detector("Slack Token", _c(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b")),
    Detector("Google API Key", _c(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Detector("Stripe API Key", _c(r"\b(?:sk|rk)_(?:test|live)_[0-9A-Za-z]{16,}\b")),
    Detector(
        "Private Key Block",
        _c(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    Detector(
        "JSON Web Token",
        _c(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ),
    Detector(
        "Slack Webhook",
        _c(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ),
    Detector(
        "Generic Assigned Secret",
        _c(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)"
            r"""\s*[:=]\s*["'](?P<secret>[^"'\s]{8,})["']"""
        ),
    ),
]
