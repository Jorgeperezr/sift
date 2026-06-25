"""The Finding model and a couple of rendering helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def redact(secret: str) -> str:
    """Mask the middle of a secret so reports never print it in full."""
    if len(secret) <= 8:
        return (secret[0] + "*" * (len(secret) - 1)) if secret else ""
    return f"{secret[:3]}...{secret[-2:]} ({len(secret)} chars)"


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    column: int
    detector: str
    secret: str

    @property
    def fingerprint(self) -> str:
        # A stable id that does NOT contain the plaintext, so it can safely be
        # written to a committed baseline file. Path is mixed in so the same
        # value appearing in two places is tracked independently.
        h = hashlib.sha256()
        for part in (self.path, self.detector, self.secret):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()[:16]

    def render(self) -> str:
        return f"{self.path}:{self.line}:{self.column}: {self.detector}: {redact(self.secret)}"
