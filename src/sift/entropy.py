"""Shannon entropy helpers used to catch high-entropy (random-looking) strings.

The thresholds mirror the long-standing defaults used by tools like
detect-secrets: base64-ish runs above 4.5 bits/char and hex runs above 3.0.
"""

from __future__ import annotations

import math
import re
import string

BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=")
HEX_CHARS = set(string.hexdigits)

_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{16,}")
_HEX_RUN = re.compile(r"[A-Fa-f0-9]{16,}")


def shannon_entropy(data: str) -> float:
    """Bits of entropy per character. Empty or single-symbol strings score 0."""
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for ch in data:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_high_entropy(
    line: str,
    b64_threshold: float = 4.5,
    hex_threshold: float = 3.0,
):
    """Yield (token, start_col) for substrings that look like encoded secrets."""
    seen: set[str] = set()
    for run, threshold in ((_B64_RUN, b64_threshold), (_HEX_RUN, hex_threshold)):
        for m in run.finditer(line):
            token = m.group()
            if token in seen:
                continue
            if shannon_entropy(token) >= threshold:
                seen.add(token)
                yield token, m.start()
