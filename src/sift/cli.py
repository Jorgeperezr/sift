"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .baseline import filter_findings, load_baseline, write_baseline
from .config import load_config
from .findings import Finding, redact
from .scanner import scan_paths


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sift",
        description="Scan source code for accidentally committed secrets.",
    )
    parser.add_argument("--version", action="version", version=f"sift {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan paths and report findings")
    scan.add_argument("paths", nargs="*", default=["."], help="files or dirs (default: .)")
    scan.add_argument("--baseline", metavar="FILE", help="ignore findings listed in this baseline")
    scan.add_argument("--json", action="store_true", help="emit findings as JSON")
    scan.add_argument("--no-entropy", action="store_true", help="disable high-entropy detection")

    base = sub.add_parser("baseline", help="write current findings to a baseline file")
    base.add_argument("paths", nargs="*", default=["."])
    base.add_argument("-o", "--output", default=".sift-baseline.json", help="baseline path")
    base.add_argument("--no-entropy", action="store_true")

    return parser


def _as_dict(f: Finding) -> dict:
    return {
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "detector": f.detector,
        "secret": redact(f.secret),
        "fingerprint": f.fingerprint,
    }


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    config = load_config()
    if getattr(args, "no_entropy", False):
        config.use_entropy = False
    paths = args.paths or ["."]

    if args.command == "baseline":
        findings = scan_paths(paths, config)
        write_baseline(findings, args.output)
        print(f"Wrote {len(findings)} finding(s) to {args.output}", file=sys.stderr)
        return 0

    findings = scan_paths(paths, config)
    baseline_path = args.baseline or config.baseline
    if baseline_path:
        findings = filter_findings(findings, load_baseline(baseline_path))

    if args.json:
        print(json.dumps([_as_dict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f.render())
        summary = f"{len(findings)} potential secret(s) found." if findings else "No secrets found."
        print(summary, file=sys.stderr)

    return 1 if findings else 0
