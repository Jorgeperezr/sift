# sift

A small, dependency-free secret scanner for source code. It flags API keys,
tokens, private keys, and other credentials before they get committed, and is
built to run as a CI check or a pre-commit hook.

Detection combines a curated set of format-specific patterns (AWS, GitHub,
Slack, Stripe, Google, JWTs, private-key blocks, and so on) with a
Shannon-entropy pass that catches generic high-entropy strings the patterns
don't recognise.

## Install

Requires Python 3.11+.

```bash
pip install -e .
```

For development (tests and linter):

```bash
pip install -e ".[dev]"
```

## Usage

Scan the current directory:

```bash
sift scan .
```

Scan specific paths, or emit JSON for other tools:

```bash
sift scan src/ config.py
sift scan . --json
```

`sift` exits with status `1` when it finds something and `0` when it doesn't,
so it drops straight into a pipeline or a pre-commit hook. Secrets are always
redacted in the output:

```
settings.py:4:19: AWS Access Key ID: AKI...LE (20 chars)
settings.py:5:17: GitHub Token: ghp...cd (40 chars)
settings.py:6:13: Generic Assigned Secret: Sup...23 (14 chars)
```

### Ignoring a line

Add a trailing comment to silence a known false positive:

```python
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
```

### Baselines

To adopt `sift` on an existing project without fixing everything at once,
record the current findings as a baseline and commit it. Later scans then
report only new secrets.

```bash
sift baseline . -o .sift-baseline.json
sift scan . --baseline .sift-baseline.json
```

The baseline stores fingerprints, not the secrets themselves, so it is safe to
commit.

## Pre-commit hook

In another repository's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/<you>/sift
    rev: v0.1.0
    hooks:
      - id: sift
```

## Configuration

Optional, under `[tool.sift]` in `pyproject.toml` (or a standalone
`.sift.toml`):

```toml
[tool.sift]
exclude = ["tests/*", "docs/*"]
entropy = true
baseline = ".sift-baseline.json"
```

## Project structure

```
src/sift/
    detectors.py   format-specific regex detectors
    entropy.py     Shannon-entropy detection
    scanner.py     file walking, filtering, concurrency
    baseline.py    baseline read/write and filtering
    config.py      pyproject / .sift.toml loading
    cli.py         command-line interface
tests/             unit tests
```

## Limitations

`sift` reads working-tree files, not git history, so it won't surface secrets
already buried in old commits — use a history scanner for that. It also can't
tell a live credential from a revoked one; it flags anything that matches.

## License

[MIT](LICENSE).
