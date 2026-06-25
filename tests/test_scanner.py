from sift.config import Config
from sift.scanner import scan_paths


def test_finds_secret_in_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.py").write_text('value = "AKIAIOSFODNN7EXAMPLE"\nx = 1\n')
    findings = scan_paths(["."], Config(use_entropy=False))
    assert len(findings) == 1
    assert findings[0].detector == "AWS Access Key ID"
    assert findings[0].line == 1


def test_allowlist_comment_suppresses(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "x.py").write_text('key = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret\n')
    assert scan_paths(["."], Config(use_entropy=False)) == []


def test_binary_file_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01AKIAIOSFODNN7EXAMPLE\x00\x02")
    assert scan_paths(["."], Config(use_entropy=False)) == []


def test_excluded_glob(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text('value = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_paths(["."], Config(exclude=["vendor/*"], use_entropy=False))
    assert findings == []
