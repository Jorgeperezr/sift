from sift.baseline import filter_findings, load_baseline, write_baseline
from sift.findings import Finding


def test_baseline_roundtrip(tmp_path):
    f = Finding("a.py", 1, 5, "AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE")
    out = tmp_path / "baseline.json"
    write_baseline([f], str(out))

    assert f.fingerprint in load_baseline(str(out))
    # The plaintext secret must never end up in the committed baseline.
    assert "AKIAIOSFODNN7EXAMPLE" not in out.read_text()


def test_filter_removes_known():
    f1 = Finding("a.py", 1, 5, "X", "secret-one")
    f2 = Finding("b.py", 2, 3, "Y", "secret-two")
    assert filter_findings([f1, f2], {f1.fingerprint}) == [f2]


def test_missing_baseline_is_empty():
    assert load_baseline("does-not-exist.json") == set()
