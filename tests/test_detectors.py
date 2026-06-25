from sift.detectors import DETECTORS


def _names(line: str) -> list[str]:
    return [det.name for det in DETECTORS for _ in det.scan(line)]


def test_aws_access_key():
    # AWS's own documented example key id.
    assert "AWS Access Key ID" in _names('value = "AKIAIOSFODNN7EXAMPLE"')


def test_github_token():
    fake = "ghp_" + "0123456789abcdefABCDEF0123456789abcd"  # 36 chars after prefix
    assert "GitHub Token" in _names(f"token={fake}")


def test_private_key_block():
    assert "Private Key Block" in _names("-----BEGIN RSA PRIVATE KEY-----")


def test_jwt():
    fake = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysignature123"
    assert "JSON Web Token" in _names(fake)


def test_generic_assignment():
    assert "Generic Assigned Secret" in _names('password = "S3cr3tValue"')


def test_no_false_positive_on_plain_code():
    assert _names("total = compute(items) + 42  # running sum") == []
