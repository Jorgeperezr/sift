from sift.entropy import iter_high_entropy, shannon_entropy


def test_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9  # 4 equally likely symbols


def test_flags_random_base64():
    line = 'token = "x7Qd9Pl2aFv8Kc3Nz1Rw6Tb4Yh0Mj5sUe2Gpd"'
    tokens = [t for t, _ in iter_high_entropy(line)]
    assert tokens


def test_ignores_prose():
    assert list(iter_high_entropy("the quick brown fox jumps over the lazy dog")) == []
