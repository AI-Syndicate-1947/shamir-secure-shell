import json
from pathlib import Path

import pytest

from shamir_ssh import consolidated_secret, operations


def test_consolidate_parse_roundtrip(tmp_path: Path):
    key_path = tmp_path / "key"
    key_path.write_bytes(b"payload-for-consolidated-test-xxx")
    lines = operations.split_private_key_file(key_path, threshold=2, num_shares=3)
    objs = [json.loads(line) for line in lines]
    blob = consolidated_secret.consolidate_share_dicts(objs)
    data = json.loads(blob)
    assert data["k"] == 2
    assert data["n"] == 3
    assert len(data["shares"]) == 3
    assert data["shares"][0]["x"] == 1
    restored = consolidated_secret.parse_consolidated_secret_string(blob)
    assert len(restored) == 3
    pem = operations.combine_share_objects(restored[:2])
    assert pem == key_path.read_bytes()


def test_consolidate_wrong_count(tmp_path: Path):
    key_path = tmp_path / "k"
    key_path.write_bytes(b"x" * 32)
    lines = operations.split_private_key_file(key_path, 2, 3)
    objs = [json.loads(lines[0])]
    with pytest.raises(ValueError, match="expected 3 shares"):
        consolidated_secret.consolidate_share_dicts(objs)


def test_consolidate_duplicate_x(tmp_path: Path):
    key_path = tmp_path / "k"
    key_path.write_bytes(b"x" * 32)
    lines = operations.split_private_key_file(key_path, 2, 3)
    o = json.loads(lines[0])
    with pytest.raises(ValueError, match="duplicate"):
        consolidated_secret.consolidate_share_dicts([o, o, o])


def test_parse_bad_version():
    with pytest.raises(ValueError, match="consolidated_version"):
        consolidated_secret.parse_consolidated_secret_string("{}")
