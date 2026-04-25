import json
from pathlib import Path

import pytest

from shamir_ssh import operations, shamir_prime


def test_shamir_prime_roundtrip_int():
    secret = (2**255) - 12345
    pts = shamir_prime.split_secret_int(secret, 3, 5)
    assert len(pts) == 5
    got = shamir_prime.recover_secret_int(pts[:3])
    assert got == secret
    got2 = shamir_prime.recover_secret_int([pts[0], pts[2], pts[4]])
    assert got2 == secret


def test_envelope_split_combine_roundtrip(tmp_path: Path):
    key_path = tmp_path / "id_ed25519"
    pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfakebutlongenough\n-----END OPENSSH PRIVATE KEY-----\n"
    key_path.write_bytes(pem)
    lines = operations.split_private_key_file(key_path, threshold=3, num_shares=5)
    assert len(lines) == 5
    objs = [json.loads(line) for line in lines]
    out = operations.combine_share_objects(objs[:3])
    assert out == pem


def test_combine_requires_k_shares(tmp_path: Path):
    key_path = tmp_path / "k"
    key_path.write_bytes(b"secret-bytes-for-test-xxxxxxxxxxxx")
    lines = operations.split_private_key_file(key_path, threshold=3, num_shares=5)
    objs = [json.loads(line) for line in lines[:2]]
    with pytest.raises(ValueError, match="at least 3"):
        operations.combine_share_objects(objs)


def test_mismatched_shares_rejected(tmp_path: Path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.write_bytes(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    b.write_bytes(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    la = [json.loads(x) for x in operations.split_private_key_file(a, 2, 3)]
    lb = [json.loads(x) for x in operations.split_private_key_file(b, 2, 3)]
    with pytest.raises(ValueError, match="metadata mismatch"):
        operations.combine_share_objects([la[0], lb[0]])
