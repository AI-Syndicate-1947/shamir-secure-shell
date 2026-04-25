"""JSON share format: one self-contained object per share (Shamir point + ciphertext)."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

SCHEME_ID = "shamir_ssh_envelope_v1"


def fingerprint_pem(pem_bytes: bytes) -> str:
    return hashlib.sha256(pem_bytes).hexdigest()


def build_share(
    *,
    k: int,
    n: int,
    x: int,
    y: int,
    nonce_b64: str,
    ciphertext_b64: str,
    fp: str,
) -> dict[str, Any]:
    return {
        "scheme": SCHEME_ID,
        "k": k,
        "n": n,
        "x": x,
        "y": format(y, "x"),
        "nonce_b64": nonce_b64,
        "ciphertext_b64": ciphertext_b64,
        "fingerprint_sha256": fp,
    }


def share_to_json(share: dict[str, Any]) -> str:
    return json.dumps(share, separators=(",", ":"), sort_keys=True)


def validate_share_dict(obj: dict[str, Any]) -> dict[str, Any]:
    if obj.get("scheme") != SCHEME_ID:
        raise ValueError("unknown or missing scheme")
    for key in ("k", "n", "x", "y", "nonce_b64", "ciphertext_b64", "fingerprint_sha256"):
        if key not in obj:
            raise ValueError(f"missing field: {key}")
    return obj


def parse_share_json_line(line: str) -> dict[str, Any]:
    line = line.strip()
    if not line:
        raise ValueError("empty share line")
    return validate_share_dict(json.loads(line))


def share_tuple_from_obj(obj: dict[str, Any]) -> tuple[int, int]:
    x = int(obj["x"])
    y = int(obj["y"], 16)
    return x, y


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)
