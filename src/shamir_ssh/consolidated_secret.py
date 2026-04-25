"""Single JSON blob for all shares (AWS Secrets Manager and similar)."""

from __future__ import annotations

import json
import re
from typing import Any

from shamir_ssh.share_format import SCHEME_ID, validate_share_dict

# Top-level JSON stored in Secrets Manager (same scheme id as per-share envelope).
_CONSOLIDATED_VERSION = 1


def _hex_y(s: str) -> str:
    if not isinstance(s, str) or not s:
        raise ValueError("each share y must be a non-empty hex string")
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        raise ValueError("each share y must be hexadecimal")
    return s.lower()


def consolidate_share_dicts(share_objs: list[dict]) -> str:
    """Validate a full set of per-share dicts and return compact JSON for one secret value."""
    if not share_objs:
        raise ValueError("no shares to consolidate")
    validated = [validate_share_dict(dict(o)) for o in share_objs]
    first = validated[0]
    k = int(first["k"])
    n = int(first["n"])
    fp = str(first["fingerprint_sha256"])
    nonce_b64 = str(first["nonce_b64"])
    ct_b64 = str(first["ciphertext_b64"])
    if k < 2 or n < k:
        raise ValueError("invalid k or n in shares")
    if len(validated) != n:
        raise ValueError(f"expected {n} shares, got {len(validated)}")
    seen_x: set[int] = set()
    share_points: list[dict[str, Any]] = []
    for o in validated:
        if (
            int(o["k"]) != k
            or int(o["n"]) != n
            or str(o["fingerprint_sha256"]) != fp
            or str(o["nonce_b64"]) != nonce_b64
            or str(o["ciphertext_b64"]) != ct_b64
        ):
            raise ValueError("shares do not belong to the same split (metadata mismatch)")
        x = int(o["x"])
        if x in seen_x:
            raise ValueError(f"duplicate share index x={x}")
        seen_x.add(x)
        y_str = _hex_y(str(o["y"]))
        share_points.append({"x": x, "y": y_str})
    share_points.sort(key=lambda p: p["x"])
    blob = {
        "consolidated_version": _CONSOLIDATED_VERSION,
        "scheme": SCHEME_ID,
        "k": k,
        "n": n,
        "nonce_b64": nonce_b64,
        "ciphertext_b64": ct_b64,
        "fingerprint_sha256": fp,
        "shares": share_points,
    }
    return json.dumps(blob, separators=(",", ":"), sort_keys=True)


def parse_consolidated_secret_string(secret_string: str) -> list[dict[str, Any]]:
    """Parse secret string JSON into full per-share dicts for combine_share_objects."""
    try:
        obj = json.loads(secret_string)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON secret: {e}") from e
    if not isinstance(obj, dict):
        raise ValueError("secret value must be a JSON object")
    ver = obj.get("consolidated_version")
    if ver != _CONSOLIDATED_VERSION:
        raise ValueError("unknown or missing consolidated_version")
    if obj.get("scheme") != SCHEME_ID:
        raise ValueError("unknown or missing scheme")
    for key in ("k", "n", "nonce_b64", "ciphertext_b64", "fingerprint_sha256", "shares"):
        if key not in obj:
            raise ValueError(f"missing field: {key}")
    k = int(obj["k"])
    n = int(obj["n"])
    shares_raw = obj["shares"]
    if not isinstance(shares_raw, list):
        raise ValueError("shares must be an array")
    if len(shares_raw) != n:
        raise ValueError(f"expected shares array length {n}, got {len(shares_raw)}")
    fp = str(obj["fingerprint_sha256"])
    nonce_b64 = str(obj["nonce_b64"])
    ct_b64 = str(obj["ciphertext_b64"])
    full: list[dict[str, Any]] = []
    seen_x: set[int] = set()
    for item in shares_raw:
        if not isinstance(item, dict):
            raise ValueError("each share entry must be an object")
        if set(item.keys()) != {"x", "y"}:
            raise ValueError("each share entry must contain only x and y")
        x = int(item["x"])
        if x in seen_x:
            raise ValueError(f"duplicate share index x={x}")
        seen_x.add(x)
        y_str = _hex_y(str(item["y"]))
        full.append(
            {
                "scheme": SCHEME_ID,
                "k": k,
                "n": n,
                "x": x,
                "y": y_str,
                "nonce_b64": nonce_b64,
                "ciphertext_b64": ct_b64,
                "fingerprint_sha256": fp,
            }
        )
    full.sort(key=lambda d: int(d["x"]))
    return full
