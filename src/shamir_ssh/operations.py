"""High-level split and combine for private key files."""

from __future__ import annotations

import glob
import os
from pathlib import Path

from shamir_ssh import crypto_envelope
from shamir_ssh import share_format
from shamir_ssh import shamir_prime


def resolve_share_path_args(patterns: list[str]) -> list[Path]:
    """
    Expand shell-style globs (*, ?, []) in each pattern; treat patterns without
    glob metacharacters as a single literal path. Deduplicate by resolved path.

    On Windows, patterns such as ``.\\shares\\share_*.json`` may not match if
    passed with backslashes; we normalize the path and retry with forward
    slashes when the first glob attempt finds nothing.
    """
    out: list[Path] = []
    seen: set[str] = set()
    for pat in patterns:
        expanded = os.path.expanduser(pat)
        expanded = os.path.normpath(expanded)
        if any(c in expanded for c in "*?["):
            matches = sorted(glob.glob(expanded))
            if not matches and "\\" in expanded:
                matches = sorted(glob.glob(expanded.replace("\\", "/")))
            if not matches:
                raise ValueError(f"no files match glob {pat!r}")
            candidates = [Path(m) for m in matches]
        else:
            p = Path(os.path.expanduser(pat))
            p = Path(os.path.normpath(p))
            if not p.is_file():
                raise ValueError(f"not a file: {pat}")
            candidates = [p]
        for p in candidates:
            if not p.is_file():
                continue
            key = os.path.normcase(os.path.normpath(str(p.resolve())))
            if key not in seen:
                seen.add(key)
                out.append(p)
    if not out:
        raise ValueError("no share files found")
    return out


def split_private_key_file(
    pem_path: Path,
    threshold: int,
    num_shares: int,
) -> list[str]:
    pem_bytes = pem_path.read_bytes()
    if not pem_bytes.strip():
        raise ValueError("private key file is empty")
    fp = share_format.fingerprint_pem(pem_bytes)
    key = crypto_envelope.generate_key()
    nonce, ciphertext = crypto_envelope.seal(pem_bytes, key)
    secret_int = int.from_bytes(key, "big")
    points = shamir_prime.split_secret_int(secret_int, threshold, num_shares)
    nonce_b64 = share_format.b64encode(nonce)
    ct_b64 = share_format.b64encode(ciphertext)
    lines: list[str] = []
    for x, y in points:
        share = share_format.build_share(
            k=threshold,
            n=num_shares,
            x=x,
            y=y,
            nonce_b64=nonce_b64,
            ciphertext_b64=ct_b64,
            fp=fp,
        )
        lines.append(share_format.share_to_json(share))
    return lines


def combine_share_objects(share_objs: list[dict]) -> bytes:
    if len(share_objs) < 2:
        raise ValueError("need at least 2 shares")
    validated = [share_format.validate_share_dict(dict(o)) for o in share_objs]
    first = validated[0]
    k = int(first["k"])
    n = int(first["n"])
    fp = str(first["fingerprint_sha256"])
    nonce_b64 = str(first["nonce_b64"])
    ct_b64 = str(first["ciphertext_b64"])
    if k < 2:
        raise ValueError("invalid threshold in share")
    if n < k:
        raise ValueError("invalid n in share")
    if len(validated) < k:
        raise ValueError(f"need at least {k} distinct shares (got {len(validated)})")
    for o in validated[1:]:
        if (
            int(o["k"]) != k
            or int(o["n"]) != n
            or str(o["fingerprint_sha256"]) != fp
            or str(o["nonce_b64"]) != nonce_b64
            or str(o["ciphertext_b64"]) != ct_b64
        ):
            raise ValueError("shares do not belong to the same split (metadata mismatch)")
    tuples: list[tuple[int, int]] = []
    seen_x: set[int] = set()
    for o in validated:
        xt = share_format.share_tuple_from_obj(o)
        if xt[0] in seen_x:
            raise ValueError(f"duplicate share index x={xt[0]}")
        seen_x.add(xt[0])
        tuples.append(xt)
    if len(tuples) < k:
        raise ValueError(f"need at least {k} distinct shares")
    subset = tuples[:k]
    recovered = shamir_prime.recover_secret_int(subset)
    if recovered >= 2**256:
        raise ValueError("recovered key integer out of expected range")
    key_bytes = recovered.to_bytes(32, "big")
    nonce = share_format.b64decode(nonce_b64)
    ciphertext = share_format.b64decode(ct_b64)
    pem = crypto_envelope.open_envelope(nonce, ciphertext, key_bytes)
    if share_format.fingerprint_pem(pem) != fp:
        raise ValueError("recovered key fingerprint mismatch")
    return pem


def load_shares_from_paths(paths: list[Path]) -> list[dict]:
    out: list[dict] = []
    for p in paths:
        text = p.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            out.append(share_format.parse_share_json_line(line))
    return out


def combine_from_paths(paths: list[Path]) -> bytes:
    objs = load_shares_from_paths(paths)
    return combine_share_objects(objs)


def combine_from_consolidated_secret_string(secret_string: str) -> bytes:
    from shamir_ssh.consolidated_secret import parse_consolidated_secret_string

    objs = parse_consolidated_secret_string(secret_string)
    return combine_share_objects(objs)
