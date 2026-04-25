"""Shamir secret sharing over integers mod p (Mersenne prime M521 > 256-bit secrets)."""

from __future__ import annotations

import secrets
from typing import Iterable

# 13th Mersenne prime; large enough for 32-byte AES keys as integers.
_PRIME = 2**521 - 1


def _eval_at(poly: list[int], x: int, prime: int) -> int:
    accum = 0
    for coeff in reversed(poly):
        accum = (accum * x + coeff) % prime
    return accum


def _extended_gcd(a: int, b: int) -> tuple[int, int]:
    x, last_x = 0, 1
    y, last_y = 1, 0
    while b:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y


def _divmod_mod(num: int, den: int, p: int) -> int:
    inv, _ = _extended_gcd(den % p, p)
    return (num * inv) % p


def _lagrange_interpolate(x: int, xs: list[int], ys: list[int], p: int) -> int:
    k = len(xs)
    if len(set(xs)) != k:
        raise ValueError("duplicate x in shares")

    def prod(vals: Iterable[int]) -> int:
        a = 1
        for v in vals:
            a = (a * v) % p
        return a

    nums: list[int] = []
    dens: list[int] = []
    for i in range(k):
        others = [xs[j] for j in range(k) if j != i]
        nums.append(prod(x - o for o in others))
        dens.append(prod(xs[i] - o for o in others))
    den = prod(dens)
    num = sum(
        _divmod_mod(nums[i] * den * ys[i] % p, dens[i], p) for i in range(k)
    )
    return (_divmod_mod(num, den, p) + p) % p


def split_secret_int(secret: int, threshold: int, num_shares: int, prime: int = _PRIME) -> list[tuple[int, int]]:
    if threshold < 2:
        raise ValueError("threshold must be at least 2")
    if num_shares < threshold:
        raise ValueError("num_shares must be >= threshold")
    if not 0 <= secret < prime:
        raise ValueError("secret out of range for field prime")
    rng = secrets.SystemRandom()
    poly = [secret] + [rng.randrange(prime) for _ in range(threshold - 1)]
    return [(i, _eval_at(poly, i, prime)) for i in range(1, num_shares + 1)]


def recover_secret_int(shares: list[tuple[int, int]], prime: int = _PRIME) -> int:
    if len(shares) < 2:
        raise ValueError("need at least 2 shares")
    xs = [x for x, _ in shares]
    ys = [y for _, y in shares]
    return _lagrange_interpolate(0, xs, ys, prime)
