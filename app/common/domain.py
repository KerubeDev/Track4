"""Shared DNS-domain primitives used by production and simulation code."""

from __future__ import annotations

DEFAULT_CLIENT_VOCABULARY = (
    "microsoft.com",
    "google.com",
    "googleapis.com",
    "apple.com",
    "spotify.com",
    "shodan.io",
    "banco-pa.example",
    "banco-col.example",
    "gob-pa.example",
    "hosp-pa.example",
)


def edit_distance_at_most_one(a: str, b: str) -> bool:
    """Return True when two strings differ by at most one edit."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(x != y for x, y in zip(a, b)) <= 1
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    i = 0
    while i < la and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def effective_tld_plus_one(qname: str) -> str:
    """Best-effort eTLD+1 for the controlled telemetry vocabulary.

    The product deliberately avoids a network-backed public-suffix lookup in
    the hot path. Production deployments that need full PSL semantics can
    replace this helper behind the same interface.
    """
    labels = [label for label in qname.rstrip(".").lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) >= 2 else (labels[0] if labels else "")
