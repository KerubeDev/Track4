"""Attack script (P4, issue #6): five escalating episodes with ground truth.

Episodes are generated inside the replayed logical window and interleaved with
the real-dataset background stream. Every injected query carries ``ground_truth``
in the emulator event schema; the field exists only inside the emulator output.
"""

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from math import log2

from app.emulator.events import TelemetryEvent
from app.emulator.mapping import ZoneMapping
from app.emulator.synthesizer import DnstapSynthesizer

# ---------------------------------------------------------------------------
# Episode targets (P4 / issue #6 acceptance criteria)
# ---------------------------------------------------------------------------

DGA_TARGET = 2000
DGA_IP_MIN = 5
DGA_IP_MAX = 8
TYPOSQUAT_TARGET = 300
TUNNEL_TARGET = 1000
BEACON_QUERIES = 15
BEACON_INTERVAL_S = 20
BEACON_INTERVALS = 4

_EPISODE_IDS = ("E1", "E2", "E3", "E4", "E5")

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------

# Top e2ld repeaters measured from the real dataset (docs/design.md) plus the
# fictional corporate domains — this IS the client's normal vocabulary.
CLIENT_VOCABULARY = (
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

# DGA-style label fragments (public DGA wordlists/mutations, cited in the
# README pre-existing-bases declaration, Art. 11c).
DGA_WORDS = (
    "bankguai", "zarvexil", "quondom", "helxibo", "dryftan", "muzydra",
    "cryptolocker", "tempvortex", "shadyrat", "nitrozen", "pykspa", "suppobox",
    "bdigna", "qovblox", "fexynda", "wuqzira", "joltcrate", "mireifold",
)

DGA_TLDS = ("com", "net", "xyz", "top", "info", "club", "online")

_TUNNEL_LABEL_LEN = 48
_TUNNEL_DOMAIN = "tunnel-exfil.net"


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * log2(c / total) for c in counts.values())


def edit_distance_at_most_one(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by at most one edit (sub/ins/del)."""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        return sum(1 for x, y in zip(a, b) if x != y) <= 1
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    # now la == lb - 1: b is a with exactly one insertion
    i = 0
    while i < la and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


# ---------------------------------------------------------------------------
# Episode declarations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Episode:
    episode: str
    attack: str
    target_queries: int


ATTACK_EPISODES = (
    Episode("E1", "dga", DGA_TARGET),
    Episode("E2", "typosquat", TYPOSQUAT_TARGET),
    Episode("E3", "tunnel", TUNNEL_TARGET),
    Episode("E4", "beaconing", BEACON_QUERIES * BEACON_INTERVALS),
    Episode("E5", "beaconing", BEACON_QUERIES * BEACON_INTERVALS),
)


def _label(episode: Episode, extra=None):
    info = {"attack": episode.attack, "episode": episode.episode}
    if extra:
        info.update(extra)
    return info


def _attack_client_ips(rng: random.Random, count: int) -> list:
    """Deterministic attacker IPs inside a mapped consumer range (190.14.200.0/22)."""
    return [f"190.14.{200 + (i // 250)}.{1 + (i % 250)}" for i in range(count)]


def _spread(rng: random.Random, window, count: int) -> list:
    """Sorted random timestamps inside the half-open logical window."""
    start, end = window
    span = (end - start).total_seconds()
    if span <= 0:
        span = 1.0
    lo = 0.01
    hi = max(lo, span - 0.01)
    stamps = [start + timedelta(seconds=rng.uniform(lo, hi)) for _ in range(count)]
    stamps.sort()
    return stamps


def _beacon_interval_s(window) -> float:
    """Period between burst starts; compresses for small windows so 4 fit inside."""
    span = (window[1] - window[0]).total_seconds()
    return max(1.0, min(BEACON_INTERVAL_S, span / (BEACON_INTERVALS + 1)))


def _episode_events(
    synthesizer: DnstapSynthesizer,
    episode: Episode,
    stamps: list,
    qnames: list,
    client_ips: list,
    qtype: str = "A",
    rcode: str = "NOERROR",
):
    mapping = ZoneMapping.from_csv()
    for stamp, qname, client_ip in zip(stamps, qnames, client_ips):
        profile = mapping.resolve(client_ip)
        yield synthesizer.synthesize_attack(
            timestamp=stamp,
            client_ip=client_ip,
            qname=qname,
            profile=profile,
            qtype=qtype,
            rcode=rcode,
            ground_truth=_label(episode),
        )


# ---------------------------------------------------------------------------
# Episode generators
# ---------------------------------------------------------------------------


def episode_e1_dga(synthesizer, mapping, window, rng):
    """E1 — DGA: ~2000 pseudo-random domains across 5-8 client IPs."""
    count = DGA_TARGET
    ip_count = rng.randint(DGA_IP_MIN, DGA_IP_MAX)
    ips = _attack_client_ips(rng, ip_count)
    stamps = _spread(rng, window, count)

    qnames = []
    for _ in range(count):
        word = rng.choice(DGA_WORDS)
        tail = format(rng.getrandbits(32), "x")
        label = f"{word}{tail}"[:63]
        qnames.append(f"{label}.{rng.choice(DGA_TLDS)}")
    owners = [rng.choice(ips) for _ in range(count)]

    yield from _episode_events(
        synthesizer, ATTACK_EPISODES[0], stamps, qnames, owners, rcode="NXDOMAIN"
    )


def episode_e2_typosquat(synthesizer, mapping, window, rng):
    """E2 — typosquat: ~300 edit-distance mutations of client-vocabulary domains."""
    count = TYPOSQUAT_TARGET
    stamps = _spread(rng, window, count)

    qnames = [_mutate(rng.choice(CLIENT_VOCABULARY), rng) for _ in range(count)]
    ips = _attack_client_ips(rng, 3)
    owners = [rng.choice(ips) for _ in range(count)]

    yield from _episode_events(synthesizer, ATTACK_EPISODES[1], stamps, qnames, owners)


def _mutate(domain: str, rng: random.Random) -> str:
    """One edit-distance-1 mutation of a vocabulary e2ld (never the original)."""
    label, _, tld = domain.partition(".")
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-"
    position = rng.randrange(len(label))
    kind = rng.random()
    if kind < 0.4:  # substitution
        candidate = label[:position] + rng.choice(alphabet) + label[position + 1:]
    elif kind < 0.7:  # insertion
        candidate = label[:position] + rng.choice(alphabet) + label[position:]
    else:  # deletion
        candidate = label[:position] + label[position + 1:]
    if candidate == label or not candidate:
        # guarantee a change: swap the picked character deterministically
        replacement = "0" if label[position] != "0" else "1"
        candidate = label[:position] + replacement + label[position + 1:]
    if candidate == label:
        candidate = label + "0"
    assert edit_distance_at_most_one(label, candidate)
    return f"{candidate}.{tld}" if tld else candidate


def episode_e3_tunnel(synthesizer, mapping, window, rng):
    """E3 — DNS tunnel: ~1000 queries from one IP with long high-entropy labels."""
    count = TUNNEL_TARGET
    stamps = _spread(rng, window, count)

    qnames = [
        "{}.{}".format(
            "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(_TUNNEL_LABEL_LEN)),
            _TUNNEL_DOMAIN,
        )
        for _ in range(count)
    ]
    tunnel_ip = _attack_client_ips(rng, 1)[0]
    owners = [tunnel_ip] * count

    yield from _episode_events(
        synthesizer, ATTACK_EPISODES[2], stamps, qnames, owners, qtype="TXT"
    )


def _beacon_events(synthesizer, mapping, episode, window, rng, qname):
    """One periodic beacon: BEACON_INTERVALS short bursts of BEACON_QUERIES each."""
    start, end = window
    interval = _beacon_interval_s(window)
    burst_span = min(BEACON_QUERIES * 0.2, interval * 0.5)
    beacon_ip = _attack_client_ips(rng, 1)[0]
    profile = mapping.resolve(beacon_ip)
    gt = _label(episode, {"qname": qname, "interval_s": round(interval, 3)})

    for interval_index in range(BEACON_INTERVALS):
        burst_start = start + timedelta(seconds=interval_index * interval)
        if burst_start >= end:
            break
        stamps = sorted(
            burst_start + timedelta(seconds=rng.uniform(0, burst_span))
            for _ in range(BEACON_QUERIES)
        )
        for stamp in stamps:
            stamp = min(stamp, end - timedelta(milliseconds=10))
            yield synthesizer.synthesize_attack(
                timestamp=stamp,
                client_ip=beacon_ip,
                qname=qname,
                profile=profile,
                qtype="A",
                rcode="NOERROR",
                ground_truth=gt,
            )


def episode_e4_beaconing(synthesizer, mapping, window, rng):
    """E4 — beaconing: 1 domain x 4 short periodic intervals."""
    yield from _beacon_events(
        synthesizer, mapping, ATTACK_EPISODES[3], window, rng, "cdn-metrics-update.example"
    )


def episode_e5_beaconing(synthesizer, mapping, window, rng):
    """E5 — beaconing: second beaconing family, distinct domain."""
    yield from _beacon_events(
        synthesizer, mapping, ATTACK_EPISODES[4], window, rng, "sync-heartbeat.example"
    )


# ---------------------------------------------------------------------------
# Whole-script stream
# ---------------------------------------------------------------------------


def build_attack_stream(synthesizer, mapping, window, rng: random.Random):
    """All five episodes merged in logical timestamp order.

    A per-episode child RNG keeps each episode's shape independent of ordering.
    """
    from operator import attrgetter

    from app.emulator.replay import heap_merge

    streams = [
        episode_e1_dga(synthesizer, mapping, window, random.Random(rng.getrandbits(32))),
        episode_e2_typosquat(synthesizer, mapping, window, random.Random(rng.getrandbits(32))),
        episode_e3_tunnel(synthesizer, mapping, window, random.Random(rng.getrandbits(32))),
        episode_e4_beaconing(synthesizer, mapping, window, random.Random(rng.getrandbits(32))),
        episode_e5_beaconing(synthesizer, mapping, window, random.Random(rng.getrandbits(32))),
    ]
    yield from heap_merge(streams, key=attrgetter("timestamp"))
