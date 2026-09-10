# =============================================================================
# QoE scoring engine
# Issue #12 (S2-T2) — Sentinel-DNS Track4
#
# Computes per-site, per-minute QoE scores from raw DNS event aggregates.
# All normalization parameters are loaded from config/qoe.yaml at startup.
#
# Formulas (per ADR-0006 and P2b decision):
#   latency    = 100 - p95(latency_ms) * 100 / max_latency_ms
#   nxdomain   = 100 * (1 - min(nx_rate, 0.5) / 0.5)
#   saturation = 100 * (1 - min(qps / (2 * baseline_qps), 1))
#   score      = W_lat * latency + W_nx * nxdomain + W_sat * saturation
# =============================================================================

"""QoE scoring engine for Sentinel-DNS."""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .config import QoEConfig, load_config

logger = logging.getLogger(__name__)


@dataclass
class MinuteAggregates:
    """Pre-aggregated metrics for a single site in a one-minute window.

    These are the inputs to the QoE engine. The caller (agent/Kafka consumer)
    is responsible for computing these from raw dns_events_raw rows.
    """

    site: str  # "{zone_id}-{pop_id}"
    ts: str  # ISO timestamp (minute-truncated)
    query_count: int
    distinct_clients: int
    p95_latency_ms: float
    nxdomain_rate: float  # 0.0–1.0
    qps: float  # queries per second


@dataclass
class QoEScore:
    """Output of the QoE engine for one site in one minute."""

    site: str
    ts: str
    score: int  # 0–100
    label: str  # Excellent | Good | Fair | Poor
    latency_component: int  # 0–100
    nxdomain_component: int  # 0–100
    saturation_component: int  # 0–100
    # Culprit breakdown: how many weighted points each component contributes
    # (lower = worse, the "culprit" is the component with the largest gap)
    latency_points: float  # weighted contribution to final score
    nxdomain_points: float
    saturation_points: float
    qps: float
    query_count: int
    distinct_clients: int
    nxdomain_rate: float
    p95_latency_ms: float
    baseline_qps: float


@dataclass(frozen=True)
class ZoneBaseline:
    """Baseline anchors for a specific zone+pop site, from zone_mapping.csv."""

    zone_id: str
    zone_name: str
    pop_id: str
    pop_name: str
    baseline_qps: float
    baseline_p95_latency_ms: float


def load_zone_mapping(
    csv_path: str | Path | None = None,
) -> Dict[str, ZoneBaseline]:
    """Load zone_mapping.csv into a dict keyed by site ("{zone_id}-{pop_id}").

    Args:
        csv_path: Path to zone_mapping.csv. If None, uses
                  deploy/clickhouse/zone_mapping.csv relative to project root.

    Returns:
        Dict mapping site string → ZoneBaseline.
    """
    if csv_path is None:
        project_root = Path(__file__).resolve().parent.parent.parent
        csv_path = project_root / "deploy" / "clickhouse" / "zone_mapping.csv"
    else:
        csv_path = Path(csv_path)

    baselines: Dict[str, ZoneBaseline] = {}

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            zone_id = row["zone_id"].strip()
            pop_id = row["pop_id"].strip()
            site = f"{zone_id}-{pop_id}"

            baselines[site] = ZoneBaseline(
                zone_id=zone_id,
                zone_name=row["zone_name"].strip(),
                pop_id=pop_id,
                pop_name=row["pop_name"].strip(),
                baseline_qps=float(row["baseline_qps"]),
                baseline_p95_latency_ms=float(row["baseline_p95_latency_ms"]),
            )

    return baselines


def _normalize_latency(p95_ms: float, max_latency_ms: float) -> int:
    """Normalize p95 latency to 0–100, higher = better.

    Formula: 100 - p95_ms * 100 / max_latency_ms
    Clamped to [0, 100].
    """
    raw = 100.0 - (p95_ms * 100.0 / max_latency_ms)
    return max(0, min(100, int(round(raw))))


def _normalize_nxdomain(nx_rate: float, clamp_rate: float) -> int:
    """Normalize NXDOMAIN rate to 0–100, higher = better.

    Formula: 100 * (1 - min(nx_rate, clamp_rate) / clamp_rate)
    Clamped to [0, 100].
    """
    clamped = min(nx_rate, clamp_rate)
    raw = 100.0 * (1.0 - clamped / clamp_rate)
    return max(0, min(100, int(round(raw))))


def _normalize_saturation(qps: float, baseline_qps: float, overflow_multiplier: float) -> int:
    """Normalize saturation to 0–100, higher = better.

    Formula: 100 * (1 - min(qps / (overflow_multiplier * baseline_qps), 1))
    Clamped to [0, 100].
    """
    if baseline_qps <= 0:
        return 0
    threshold = overflow_multiplier * baseline_qps
    raw = 100.0 * (1.0 - min(qps / threshold, 1.0))
    return max(0, min(100, int(round(raw))))


def _label_from_score(score: int, labels: list) -> str:
    """Derive human label from score using configured thresholds."""
    for lbl in labels:
        if score >= lbl.min_score:
            return lbl.name
    return "Poor"


def compute_qoe(
    aggregates: MinuteAggregates,
    config: QoEConfig,
    baselines: Optional[Dict[str, ZoneBaseline]] = None,
) -> QoEScore:
    """Compute QoE score for one site in one minute.

    Args:
        aggregates: Pre-aggregated metrics for this site/minute.
        config: QoE configuration (weights, normalization, labels).
        baselines: Zone baseline map from zone_mapping.csv. If None or site
                   not found, uses config defaults.

    Returns:
        QoEScore with all components, label, and culprit breakdown.
    """
    # Resolve baselines
    baseline_qps = config.defaults.get("baseline_qps", 10.0)
    if baselines and aggregates.site in baselines:
        zb = baselines[aggregates.site]
        baseline_qps = zb.baseline_qps

    # Normalize each component to 0–100
    lat_comp = _normalize_latency(
        aggregates.p95_latency_ms,
        config.normalization.max_latency_ms,
    )
    nx_comp = _normalize_nxdomain(
        aggregates.nxdomain_rate,
        config.normalization.clamp_rate,
    )
    sat_comp = _normalize_saturation(
        aggregates.qps,
        baseline_qps,
        config.normalization.overflow_multiplier,
    )

    # Weighted sum
    w_lat = config.weights["latency"]
    w_nx = config.weights["nxdomain"]
    w_sat = config.weights["saturation"]

    lat_pts = lat_comp * w_lat
    nx_pts = nx_comp * w_nx
    sat_pts = sat_comp * w_sat

    score = int(round(lat_pts + nx_pts + sat_pts))
    score = max(0, min(100, score))

    label = _label_from_score(score, config.labels)

    return QoEScore(
        site=aggregates.site,
        ts=aggregates.ts,
        score=score,
        label=label,
        latency_component=lat_comp,
        nxdomain_component=nx_comp,
        saturation_component=sat_comp,
        latency_points=round(lat_pts, 4),
        nxdomain_points=round(nx_pts, 4),
        saturation_points=round(sat_pts, 4),
        qps=aggregates.qps,
        query_count=aggregates.query_count,
        distinct_clients=aggregates.distinct_clients,
        nxdomain_rate=aggregates.nxdomain_rate,
        p95_latency_ms=aggregates.p95_latency_ms,
        baseline_qps=baseline_qps,
    )
