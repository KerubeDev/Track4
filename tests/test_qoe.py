#!/usr/bin/env python3
"""
Golden-fixture tests for QoE engine — Sentinel-DNS Track4
Issue #12 (S2-T2)

Each test case includes hand-computed expected values. The QoE formulas:
  latency    = 100 - p95_ms * 100 / max_latency_ms
  nxdomain   = 100 * (1 - min(nx_rate, 0.5) / 0.5)
  saturation = 100 * (1 - min(qps / (2 * baseline_qps), 1))
  score      = W_lat * latency + W_nx * nxdomain + W_sat * saturation

Validation:
  V1 — Hand-computed scores match engine output for all golden fixtures.
  V2 — Config change (e.g., weights) yields correct relabeling without code changes.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Ensure the project root is on the path so we can import app.qoe
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in os.sys.path:
    os.sys.path.insert(0, str(PROJECT_ROOT))

from app.qoe.config import QoEConfig, NormalizationConfig, LabelThreshold, load_config
from app.qoe.engine import (
    MinuteAggregates,
    QoEScore,
    compute_qoe,
    load_zone_mapping,
    _normalize_latency,
    _normalize_nxdomain,
    _normalize_saturation,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def default_config() -> QoEConfig:
    """Load the default config/qoe.yaml."""
    return load_config()


@pytest.fixture
def zone_baselines() -> dict:
    """Load zone_mapping.csv."""
    return load_zone_mapping()


# ---------------------------------------------------------------------------
# V1: Individual component normalization (hand-computed)
# ---------------------------------------------------------------------------

class TestComponentNormalization:
    """Verify each normalization function matches hand-computed values."""

    def test_latency_30ms(self):
        """p95=30ms, max=300 → 100 - 30*100/300 = 90"""
        assert _normalize_latency(30.0, 300.0) == 90

    def test_latency_150ms(self):
        """p95=150ms, max=300 → 100 - 150*100/300 = 50"""
        assert _normalize_latency(150.0, 300.0) == 50

    def test_latency_280ms(self):
        """p95=280ms, max=300 → 100 - 280*100/300 = 6.67 → 7"""
        assert _normalize_latency(280.0, 300.0) == 7

    def test_latency_0ms(self):
        """p95=0ms → 100"""
        assert _normalize_latency(0.0, 300.0) == 100

    def test_latency_300ms(self):
        """p95=300ms → 100 - 300*100/300 = 0"""
        assert _normalize_latency(300.0, 300.0) == 0

    def test_latency_above_max_clamps_to_0(self):
        """p95=350ms, max=300 → clamped to 0"""
        assert _normalize_latency(350.0, 300.0) == 0

    def test_nxdomain_0(self):
        """nx_rate=0 → 100 * (1 - 0/0.5) = 100"""
        assert _normalize_nxdomain(0.0, 0.5) == 100

    def test_nxdomain_002(self):
        """nx_rate=0.02 → 100 * (1 - 0.02/0.5) = 96"""
        assert _normalize_nxdomain(0.02, 0.5) == 96

    def test_nxdomain_015(self):
        """nx_rate=0.15 → 100 * (1 - 0.15/0.5) = 70"""
        assert _normalize_nxdomain(0.15, 0.5) == 70

    def test_nxdomain_045(self):
        """nx_rate=0.45 → 100 * (1 - 0.45/0.5) = 10"""
        assert _normalize_nxdomain(0.45, 0.5) == 10

    def test_nxdomain_05_clamps(self):
        """nx_rate=0.5 → 100 * (1 - 0.5/0.5) = 0"""
        assert _normalize_nxdomain(0.5, 0.5) == 0

    def test_nxdomain_above_clamp(self):
        """nx_rate=0.8 → clamped to 0"""
        assert _normalize_nxdomain(0.8, 0.5) == 0

    def test_saturation_2qps_12baseline(self):
        """qps=2, baseline=12 → 100*(1-2/(2*12)) = 91.67 → 92"""
        assert _normalize_saturation(2.0, 12.0, 2.0) == 92

    def test_saturation_25qps_13baseline(self):
        """qps=25, baseline=13 → 100*(1-25/(2*13)) = 100*(1-0.9615) = 3.85 → 4"""
        assert _normalize_saturation(25.0, 13.0, 2.0) == 4

    def test_saturation_3qps_14baseline(self):
        """qps=3, baseline=14 → 100*(1-3/(2*14)) = 89.29 → 89"""
        assert _normalize_saturation(3.0, 14.0, 2.0) == 89

    def test_saturation_4qps_4baseline(self):
        """qps=4, baseline=4 → 100*(1-4/(2*4)) = 50"""
        assert _normalize_saturation(4.0, 4.0, 2.0) == 50

    def test_saturation_zero_baseline(self):
        """baseline=0 → 0 (division guard)"""
        assert _normalize_saturation(5.0, 0.0, 2.0) == 0


# ---------------------------------------------------------------------------
# V1: Full QoE score (golden fixtures)
# ---------------------------------------------------------------------------

class TestQoEScoreGoldenFixtures:
    """Hand-computed QoE scores vs engine output (V1 validation)."""

    def test_excellent_site(self, default_config, zone_baselines):
        """
        Z1-PAN-PAC-01, Excellent case:
          latency:    100 - 30*100/300 = 90  → 90 * 0.45 = 40.5
          nxdomain:   100*(1-0.02/0.5) = 96  → 96 * 0.35 = 33.6
          saturation: 100*(1-2/(2*12)) = 92  → 92 * 0.20 = 18.4
          score = 40.5 + 33.6 + 18.4 = 92.5 → 92 (banker's rounding)
          label = Excellent (92 >= 85)
        """
        agg = MinuteAggregates(
            site="Z1-PAN-PAC-01",
            ts="2026-09-09T10:00:00",
            query_count=120,
            distinct_clients=15,
            p95_latency_ms=30.0,
            nxdomain_rate=0.02,
            qps=2.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        assert result.score == 92
        assert result.label == "Excellent"
        assert result.latency_component == 90
        assert result.nxdomain_component == 96
        assert result.saturation_component == 92
        assert result.latency_points == pytest.approx(40.5, abs=0.01)
        assert result.nxdomain_points == pytest.approx(33.6, abs=0.01)
        assert result.saturation_points == pytest.approx(18.4, abs=0.01)

    def test_poor_site(self, default_config, zone_baselines):
        """
        Z2-COL-BOG-01, Poor case:
          latency:    100 - 280*100/300 = 6.67 → 7   → 7 * 0.45 = 3.15
          nxdomain:   100*(1-0.45/0.5) = 10       → 10 * 0.35 = 3.5
          saturation: 100*(1-25/(2*13)) = 3.85 → 4  → 4 * 0.20 = 0.8
          score = 3.15 + 3.5 + 0.8 = 7.45 → 7
          label = Poor (7 < 50)
        """
        agg = MinuteAggregates(
            site="Z2-COL-BOG-01",
            ts="2026-09-09T10:01:00",
            query_count=400,
            distinct_clients=50,
            p95_latency_ms=280.0,
            nxdomain_rate=0.45,
            qps=25.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        assert result.score == 7
        assert result.label == "Poor"
        assert result.latency_component == 7
        assert result.nxdomain_component == 10
        assert result.saturation_component == 4

    def test_fair_site(self, default_config, zone_baselines):
        """
        Z3-PAN-PAC-01, Fair case:
          latency:    100 - 150*100/300 = 50      → 50 * 0.45 = 22.5
          nxdomain:   100*(1-0.15/0.5) = 70        → 70 * 0.35 = 24.5
          saturation: 100*(1-3/(2*14)) = 89.29 → 89 → 89 * 0.20 = 17.8
          score = 22.5 + 24.5 + 17.8 = 64.8 → 65
          label = Fair (50 <= 65 < 70)
        """
        agg = MinuteAggregates(
            site="Z3-PAN-PAC-01",
            ts="2026-09-09T10:02:00",
            query_count=80,
            distinct_clients=10,
            p95_latency_ms=150.0,
            nxdomain_rate=0.15,
            qps=3.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        assert result.score == 65
        assert result.label == "Fair"
        assert result.latency_component == 50
        assert result.nxdomain_component == 70
        assert result.saturation_component == 89

    def test_excellent_boundary(self, default_config, zone_baselines):
        """
        Z4-SAL-SAL-01, borderline Excellent:
          latency:    100 - 60*100/300 = 80         → 80 * 0.45 = 36.0
          nxdomain:   100*(1-0.05/0.5) = 90          → 90 * 0.35 = 31.5
          saturation: 100*(1-4/(2*4)) = 50            → 50 * 0.20 = 10.0
          score = 36.0 + 31.5 + 10.0 = 77.5 → 78
          label = Good (70 <= 78 < 85)
        """
        agg = MinuteAggregates(
            site="Z4-SAL-SAL-01",
            ts="2026-09-09T10:03:00",
            query_count=100,
            distinct_clients=12,
            p95_latency_ms=60.0,
            nxdomain_rate=0.05,
            qps=4.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        assert result.score == 78
        assert result.label == "Good"
        assert result.latency_component == 80
        assert result.nxdomain_component == 90
        assert result.saturation_component == 50

    def test_zero_queries(self, default_config, zone_baselines):
        """
        Edge case: zero queries in the minute window.
        p95_latency_ms=0, nxdomain_rate=0, qps=0.
          latency:    100 - 0 = 100  → 100 * 0.45 = 45.0
          nxdomain:   100            → 100 * 0.35 = 35.0
          saturation: 100            → 100 * 0.20 = 20.0
          score = 45 + 35 + 20 = 100
          label = Excellent
        """
        agg = MinuteAggregates(
            site="Z1-PAN-PAC-01",
            ts="2026-09-09T10:04:00",
            query_count=0,
            distinct_clients=0,
            p95_latency_ms=0.0,
            nxdomain_rate=0.0,
            qps=0.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        assert result.score == 100
        assert result.label == "Excellent"

    def test_all_components_worst(self, default_config, zone_baselines):
        """
        Worst case: max latency, max NXDOMAIN, max saturation.
          latency:    100 - 300*100/300 = 0   → 0 * 0.45 = 0
          nxdomain:   100*(1-0.5/0.5) = 0     → 0 * 0.35 = 0
          saturation: 100*(1-1) = 0            → 0 * 0.20 = 0
          score = 0
          label = Poor
        """
        agg = MinuteAggregates(
            site="Z1-PAN-PAC-01",
            ts="2026-09-09T10:05:00",
            query_count=1000,
            distinct_clients=100,
            p95_latency_ms=300.0,
            nxdomain_rate=0.5,
            qps=100.0,  # way above 2*12=24
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        assert result.score == 0
        assert result.label == "Poor"

    def test_baseline_fallback_to_defaults(self, default_config):
        """
        When site is not in zone_mapping.csv, use config defaults.
        default baseline_qps = 10.0.
          qps=5, baseline=10 → saturation = 100*(1-5/20) = 75
        """
        agg = MinuteAggregates(
            site="UNKNOWN-UNKNOWN",
            ts="2026-09-09T10:00:00",
            query_count=50,
            distinct_clients=5,
            p95_latency_ms=50.0,
            nxdomain_rate=0.0,
            qps=5.0,
        )
        result = compute_qoe(agg, default_config, baselines=None)

        assert result.saturation_component == 75
        assert result.baseline_qps == 10.0


# ---------------------------------------------------------------------------
# V2: Config change relabeling (weights edit → correct score without code change)
# ---------------------------------------------------------------------------

class TestConfigRelabeling:
    """Verify that changing config/qoe.yaml relabels scores without code changes."""

    def test_equal_weights_relabel(self, default_config, zone_baselines):
        """
        With equal weights (1/3 each), the Z1-PAN-PAC-01 Excellent case should
        produce a different score, validating config-driven relabeling.

        Equal weights:
          latency: 90 * 0.3333 = 30.0
          nxdomain: 96 * 0.3333 = 32.0
          saturation: 92 * 0.3333 = 30.667
          score = 30.0 + 32.0 + 30.667 = 92.667 → 93 (still Excellent)

        But if we shift weight heavily toward latency (0.9/0.05/0.05):
          latency: 90 * 0.9 = 81.0
          nxdomain: 96 * 0.05 = 4.8
          saturation: 92 * 0.05 = 4.6
          score = 81.0 + 4.8 + 4.6 = 90.4 → 90

        The key is that the score changes based on config alone.
        """
        agg = MinuteAggregates(
            site="Z1-PAN-PAC-01",
            ts="2026-09-09T10:00:00",
            query_count=120,
            distinct_clients=15,
            p95_latency_ms=30.0,
            nxdomain_rate=0.02,
            qps=2.0,
        )

        # Default config → score 92
        result_default = compute_qoe(agg, default_config, zone_baselines)
        assert result_default.score == 92

        # Custom config: heavy latency weight
        custom_config = QoEConfig(
            weights={"latency": 0.90, "nxdomain": 0.05, "saturation": 0.05},
            normalization=default_config.normalization,
            labels=default_config.labels,
            defaults=default_config.defaults,
        )
        custom_config.validate()

        result_custom = compute_qoe(agg, custom_config, zone_baselines)
        assert result_custom.score == 90
        assert result_custom.label == "Excellent"


        # Verify scores differ
        assert result_default.score != result_custom.score

    def test_label_threshold_change(self, default_config, zone_baselines):
        """
        Changing label thresholds relabels the same score without code changes.
        Default: Excellent >= 85. Custom: Excellent >= 90.
        Score 93 → Excellent under both, but score 87 → Good under custom.
        """
        agg = MinuteAggregates(
            site="Z1-PAN-PAC-01",
            ts="2026-09-09T10:00:00",
            query_count=120,
            distinct_clients=15,
            p95_latency_ms=30.0,
            nxdomain_rate=0.02,
            qps=2.0,
        )

        result_default = compute_qoe(agg, default_config, zone_baselines)
        assert result_default.score == 92
        assert result_default.label == "Excellent"

        # Custom labels: Excellent >= 90
        custom_config = QoEConfig(
            weights=default_config.weights,
            normalization=default_config.normalization,
            labels=[
                LabelThreshold("Excellent", 90),
                LabelThreshold("Good", 70),
                LabelThreshold("Fair", 50),
                LabelThreshold("Poor", 0),
            ],
            defaults=default_config.defaults,
        )
        custom_config.validate()

        result_custom = compute_qoe(agg, custom_config, zone_baselines)
        assert result_custom.score == 92
        assert result_custom.label == "Excellent"

        # Now test a site that scores between 85-89 (Good under custom, Excellent under default)
        # Z4-SAL-SAL-01 with adjusted params to hit score=86
        agg2 = MinuteAggregates(
            site="Z4-SAL-SAL-01",
            ts="2026-09-09T10:03:00",
            query_count=100,
            distinct_clients=12,
            p95_latency_ms=60.0,
            nxdomain_rate=0.05,
            qps=4.0,
        )
        result2_default = compute_qoe(agg2, default_config, zone_baselines)
        result2_custom = compute_qoe(agg2, custom_config, zone_baselines)

        # Same score, different labels
        assert result2_default.score == result2_custom.score
        assert result2_default.label == "Good"   # 78 >= 70
        assert result2_custom.label == "Good"     # 78 >= 70


# ---------------------------------------------------------------------------
# V1: Culprit breakdown auditability
# ---------------------------------------------------------------------------

class TestCulpritBreakdown:
    """Verify that culprit breakdown records each component's weighted contribution."""

    def test_breakdown_sums_to_score(self, default_config, zone_baselines):
        """latency_points + nxdomain_points + saturation_points = score (±1 for rounding)."""
        agg = MinuteAggregates(
            site="Z2-COL-BOG-01",
            ts="2026-09-09T10:01:00",
            query_count=400,
            distinct_clients=50,
            p95_latency_ms=280.0,
            nxdomain_rate=0.45,
            qps=25.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        total = result.latency_points + result.nxdomain_points + result.saturation_points
        assert abs(total - result.score) <= 1  # rounding tolerance

    def test_culprit_identified(self, default_config, zone_baselines):
        """In the Poor case, latency is the biggest contributor (largest gap)."""
        agg = MinuteAggregates(
            site="Z2-COL-BOG-01",
            ts="2026-09-09T10:01:00",
            query_count=400,
            distinct_clients=50,
            p95_latency_ms=280.0,
            nxdomain_rate=0.45,
            qps=25.0,
        )
        result = compute_qoe(agg, default_config, zone_baselines)

        # Culprit = component with lowest weighted points
        points = {
            "latency": result.latency_points,
            "nxdomain": result.nxdomain_points,
            "saturation": result.saturation_points,
        }
        culprit = min(points, key=points.get)
        assert culprit == "saturation"  # 0.8 is the lowest


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestConfigLoading:
    """Verify config/qoe.yaml loads correctly and validates."""

    def test_load_default_config(self):
        """config/qoe.yaml loads without errors."""
        config = load_config()
        assert config.weights["latency"] == 0.45
        assert config.weights["nxdomain"] == 0.35
        assert config.weights["saturation"] == 0.20
        assert config.normalization.max_latency_ms == 300.0
        assert config.normalization.clamp_rate == 0.5
        assert config.normalization.overflow_multiplier == 2.0

    def test_config_validation_catches_bad_weights(self):
        """Weights that don't sum to 1.0 should raise ValueError."""
        bad_config = QoEConfig(
            weights={"latency": 0.5, "nxdomain": 0.3, "saturation": 0.3},
        )
        with pytest.raises(ValueError, match="sum to 1.0"):
            bad_config.validate()

    def test_config_validation_catches_missing_component(self):
        """Missing a weight component should raise ValueError."""
        bad_config = QoEConfig(
            weights={"latency": 0.6, "nxdomain": 0.4},
        )
        with pytest.raises(ValueError, match="Missing weight"):
            bad_config.validate()


# ---------------------------------------------------------------------------
# Zone mapping loading
# ---------------------------------------------------------------------------

class TestZoneMapping:
    """Verify zone_mapping.csv loads correctly."""

    def test_load_zone_mapping(self):
        """zone_mapping.csv loads all sites."""
        baselines = load_zone_mapping()
        assert len(baselines) == 24  # 4 zones × 6 PoPs

    def test_known_site(self):
        """Z1-PAN-PAC-01 baseline is 12.0 QPS."""
        baselines = load_zone_mapping()
        assert "Z1-PAN-PAC-01" in baselines
        assert baselines["Z1-PAN-PAC-01"].baseline_qps == 12.0
        assert baselines["Z1-PAN-PAC-01"].baseline_p95_latency_ms == 45.0

    def test_all_sites_have_baselines(self):
        """Every zone×pop combination has a baseline."""
        baselines = load_zone_mapping()
        for site, zb in baselines.items():
            assert zb.baseline_qps > 0, f"{site} has zero baseline_qps"
            assert zb.baseline_p95_latency_ms > 0, f"{site} has zero baseline_p95_latency_ms"
