# =============================================================================
# QoE configuration loader
# Issue #12 (S2-T2) — Sentinel-DNS Track4
#
# Loads and validates config/qoe.yaml. All weights, thresholds, normalization
# formulas, and labels are read from here — changing the YAML relabels scores
# without code changes.
# =============================================================================

"""Configuration loader for QoE scoring."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

import yaml


@dataclass(frozen=True)
class NormalizationConfig:
    """Normalization parameters for a single QoE component."""

    max_latency_ms: float = 300.0
    clamp_rate: float = 0.5
    overflow_multiplier: float = 2.0


@dataclass(frozen=True)
class LabelThreshold:
    """A single label boundary: (label_name, min_score)."""

    name: str
    min_score: int


@dataclass(frozen=True)
class QoEConfig:
    """Full QoE configuration loaded from config/qoe.yaml."""

    weights: Dict[str, float] = field(default_factory=lambda: {
        "latency": 0.45,
        "nxdomain": 0.35,
        "saturation": 0.20,
    })
    normalization: NormalizationConfig = field(default_factory=NormalizationConfig)
    labels: List[LabelThreshold] = field(default_factory=lambda: [
        LabelThreshold("Excellent", 85),
        LabelThreshold("Good", 70),
        LabelThreshold("Fair", 50),
        LabelThreshold("Poor", 0),
    ])
    defaults: Dict[str, float] = field(default_factory=lambda: {
        "baseline_qps": 10.0,
        "baseline_p95_latency_ms": 50.0,
    })

    def validate(self) -> None:
        """Validate config invariants. Raises ValueError on bad config."""
        # Weights must sum to 1.0 (with float tolerance)
        total = sum(self.weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Weights must sum to 1.0, got {total}"
            )

        # All three components must be present
        required = {"latency", "nxdomain", "saturation"}
        missing = required - set(self.weights.keys())
        if missing:
            raise ValueError(f"Missing weight components: {missing}")

        # All weights must be non-negative
        for name, w in self.weights.items():
            if w < 0:
                raise ValueError(f"Weight '{name}' must be non-negative, got {w}")

        # Normalization bounds
        if self.normalization.max_latency_ms <= 0:
            raise ValueError(
                f"max_latency_ms must be positive, got {self.normalization.max_latency_ms}"
            )
        if not (0 < self.normalization.clamp_rate <= 1.0):
            raise ValueError(
                f"clamp_rate must be in (0, 1], got {self.normalization.clamp_rate}"
            )
        if self.normalization.overflow_multiplier <= 0:
            raise ValueError(
                f"overflow_multiplier must be positive, got {self.normalization.overflow_multiplier}"
            )

        # Labels must be sorted descending by min_score
        scores = [l.min_score for l in self.labels]
        if scores != sorted(scores, reverse=True):
            raise ValueError(f"Labels must be sorted descending by min_score, got {scores}")

        # Label boundaries must be contiguous (each next = previous - step or overlap)
        # We just check they cover 0-100
        if self.labels[-1].min_score != 0:
            raise ValueError("Lowest label must have min_score = 0")


def _load_yaml(path: Path) -> dict:
    """Load a YAML file and return the parsed dict."""
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_config(config_path: str | Path | None = None) -> QoEConfig:
    """Load QoE configuration from config/qoe.yaml.

    Args:
        config_path: Path to the YAML config file. If None, uses
                     config/qoe.yaml relative to the project root.

    Returns:
        Validated QoEConfig instance.
    """
    if config_path is None:
        # Walk up from this file to find the project root
        project_root = Path(__file__).resolve().parent.parent.parent
        config_path = project_root / "config" / "qoe.yaml"
    else:
        config_path = Path(config_path)

    data = _load_yaml(config_path)

    # Build normalization config
    norm = data.get("normalization", {})
    norm_config = NormalizationConfig(
        max_latency_ms=norm.get("latency", {}).get("max_latency_ms", 300.0),
        clamp_rate=norm.get("nxdomain", {}).get("clamp_rate", 0.5),
        overflow_multiplier=norm.get("saturation", {}).get("overflow_multiplier", 2.0),
    )

    # Build labels
    labels_data = data.get("labels", {})
    label_order = ["excellent", "good", "fair", "poor"]
    labels = []
    for lbl in label_order:
        if lbl in labels_data:
            labels.append(LabelThreshold(
                name=lbl.capitalize(),
                min_score=labels_data[lbl]["min_score"],
            ))

    config = QoEConfig(
        weights=data.get("weights", {
            "latency": 0.45,
            "nxdomain": 0.35,
            "saturation": 0.20,
        }),
        normalization=norm_config,
        labels=labels,
        defaults=data.get("defaults", {
            "baseline_qps": 10.0,
            "baseline_p95_latency_ms": 50.0,
        }),
    )

    config.validate()
    return config
