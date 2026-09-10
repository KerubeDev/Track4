# =============================================================================
# QoE scoring engine — Sentinel-DNS Track4
# Issue #12 (S2-T2)
#
# Per-site, per-minute Quality-of-Experience computation.
# See config/qoe.yaml for all tunable parameters.
# =============================================================================

"""QoE scoring engine for Sentinel-DNS."""

from .engine import QoEScore, compute_qoe, load_config, load_zone_mapping
from .config import QoEConfig

__all__ = ["QoEConfig", "QoEScore", "compute_qoe", "load_config", "load_zone_mapping"]
