#!/usr/bin/env python3
"""
Alert publisher — Sentinel-DNS Track4
Issue #14 (S2-T4) — Wazuh syslog ingestion

Publishes each alert as a one-line JSON event via remote syslog,
exactly per ADR-0004 and P3b severity mapping.

The JSON event is sent as a single UDP syslog datagram (RFC 3164
<header> + body) directly to the Wazuh manager so its
``remote connection=syslog`` listener (``ossec.conf``, port 1514/udp)
receives it, and the decoder can parse it via
<program_name>sentinel-dns</program_name>.
"""

from __future__ import annotations

import json
import logging
import socket
import syslog
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Verdict → Wazuh rule ID + severity mapping (P3b / ADR-0004)
# ---------------------------------------------------------------------------
# Confidence-keyed rules for DGA (threshold → rule).
DGA_CONFIDENCE_RULES: Dict[float, Dict[str, Any]] = {
    0.90: {"rule_id": 100101, "severity": 12},
}
# DGA default rule when no confidence threshold is met.
DGA_DEFAULT_RULE: Dict[str, Any] = {"rule_id": 100102, "severity": 9}

VERDICT_MAP: Dict[str, Dict[str, Any]] = {
    "tunnel": {"rule_id": 100103, "severity": 12},
    "beaconing": {"rule_id": 100104, "severity": 10},
    "typosquat": {"rule_id": 100105, "severity": 6},
    "unverified": {"rule_id": 100106, "severity": 5},
}


@dataclass(frozen=True)
class VerdictInfo:
    """Parsed QVAC verdict for an escalated query."""

    verdict: str
    confidence: float
    reasoning_short: str = ""
    recommended_action: str = ""
    qname: str = ""
    client_ip: str = ""
    signal_evidence: Dict[str, Any] = field(default_factory=dict)


def resolve_wazuh_rule(verdict: str, confidence: float) -> Optional[Dict[str, Any]]:
    """Resolve the Wazuh rule ID and severity for a verdict + confidence pair.

    Returns a dict with keys ``rule_id`` and ``severity``, or ``None`` if
    the verdict is ``benign`` (no alert emitted per P3b).

    Examples:
        >>> resolve_wazuh_rule("dga", 0.95)
        {'rule_id': 100101, 'severity': 12}
        >>> resolve_wazuh_rule("dga", 0.80)
        {'rule_id': 100102, 'severity': 9}
        >>> resolve_wazuh_rule("benign", 0.50) is None
        True
    """
    if verdict == "benign":
        return None

    if verdict == "dga":
        for threshold in sorted(DGA_CONFIDENCE_RULES):
            if confidence >= threshold:
                return DGA_CONFIDENCE_RULES[threshold]
        return DGA_DEFAULT_RULE

    mapping = VERDICT_MAP.get(verdict)
    if mapping is None:
        # Unknown verdict → unverified (ADR-0002 degradation)
        return {"rule_id": 100106, "severity": 5}

    return {"rule_id": mapping["rule_id"], "severity": mapping["severity"]}


def format_alert(
    verdict_info: VerdictInfo,
    rule_id: int,
    severity: int,
    *,
    schema_version: str = "1.0",
) -> str:
    """Format a one-line JSON alert for Wazuh ingestion.

    The output is a single line of JSON (no embedded newlines) that
    Wazuh's decoder can parse via ``sentinel-dns`` program name.

    Required fields per ADR-0004:
      - ``sentinel.verdict``: the threat classification
      - ``sentinel.confidence``: model confidence (0.0–1.0)
      - ``rule_id``: the Wazuh rule ID
      - ``severity``: the Wazuh severity level

    Optional fields:
      - ``reasoning_short``, ``recommended_action``: QVAC evidence
      - ``qname``, ``client_ip``: originating query info
      - ``signal_evidence``: deterministic filter signals that triggered escalation
      - ``schema_version``: event schema version
    """
    event = {
        "schema_version": schema_version,
        "sentinel.verdict": verdict_info.verdict,
        "sentinel.confidence": verdict_info.confidence,
        "rule_id": rule_id,
        "severity": severity,
        "reasoning_short": verdict_info.reasoning_short,
        "recommended_action": verdict_info.recommended_action,
        "qname": verdict_info.qname,
        "client_ip": verdict_info.client_ip,
        "signal_evidence": verdict_info.signal_evidence,
    }
    return json.dumps(event, separators=(",", ":"))


class AlertPublisher:
    """Publishes sentinel-dns alerts via remote syslog to Wazuh.

    Sends one-line JSON events as UDP syslog datagrams to
    ``wazuh_host:wazuh_port`` (default ``wazuh:1514/udp``), with
    ``<program_name>sentinel-dns`` in the message body so the Wazuh
    decoder (``local_decoder.xml``) can extract ``verdict`` and
    ``confidence`` fields.

    Usage::

        publisher = AlertPublisher(wazuh_host="wazuh", wazuh_port=1514)
        publisher.publish(verdict_info)
    """

    def __init__(
        self,
        wazuh_host: str = "wazuh",
        wazuh_port: int = 1514,
        *,
        syslog_facility: int = syslog.LOG_LOCAL4,
    ) -> None:
        self.wazuh_host = wazuh_host
        self.wazuh_port = wazuh_port
        self._syslog_facility = syslog_facility

    def publish(self, verdict_info: VerdictInfo) -> bool:
        """Publish a verdict as a Wazuh alert.

        Resolves the Wazuh rule from the verdict + confidence, formats
        the one-line JSON, and sends it via remote syslog.

        Returns ``True`` on success, ``False`` on failure (logged).
        """
        rule = resolve_wazuh_rule(verdict_info.verdict, verdict_info.confidence)
        if rule is None:
            logger.debug(
                "Benign verdict for %s — no Wazuh alert emitted",
                verdict_info.qname,
            )
            return True

        alert_line = format_alert(verdict_info, rule["rule_id"], rule["severity"])

        return self._send_syslog(alert_line)

    def _send_syslog(self, message: str) -> bool:
        """Send one alert as a UDP syslog datagram to the Wazuh manager.

        Remote syslog per ADR-0004: a single datagram to
        ``wazuh_host:wazuh_port`` (default ``wazuh:1514/udp``), matching
        the Wazuh ``remote connection=syslog`` listener in ``ossec.conf``.
        Priority is ``LOG_INFO`` on the configured facility (default
        ``LOG_LOCAL4`` → ``<166>``), and the ``sentinel-dns`` ident is
        carried in the message body so Wazuh's decoder matches
        ``program_name``.
        """
        pri = self._syslog_facility + syslog.LOG_INFO
        payload = f"<{pri}>sentinel-dns: {message}"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(payload.encode("utf-8"), (self.wazuh_host, self.wazuh_port))
            logger.debug(
                "Alert sent to Wazuh %s:%d (%d bytes)",
                self.wazuh_host,
                self.wazuh_port,
                len(payload),
            )
            return True
        except OSError as exc:
            logger.error("Failed to send syslog to Wazuh: %s", exc)
            return False
