#!/usr/bin/env python3
"""
Tests for Wazuh syslog ingestion and severity mapping — Sentinel-DNS Track4
Issue #14 (S2-T4)

Validates:
  V1 — Rule IDs 100101–100106 match the P3b severity mapping table exactly.
  V2 — Alert format is one-line JSON with required fields.
  V3 — Decoder/rules XML files are structurally valid and contain required IDs.
  V4 — Alert publisher resolves correct rules for all verdict/confidence combos.
  V5 — Benign verdict emits no alert (None rule).
"""

from __future__ import annotations

import json
import os
import sys
import socket
import syslog
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch
from xml.etree import ElementTree as ET

import pytest

# ---------------------------------------------------------------------------
# Ensure the project root is on the path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.agent.alert_publisher import (
    VERDICT_MAP,
    DGA_CONFIDENCE_RULES,
    DGA_DEFAULT_RULE,
    VerdictInfo,
    resolve_wazuh_rule,
    format_alert,
    AlertPublisher,
)


# ===========================================================================
# Shared test helpers
# ===========================================================================

def _make_verdict(**kwargs: Any) -> VerdictInfo:
    """Create a VerdictInfo with sensible defaults for testing."""
    defaults: Dict[str, Any] = {
        "verdict": "dga",
        "confidence": 0.95,
        "reasoning_short": "High entropy domain",
        "recommended_action": "Block",
        "qname": "evil.example.com",
        "client_ip": "10.0.1.50",
        "signal_evidence": {"entropy": 4.2, "length": 45},
    }
    defaults.update(kwargs)
    return VerdictInfo(**defaults)


# ===========================================================================
# V1: P3b severity mapping — golden fixture table
# ===========================================================================

# Expected: (verdict, confidence, expected_rule_id, expected_severity)
P3B_SEVERITY_TABLE = [
    ("dga", 0.95, 100101, 12),
    ("dga", 0.90, 100101, 12),
    ("dga", 0.89, 100102, 9),
    ("dga", 0.50, 100102, 9),
    ("tunnel", 0.80, 100103, 12),
    ("beaconing", 0.70, 100104, 10),
    ("typosquat", 0.60, 100105, 6),
    ("unverified", 0.00, 100106, 5),
    ("benign", 0.99, None, None),  # no rule emitted
]


class TestP3bSeverityMapping:
    """V1: Rule IDs and severity match the P3b decision table exactly."""

    @pytest.mark.parametrize(
        "verdict,confidence,expected_rule_id,expected_severity",
        P3B_SEVERITY_TABLE,
        ids=[f"{v}-c{c}" for v, c, _, _ in P3B_SEVERITY_TABLE],
    )
    def test_severity_mapping(
        self,
        verdict: str,
        confidence: float,
        expected_rule_id: Optional[int],
        expected_severity: Optional[int],
    ) -> None:
        """Each verdict+confidence maps to the correct rule ID and severity."""
        result = resolve_wazuh_rule(verdict, confidence)

        if expected_rule_id is None:
            assert result is None, (
                f"Expected no alert for benign, got {result}"
            )
        else:
            assert result is not None, (
                f"Expected rule {expected_rule_id} for {verdict}, got None"
            )
            assert result["rule_id"] == expected_rule_id, (
                f"verdict={verdict} confidence={confidence}: "
                f"expected rule_id={expected_rule_id}, got {result['rule_id']}"
            )
            assert result["severity"] == expected_severity, (
                f"verdict={verdict} confidence={confidence}: "
                f"expected severity={expected_severity}, got {result['severity']}"
            )


# ===========================================================================
# V1: VERDICT_MAP structural checks
# ===========================================================================

class TestVerdictMapStructure:
    """Verify VERDICT_MAP covers all required verdicts."""

    def test_all_verdicts_present(self) -> None:
        """VERDICT_MAP contains entries for all non-benign, non-dga verdicts."""
        required_verdicts = {"tunnel", "beaconing", "typosquat", "unverified"}
        assert required_verdicts.issubset(set(VERDICT_MAP.keys()))
        assert "dga" in DGA_CONFIDENCE_RULES or DGA_DEFAULT_RULE is not None

    def test_dga_has_high_and_low_confidence(self) -> None:
        """DGA confidence rules must have a high-confidence entry and a default fallback."""
        assert 0.90 in DGA_CONFIDENCE_RULES
        assert DGA_DEFAULT_RULE is not None
        assert "rule_id" in DGA_CONFIDENCE_RULES[0.90]
        assert "severity" in DGA_CONFIDENCE_RULES[0.90]
        assert "rule_id" in DGA_DEFAULT_RULE
        assert "severity" in DGA_DEFAULT_RULE

    def test_rule_ids_are_consecutive(self) -> None:
        """All rule IDs are in the 100101–100106 range."""
        all_ids = []
        for verdict, mapping in VERDICT_MAP.items():
            all_ids.append(mapping["rule_id"])
        for rule in DGA_CONFIDENCE_RULES.values():
            all_ids.append(rule["rule_id"])
        all_ids.append(DGA_DEFAULT_RULE["rule_id"])
        assert sorted(set(all_ids)) == [100101, 100102, 100103, 100104, 100105, 100106]


# ===========================================================================
# V2: Alert format — one-line JSON with required fields
# ===========================================================================

class TestAlertFormat:
    """V2: Alerts are one-line JSON with required fields."""

    def test_one_line_json(self) -> None:
        """Alert must be a single line (no embedded newlines)."""
        vi =         _make_verdict()
        alert = format_alert(vi, rule_id=100101, severity=12)
        assert "\n" not in alert, "Alert contains embedded newline"

    def test_valid_json(self) -> None:
        """Alert must parse as valid JSON."""
        vi =         _make_verdict()
        alert = format_alert(vi, rule_id=100101, severity=12)
        parsed = json.loads(alert)
        assert isinstance(parsed, dict)

    def test_required_fields_present(self) -> None:
        """Alert must contain all required fields per ADR-0004."""
        vi =         _make_verdict()
        alert = format_alert(vi, rule_id=100101, severity=12)
        parsed = json.loads(alert)

        required_fields = [
            "sentinel.verdict",
            "sentinel.confidence",
            "rule_id",
            "severity",
            "reasoning_short",
            "recommended_action",
            "qname",
            "client_ip",
            "signal_evidence",
            "schema_version",
        ]
        for field in required_fields:
            assert field in parsed, f"Missing required field: {field}"

    def test_verdict_and_confidence_propagated(self) -> None:
        """sentinel.verdict and sentinel.confidence must be in the JSON event."""
        vi = _make_verdict(verdict="tunnel", confidence=0.88)
        alert = format_alert(vi, rule_id=100103, severity=12)
        parsed = json.loads(alert)

        assert parsed["sentinel.verdict"] == "tunnel"
        assert parsed["sentinel.confidence"] == 0.88

    def test_rule_id_and_severity_match(self) -> None:
        """rule_id and severity in the JSON match the resolved values."""
        vi =         _make_verdict(verdict="beaconing", confidence=0.70)
        alert = format_alert(vi, rule_id=100104, severity=10)
        parsed = json.loads(alert)

        assert parsed["rule_id"] == 100104
        assert parsed["severity"] == 10

    def test_json_compact_separators(self) -> None:
        """JSON uses compact separators (no spaces after commas/colons)."""
        vi =         _make_verdict()
        alert = format_alert(vi, rule_id=100101, severity=12)
        # Compact JSON should not have ", " (comma-space) or ": " (colon-space)
        assert ", " not in alert, "Alert has spaces after commas"
        assert ": " not in alert, "Alert has spaces after colons"

    def test_schema_version_default(self) -> None:
        """schema_version defaults to 1.0."""
        vi =         _make_verdict()
        alert = format_alert(vi, rule_id=100101, severity=12)
        parsed = json.loads(alert)
        assert parsed["schema_version"] == "1.0"


# ===========================================================================
# V3: XML files — structural validation
# ===========================================================================

class TestWazuhXmlFiles:
    """V3: Decoder and rules XML are structurally valid."""

    @pytest.fixture
    def rules_xml_path(self) -> Path:
        return PROJECT_ROOT / "deploy" / "wazuh" / "etc" / "rules" / "local_rules.xml"

    @pytest.fixture
    def decoder_xml_path(self) -> Path:
        return PROJECT_ROOT / "deploy" / "wazuh" / "etc" / "decoders" / "local_decoder.xml"

    @pytest.fixture
    def ossec_conf_path(self) -> Path:
        return PROJECT_ROOT / "deploy" / "wazuh" / "etc" / "ossec.conf"

    def test_rules_xml_parsable(self, rules_xml_path: Path) -> None:
        """local_rules.xml must be valid XML."""
        assert rules_xml_path.exists(), f"File not found: {rules_xml_path}"
        ET.parse(rules_xml_path)

    def test_decoder_xml_parsable(self, decoder_xml_path: Path) -> None:
        """local_decoder.xml must be valid XML."""
        assert decoder_xml_path.exists(), f"File not found: {decoder_xml_path}"
        ET.parse(decoder_xml_path)

    def test_ossec_conf_parsable(self, ossec_conf_path: Path) -> None:
        """ossec.conf must be valid XML."""
        assert ossec_conf_path.exists(), f"File not found: {ossec_conf_path}"
        ET.parse(ossec_conf_path)

    def test_all_rule_ids_present(self, rules_xml_path: Path) -> None:
        """Rules XML must contain rule IDs 100101–100106."""
        tree = ET.parse(rules_xml_path)
        root = tree.getroot()

        found_ids = set()
        for rule_elem in root.iter("rule"):
            rule_id = rule_elem.get("id")
            if rule_id:
                found_ids.add(int(rule_id))

        expected_ids = {100101, 100102, 100103, 100104, 100105, 100106}
        assert expected_ids.issubset(found_ids), (
            f"Missing rule IDs: {expected_ids - found_ids}"
        )

    def test_decoder_matches_sentinel_dns(self, decoder_xml_path: Path) -> None:
        """Decoder must match program name 'sentinel-dns'."""
        tree = ET.parse(decoder_xml_path)
        root = tree.getroot()

        # Wazuh decoder files may use <xml> or <decoders> root wrapper
        # containing <decoder> children; iterate all elements to find
        # <program_name>.
        program_names = []
        for pn in root.iter("program_name"):
            program_names.append(pn.text or "")

        assert "sentinel-dns" in program_names, (
            f"Decoder missing program_name 'sentinel-dns', found: {program_names}"
        )

    def test_decoder_extracts_verdict(self, decoder_xml_path: Path) -> None:
        """Decoder must extract 'sentinel.verdict' field."""
        tree = ET.parse(decoder_xml_path)
        root = tree.getroot()

        orders = []
        for order in root.iter("order"):
            order_text = order.text or ""
            orders.append(order_text)

        assert any("sentinel.verdict" in o for o in orders), (
            f"Decoder missing 'sentinel.verdict' in <order>, found: {orders}"
        )

    def test_decoder_extracts_confidence(self, decoder_xml_path: Path) -> None:
        """Decoder must extract 'sentinel.confidence' field."""
        tree = ET.parse(decoder_xml_path)
        root = tree.getroot()

        orders = []
        for order in root.iter("order"):
            order_text = order.text or ""
            orders.append(order_text)

        assert any("sentinel.confidence" in o for o in orders), (
            f"Decoder missing 'sentinel.confidence' in <order>, found: {orders}"
        )

    def test_rules_reference_decoder(self, rules_xml_path: Path) -> None:
        """All sentinel-dns rules must reference decoded_as='sentinel-dns-json'."""
        tree = ET.parse(rules_xml_path)
        root = tree.getroot()

        for rule_elem in root.iter("rule"):
            rule_id = rule_elem.get("id")
            if rule_id and int(rule_id) in {100101, 100102, 100103, 100104, 100105, 100106}:
                decoded_as_elems = list(rule_elem.iter("decoded_as"))
                decoded_values = [d.text for d in decoded_as_elems if d.text]
                assert "sentinel-dns-json" in decoded_values, (
                    f"Rule {rule_id} missing decoded_as='sentinel-dns-json'"
                )

    def test_ossec_conf_remote_syslog(self, ossec_conf_path: Path) -> None:
        """ossec.conf must configure remote syslog listener."""
        tree = ET.parse(ossec_conf_path)
        root = tree.getroot()

        remote_found = False
        for remote in root.iter("remote"):
            connection = remote.find("connection")
            if connection is not None and connection.text == "syslog":
                remote_found = True
                port = remote.find("port")
                assert port is not None and port.text == "1514", (
                    f"Expected syslog port 1514, got {port.text if port is not None else None}"
                )
                break

        assert remote_found, "ossec.conf missing <remote><connection>syslog</connection>"


# ===========================================================================
# V4: Alert publisher — rule resolution edge cases
# ===========================================================================

class TestAlertPublisherRuleResolution:
    """V4: Publisher resolves correct rules for all verdict/confidence combos."""

    def test_dga_high_confidence_boundary(self) -> None:
        """DGA at exactly 0.90 → high confidence (rule 100101)."""
        result = resolve_wazuh_rule("dga", 0.90)
        assert result is not None
        assert result["rule_id"] == 100101
        assert result["severity"] == 12

    def test_dga_high_confidence_above(self) -> None:
        """DGA at 0.99 → high confidence (rule 100101)."""
        result = resolve_wazuh_rule("dga", 0.99)
        assert result is not None
        assert result["rule_id"] == 100101

    def test_dga_low_confidence_below(self) -> None:
        """DGA at 0.89 → low confidence (rule 100102)."""
        result = resolve_wazuh_rule("dga", 0.89)
        assert result is not None
        assert result["rule_id"] == 100102
        assert result["severity"] == 9

    def test_dga_zero_confidence(self) -> None:
        """DGA at 0.00 → low confidence (rule 100102)."""
        result = resolve_wazuh_rule("dga", 0.00)
        assert result is not None
        assert result["rule_id"] == 100102

    def test_unknown_verdict_falls_back_to_unverified(self) -> None:
        """Unknown verdict → unverified (rule 100106, severity 5)."""
        result = resolve_wazuh_rule("unknown_threat", 0.50)
        assert result is not None
        assert result["rule_id"] == 100106
        assert result["severity"] == 5

    def test_benign_returns_none(self) -> None:
        """Benign verdict → no rule (None)."""
        assert resolve_wazuh_rule("benign", 0.99) is None
        assert resolve_wazuh_rule("benign", 0.00) is None


# ===========================================================================
# V5: Benign → no alert
# ===========================================================================

class TestBenignNoAlert:
    """V5: Benign verdict must not produce a Wazuh alert."""

    def test_publish_benign_returns_true(self) -> None:
        """AlertPublisher.publish() returns True for benign (success, no alert)."""
        publisher = AlertPublisher(wazuh_host="localhost", wazuh_port=9999)
        vi = VerdictInfo(verdict="benign", confidence=0.99)
        # Should succeed without sending any syslog
        result = publisher.publish(vi)
        assert result is True

    def test_publish_benign_no_syslog_sent(self) -> None:
        """Benign verdict must never call _send_syslog (no datagram attempted)."""
        publisher = AlertPublisher(wazuh_host="localhost", wazuh_port=9999)
        vi = VerdictInfo(verdict="benign", confidence=0.99)

        calls: list[str] = []
        original = publisher._send_syslog

        def _spy(message: str) -> bool:
            calls.append(message)
            return original(message)

        publisher._send_syslog = _spy  # type: ignore[method-assign]

        result = publisher.publish(vi)

        assert result is True
        assert calls == [], f"_send_syslog called for benign verdict: {calls}"


# ===========================================================================
# V5b: UDP remote-syslog transport (ADR-0004)
# ===========================================================================

class TestUdpSyslogTransport:
    """V5b: _send_syslog sends a UDP datagram to wazuh_host:wazuh_port.

    Regression tests for review finding F1: the publisher must target the
    Wazuh manager (``SOCK_DGRAM`` + ``sendto`` to ``wazuh_host:wazuh_port``),
    not the local syslog daemon.
    """

    # Captured at import time, before any patching of socket.socket.
    AF_INET = socket.AF_INET
    SOCK_DGRAM = socket.SOCK_DGRAM

    def test_publish_sends_udp_datagram_to_wazuh_target(self) -> None:
        """publish() opens one UDP socket and sends one datagram to the target."""
        publisher = AlertPublisher(wazuh_host="wazuh", wazuh_port=1514)
        vi = _make_verdict()

        with patch("app.agent.alert_publisher.socket.socket") as sock_factory:
            sock = sock_factory.return_value.__enter__.return_value
            result = publisher.publish(vi)

        assert result is True
        sock_factory.assert_called_once_with(self.AF_INET, self.SOCK_DGRAM)
        assert sock.sendto.call_count == 1

        send_args, send_kwargs = sock.sendto.call_args
        payload, target = send_args[0], send_args[1]
        assert send_kwargs == {}
        assert target == ("wazuh", 1514)
        assert isinstance(payload, bytes)

    def test_send_syslog_payload_has_pri_and_ident(self) -> None:
        """Payload is ``<PRI>sentinel-dns: <json>`` — PRI 166 = LOCAL4.INFO."""
        publisher = AlertPublisher()  # defaults: wazuh:1514, LOG_LOCAL4
        vi =         _make_verdict(verdict="tunnel", confidence=0.88)

        alert_line = format_alert(vi, rule_id=100103, severity=12)
        expected_payload = (
            f"<{syslog.LOG_LOCAL4 + syslog.LOG_INFO}>sentinel-dns: {alert_line}"
        ).encode("utf-8")

        with patch("app.agent.alert_publisher.socket.socket") as sock_factory:
            sock = sock_factory.return_value.__enter__.return_value
            assert publisher.publish(vi) is True

        payload, _target = sock.sendto.call_args[0]
        assert payload == expected_payload
        assert payload.startswith(b"<166>sentinel-dns: ")

    def test_send_syslog_uses_configured_target_and_facility(self) -> None:
        """Custom host/port/facility are honored end to end."""
        publisher = AlertPublisher(
            wazuh_host="siem.example.com",
            wazuh_port=5514,
            syslog_facility=syslog.LOG_AUTH,
        )

        with patch("app.agent.alert_publisher.socket.socket") as sock_factory:
            sock = sock_factory.return_value.__enter__.return_value
            assert publisher._send_syslog('{"verdict":"dga"}') is True

        payload, target = sock.sendto.call_args[0]
        assert target == ("siem.example.com", 5514)
        assert payload.startswith(
            f"<{syslog.LOG_AUTH + syslog.LOG_INFO}>".encode("utf-8")
        )

    def test_send_syslog_returns_false_on_socket_error(self) -> None:
        """A send failure is swallowed, logged, and reported as False."""
        publisher = AlertPublisher(wazuh_host="wazuh", wazuh_port=1514)

        with patch("app.agent.alert_publisher.socket.socket") as sock_factory:
            sock = sock_factory.return_value.__enter__.return_value
            sock.sendto.side_effect = OSError("network unreachable")
            assert publisher._send_syslog('{"verdict":"dga"}') is False

    def test_publish_benign_opens_no_socket(self) -> None:
        """Benign verdict must not open a UDP socket at all."""
        publisher = AlertPublisher(wazuh_host="wazuh", wazuh_port=1514)
        vi =         _make_verdict(verdict="benign", confidence=0.99)

        with patch("app.agent.alert_publisher.socket.socket") as sock_factory:
            assert publisher.publish(vi) is True
            sock_factory.assert_not_called()


# ===========================================================================
# V6: Integration — format + resolve end-to-end
# ===========================================================================

class TestEndToEnd:
    """End-to-end: VerdictInfo → resolve → format → validate JSON."""

    @pytest.mark.parametrize(
        "verdict,confidence,expected_rule_id,expected_severity",
        [
            ("dga", 0.95, 100101, 12),
            ("dga", 0.80, 100102, 9),
            ("tunnel", 0.88, 100103, 12),
            ("beaconing", 0.75, 100104, 10),
            ("typosquat", 0.60, 100105, 6),
            ("unverified", 0.00, 100106, 5),
        ],
        ids=["dga-high", "dga-low", "tunnel", "beaconing", "typosquat", "unverified"],
    )
    def test_full_pipeline(
        self,
        verdict: str,
        confidence: float,
        expected_rule_id: int,
        expected_severity: int,
    ) -> None:
        """Full pipeline: VerdictInfo → resolve_wazuh_rule → format_alert → JSON."""
        vi = VerdictInfo(
            verdict=verdict,
            confidence=confidence,
            reasoning_short=f"Test reasoning for {verdict}",
            recommended_action="Block",
            qname=f"test-{verdict}.example.com",
            client_ip="10.0.1.100",
            signal_evidence={"entropy": 3.8, "length": 42},
        )

        rule = resolve_wazuh_rule(vi.verdict, vi.confidence)
        assert rule is not None
        assert rule["rule_id"] == expected_rule_id
        assert rule["severity"] == expected_severity

        alert = format_alert(vi, rule["rule_id"], rule["severity"])
        parsed = json.loads(alert)

        # Verify all key fields
        assert parsed["sentinel.verdict"] == verdict
        assert parsed["sentinel.confidence"] == confidence
        assert parsed["rule_id"] == expected_rule_id
        assert parsed["severity"] == expected_severity
        assert parsed["qname"] == f"test-{verdict}.example.com"
        assert parsed["client_ip"] == "10.0.1.100"
        assert parsed["signal_evidence"]["entropy"] == 3.8
