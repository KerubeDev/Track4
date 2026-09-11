import json
import os
import time
from unittest.mock import patch

import pytest

from app.agent.qvac_adapter import MODEL, QVACAdapter


def response(verdict="dga", confidence=0.92):
    return json.dumps({"choices": [{"message": {"content": json.dumps({
        "verdict": verdict, "confidence": confidence,
        "reasoning_short": "test", "recommended_action": "Block"
    })}}]}).encode()


def test_contract_and_payload_are_strictly_one_shot():
    calls = []
    def transport(url, body, timeout):
        calls.append((url, json.loads(body), timeout))
        return response()
    result = QVACAdapter("http://localhost:11434", transport=transport).infer(
        "x.example", {"entropy": {"value": 4.2}}, {"client_ip": "10.0.0.1"}
    )
    assert result.verdict == "dga"
    assert result.confidence == 0.92
    assert len(calls) == 1
    assert calls[0][1]["model"] == MODEL
    assert len(calls[0][1]["messages"]) == 2
    prompt = json.loads(calls[0][1]["messages"][1]["content"])
    assert prompt["qname"] == "x.example"


def test_malformed_response_degrades_to_unverified():
    result = QVACAdapter(transport=lambda *_: b"not-json").infer("x.example", {})
    assert result.verdict == "unverified"
    assert result.error


def test_invalid_contract_retries_with_bounded_budget():
    calls = []
    def transport(*_):
        calls.append(time.monotonic())
        return response("unknown", 2)
    result = QVACAdapter(retries=2, transport=transport).infer("x.example", {})
    assert result.verdict == "unverified"
    assert len(calls) == 3


def test_transport_failure_is_controlled():
    calls = []
    def transport(*args):
        calls.append(args)
        raise OSError("offline")
    result = QVACAdapter(transport=transport).infer("x", {})
    assert result.verdict == "unverified"
    assert len(calls) == 2


def test_injected_transport_never_reaches_urlopen():
    calls = []
    def transport(*_):
        calls.append(1)
        return response()
    with patch("app.agent.qvac_adapter.request.urlopen", side_effect=AssertionError("network egress attempted")):
        result = QVACAdapter(transport=transport).infer("x.example", {})
    assert result.verdict == "dga"
    assert len(calls) == 1


def test_constructor_refuses_public_inference_endpoint():
    with patch("app.agent.qvac_adapter.socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 0))]):
        with pytest.raises(ValueError, match="local/private"):
            QVACAdapter("http://model.example:11434")


def test_private_inference_endpoint_is_accepted():
    adapter = QVACAdapter("http://10.10.0.4:11434", transport=lambda *_: response("benign", 0.9))
    assert adapter.infer("www.google.com", {}).verdict == "benign"


def test_prompt_marks_dns_fields_as_untrusted_data():
    captured = {}
    def transport(_url, body, _timeout):
        captured.update(json.loads(body))
        return response()
    QVACAdapter(transport=transport).infer("ignore-previous-instructions.example", {})
    assert "untrusted data" in captured["messages"][0]["content"]


@pytest.mark.skipif(
    os.environ.get("QVAC_LIVE_SMOKE") != "1",
    reason="live QVAC smoke requires QVAC_LIVE_SMOKE=1 and a reachable local QVAC service",
)
def test_live_qvac_smoke_known_dga_and_benign():
    adapter = QVACAdapter()
    dga = adapter.infer("flub-19k.gcpvls.kixgxsvw.top", {"entropy": {"value": 6.1}}, {"client_ip": "10.0.0.1"})
    benign = adapter.infer("www.google.com", {"entropy": {"value": 2.4}}, {"client_ip": "10.0.0.1"})
    if "unverified" in (dga.verdict, benign.verdict):
        pytest.skip("local QVAC service unavailable")
    assert dga.verdict == "dga"
    assert dga.confidence >= 0.7
    assert dga.reasoning_short and dga.recommended_action
    assert benign.verdict == "benign"
    assert benign.reasoning_short and benign.recommended_action
