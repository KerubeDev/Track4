import json
import time

from app.agent.qvac_adapter import MODEL, QVACAdapter


def response(verdict="dga", confidence=0.92):
    return json.dumps({"message": {"content": json.dumps({
        "verdict": verdict, "confidence": confidence,
        "reasoning_short": "test", "recommended_action": "Block"
    })}}).encode()


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
    assert result.latency_ms >= 0
    assert len(calls) == 1
    assert calls[0][1]["model"] == MODEL
    assert len(calls[0][1]["messages"]) == 1
    prompt = json.loads(calls[0][1]["messages"][0]["content"])
    assert prompt["qname"] == "x.example"
    assert prompt["signal_evidence"]["entropy"]["value"] == 4.2


def test_malformed_response_degrades_to_unverified():
    result = QVACAdapter(transport=lambda *_: b"not-json").infer("x.example", {})
    assert result.verdict == "unverified"
    assert result.confidence == 0.0
    assert result.error


def test_invalid_contract_retries_with_bounded_budget():
    calls = []

    def transport(*_):
        calls.append(time.monotonic())
        return response("unknown", 2)

    result = QVACAdapter(retries=2, transport=transport).infer("x.example", {})
    assert result.verdict == "unverified"
    assert len(calls) == 3


def test_transport_failure_does_not_attempt_network_when_fake_transport_is_used():
    calls = []
    result = QVACAdapter(transport=lambda *args: calls.append(args) or (_ for _ in ()).throw(OSError("offline"))).infer("x", {})
    assert result.verdict == "unverified"
    assert len(calls) == 2
