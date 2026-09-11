from pathlib import Path

from app.light.store import LocalStore
from app.light.runtime import process


def _event(i, rcode="NOERROR"):
    return {"timestamp": f"2026-01-01T00:00:{i:02d}Z", "client_ip": "10.0.0.1", "qname": "normal.example", "qtype": "A", "rcode": rcode, "latency_ms": 20, "zone_id": "PA-PTY-01", "pop_id": "PAN-PAC-01"}


class FakeQVAC:
    def infer(self, qname, signals, context=None):
        class V: verdict="dga"; confidence=.9; reasoning_short="local test"; recommended_action="investigate"; latency_ms=1
        return V()


def test_local_store_snapshot(tmp_path):
    s=LocalStore(tmp_path/"shield.db"); s.write_event(_event(0)); snap=s.snapshot(); s.close(); assert snap["events"]==1 and snap["alerts"]==0


def test_light_pipeline_without_infrastructure(tmp_path, monkeypatch):
    import app.light.runtime as rt
    monkeypatch.setattr(rt, "QVACAdapter", lambda *_: FakeQVAC())
    events=[_event(i, "NXDOMAIN") for i in range(5)]
    store=LocalStore(tmp_path/"shield.db")
    count, alerts=process(events, store, "http://127.0.0.1:11434")
    snap=store.snapshot(); store.close()
    assert count==5 and alerts>=1 and snap["events"]==5 and snap["alerts"]>=1
