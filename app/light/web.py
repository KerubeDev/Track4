"""Dependency-free local dashboard for SHIELD light mode."""
from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.light.store import LocalStore

HTML = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SHIELD</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#070b14;color:#e8eefc;font:14px Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}.wrap{max-width:1180px;margin:auto;padding:36px 22px}.top{display:flex;justify-content:space-between;align-items:end;margin-bottom:26px}.brand{font-size:26px;font-weight:750;letter-spacing:.08em}.sub{color:#7f8da8;margin-top:7px}.live{font-size:12px;color:#9fb4d9}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#6ee7b7;margin-right:7px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel{border:1px solid #172238;background:linear-gradient(180deg,#0d1422,#0a101c);border-radius:14px}.card{padding:18px}.label{color:#73819b;font-size:11px;text-transform:uppercase;letter-spacing:.12em}.num{font-size:28px;margin-top:9px;font-variant-numeric:tabular-nums}.grid{display:grid;grid-template-columns:1.3fr .7fr;gap:12px;margin-top:12px}.panel{padding:18px;min-height:310px}h2{font-size:13px;margin:0 0 16px;letter-spacing:.04em}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 7px;border-bottom:1px solid #151f31;font-size:12px}th{color:#65738d;font-weight:500}.pill{padding:4px 8px;border:1px solid #293854;border-radius:999px}.bar{height:7px;background:#182238;border-radius:9px;overflow:hidden;margin:7px 0 14px}.fill{height:100%;background:#8ba7d9}.qoe{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #151f31}.score{font-size:18px;font-variant-numeric:tabular-nums}@media(max-width:800px){.cards{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}.top{align-items:start;flex-direction:column;gap:10px}}
</style></head><body><div class="wrap"><div class="top"><div><div class="brand">SHIELD</div><div class="sub">Private DNS intelligence · local runtime</div></div><div class="live"><span class="dot"></span>LOCAL / NO CLOUD INFERENCE</div></div><div class="cards"><div class="card"><div class="label">DNS queries</div><div class="num" id="events">—</div></div><div class="card"><div class="label">Alerts</div><div class="num" id="alerts">—</div></div><div class="card"><div class="label">Alert rate</div><div class="num" id="rate">—</div></div><div class="card"><div class="label">Avg QVAC latency</div><div class="num" id="lat">—</div></div></div><div class="grid"><div class="panel"><h2>Recent detections</h2><table><thead><tr><th>Domain</th><th>Verdict</th><th>Confidence</th><th>Client</th></tr></thead><tbody id="rows"></tbody></table></div><div><div class="panel"><h2>Threat distribution</h2><div id="verdicts"></div></div><div class="panel" style="margin-top:12px;min-height:200px"><h2>Network experience</h2><div id="qoe"></div></div></div></div></div><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));async function refresh(){let d=await fetch('/api/snapshot').then(r=>r.json());events.textContent=d.events.toLocaleString();alerts.textContent=d.alerts.toLocaleString();rate.textContent=(d.events?100*d.alerts/d.events:0).toFixed(2)+'%';lat.textContent=d.avg_qvac_ms.toFixed(0)+' ms';rows.innerHTML=d.recent_alerts.map(x=>`<tr><td>${esc(x.qname)}</td><td><span class="pill">${esc(x.verdict)}</span></td><td>${Math.round(100*x.confidence)}%</td><td>${esc(x.client_ip)}</td></tr>`).join('')||'<tr><td colspan=4>No alerts yet</td></tr>';let mx=Math.max(1,...d.verdicts.map(x=>x.count));verdicts.innerHTML=d.verdicts.map(x=>`<div>${esc(x.verdict)} · ${x.count}<div class="bar"><div class="fill" style="width:${100*x.count/mx}%"></div></div></div>`).join('')||'No detections yet';qoe.innerHTML=d.qoe.slice(0,8).map(x=>`<div class="qoe"><div>${esc(x.site)}<div class="sub">${esc(x.label)}</div></div><div class="score">${x.score}</div></div>`).join('')||'No QoE windows yet'}refresh();setInterval(refresh,2000)</script></body></html>'''


def serve(db_path: str, host: str, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/api/snapshot":
                store = LocalStore(db_path)
                try: payload = json.dumps(store.snapshot(), separators=(",", ":")).encode()
                finally: store.close()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(payload); return
            if self.path in ("/", "/index.html"):
                payload = HTML.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers(); self.wfile.write(payload); return
            self.send_error(404)
        def log_message(self, *_): pass
    ThreadingHTTPServer((host, port), Handler).serve_forever()


def main(argv=None):
    p=argparse.ArgumentParser(description="Serve the SHIELD light dashboard");p.add_argument("--db",default="data/shield.db");p.add_argument("--host",default="127.0.0.1");p.add_argument("--port",type=int,default=8080);a=p.parse_args(argv);print(f"SHIELD dashboard: http://{a.host}:{a.port}");serve(a.db,a.host,a.port)
if __name__ == "__main__": main()
