"""Bounded, explainable DNS signals and escalation rules."""
from __future__ import annotations
import math, os
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from app.common.domain import DEFAULT_CLIENT_VOCABULARY, edit_distance_at_most_one, effective_tld_plus_one

def _entropy(value: str) -> float:
    if not value:return 0.0
    counts={}
    for c in value: counts[c]=counts.get(c,0)+1
    n=len(value); return -sum((v/n)*math.log2(v/n) for v in counts.values())

def _seconds(timestamp: Any) -> float:
    if isinstance(timestamp,(int,float)): return float(timestamp)
    value=str(timestamp).strip().replace("Z","+00:00")
    if not value: raise ValueError("DNS event is missing a timestamp")
    parsed=datetime.fromisoformat(value)
    if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()

@dataclass(frozen=True)
class FilterConfig:
    window_seconds: float=60.0; min_window_events:int=5; nxdomain_ratio:float=.6; entropy:float=3.5; long_label:int=40; rarity:float=.2; beacon_variance:float=4.0; beacon_min_gap_seconds:float=5.0; beacon_window_seconds:float=600.0
    @classmethod
    def from_env(cls):
        return cls(float(os.getenv("FILTER_WINDOW_SECONDS","60")),int(os.getenv("FILTER_MIN_WINDOW_EVENTS","5")),float(os.getenv("FILTER_NXDOMAIN_RATIO","0.6")),float(os.getenv("FILTER_ENTROPY","3.5")),int(os.getenv("FILTER_LONG_LABEL","40")),float(os.getenv("FILTER_RARITY","0.2")),float(os.getenv("FILTER_BEACON_VARIANCE","4")),float(os.getenv("FILTER_BEACON_MIN_GAP_SECONDS","5")),float(os.getenv("FILTER_BEACON_WINDOW_SECONDS","600")))

class DeterministicFilter:
    def __init__(self,config:FilterConfig|None=None,vocabulary:Iterable[str]|None=None):
        self.config=config or FilterConfig.from_env(); self.vocabulary=tuple(v.lower() for v in (vocabulary or DEFAULT_CLIENT_VOCABULARY)); self._windows=defaultdict(deque); self._beacons=defaultdict(deque); self._last_seen={}
    def _expire(self,now:float):
        cutoff=now-self.config.window_seconds
        for client,w in list(self._windows.items()):
            while w and w[0][0]<cutoff:w.popleft()
            if not w: del self._windows[client]
        bcut=now-self.config.beacon_window_seconds
        for key,w in list(self._beacons.items()):
            while w and w[0]<bcut:w.popleft()
            if not w: del self._beacons[key]
        stale=now-self.config.beacon_window_seconds
        for client,seen in list(self._last_seen.items()):
            if seen<stale:self._last_seen.pop(client,None)
    def process(self,event:dict)->dict|None:
        try: now=_seconds(event.get("ts",event.get("timestamp")))
        except (ValueError,TypeError): return None
        client_ip=str(event.get("client_ip","")).strip(); qname=str(event.get("qname","")).rstrip(".").lower()
        if not client_ip or not qname:return None
        self._expire(now); self._last_seen[client_ip]=now; w=self._windows[client_ip]; w.append((now,event)); events=[e for _,e in w]; signals={}
        if len(events)>=self.config.min_window_events:
            nx=sum(str(e.get("rcode","")).upper()=="NXDOMAIN" for e in events)/len(events)
            if nx>=self.config.nxdomain_ratio:signals["nxdomain_ratio"]={"ratio":round(nx,3),"threshold":self.config.nxdomain_ratio,"samples":len(events)}
        labels=qname.split("."); label=max(labels[:-2] or labels[:1],key=len,default="")
        entropy=_entropy(label)
        if entropy>=self.config.entropy:signals["entropy"]={"value":round(entropy,3),"threshold":self.config.entropy}
        repeated=sum(str(e.get("qname","")).rstrip(".").lower()==qname for e in events)>1
        if len(label)>self.config.long_label and entropy>self.config.entropy and repeated:signals["long_high_entropy_repetition"]={"label_length":len(label),"entropy":round(entropy,3)}
        e2ld=effective_tld_plus_one(qname); e2ld_count=sum(effective_tld_plus_one(str(e.get("qname","")))==e2ld for e in events); rarity=1/max(1,e2ld_count)
        typo=next((known for known in self.vocabulary if e2ld!=known and edit_distance_at_most_one(e2ld,known)),None)
        if (rarity>=self.config.rarity and len(label)<=self.config.long_label) or typo:signals["rarity"]={"e2ld":e2ld,"rarity":round(rarity,3),"typosquat":bool(typo),"nearest_known_domain":typo}
        bw=self._beacons[(client_ip,qname)]; bw.append(now); gaps=[b-a for a,b in zip(bw,bw)[1:]] if False else [b-a for a,b in zip(list(bw),list(bw)[1:])]; gaps=[g for g in gaps if g>=self.config.beacon_min_gap_seconds]
        if len(gaps)>=2:
            mean=sum(gaps)/len(gaps); variance=sum((g-mean)**2 for g in gaps)/len(gaps)
            if variance<=self.config.beacon_variance:signals["beaconing"]={"interval_variance":round(variance,3),"mean_interval_seconds":round(mean,3),"intervals":len(gaps),"window_seconds":self.config.beacon_window_seconds}
        escalates=any(n in signals for n in ("nxdomain_ratio","long_high_entropy_repetition","beaconing")) or ("entropy" in signals and "rarity" in signals) or bool(typo)
        if not escalates:return None
        return {"qname":qname,"client_ip":client_ip,"signals":signals,"timestamp":event.get("ts",event.get("timestamp"))}
