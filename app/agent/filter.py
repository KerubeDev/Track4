"""Bounded, explainable DNS signals and escalation rules."""
from __future__ import annotations
import math,os
from collections import defaultdict,deque
from dataclasses import dataclass
from datetime import datetime,timezone
from typing import Any,Iterable
from app.common.domain import DEFAULT_CLIENT_VOCABULARY,effective_tld_plus_one,looks_like_typosquat

def _entropy(v):
    if not v:return 0.0
    c={}
    for x in v:c[x]=c.get(x,0)+1
    n=len(v);return -sum((z/n)*math.log2(z/n) for z in c.values())
def _seconds(t:Any)->float:
    if isinstance(t,(int,float)):return float(t)
    v=str(t).strip().replace('Z','+00:00')
    if not v:raise ValueError('DNS event is missing a timestamp')
    d=datetime.fromisoformat(v);d=d if d.tzinfo else d.replace(tzinfo=timezone.utc);return d.timestamp()
@dataclass(frozen=True)
class FilterConfig:
    window_seconds:float=60.;min_window_events:int=5;nxdomain_ratio:float=.6;entropy:float=3.5;long_label:int=40;rarity:float=.2;beacon_variance:float=4.;beacon_min_gap_seconds:float=5.;beacon_window_seconds:float=600.
    @classmethod
    def from_env(cls):return cls(float(os.getenv('FILTER_WINDOW_SECONDS','60')),int(os.getenv('FILTER_MIN_WINDOW_EVENTS','5')),float(os.getenv('FILTER_NXDOMAIN_RATIO','.6')),float(os.getenv('FILTER_ENTROPY','3.5')),int(os.getenv('FILTER_LONG_LABEL','40')),float(os.getenv('FILTER_RARITY','.2')),float(os.getenv('FILTER_BEACON_VARIANCE','4')),float(os.getenv('FILTER_BEACON_MIN_GAP_SECONDS','5')),float(os.getenv('FILTER_BEACON_WINDOW_SECONDS','600')))
class DeterministicFilter:
    def __init__(self,config:FilterConfig|None=None,vocabulary:Iterable[str]|None=None):self.config=config or FilterConfig.from_env();self.vocabulary=tuple(v.lower() for v in (vocabulary or DEFAULT_CLIENT_VOCABULARY));self._windows=defaultdict(deque);self._beacons=defaultdict(deque)
    def _expire(self,now):
        for client,w in list(self._windows.items()):
            while w and w[0][0]<now-self.config.window_seconds:w.popleft()
            if not w:del self._windows[client]
        for key,w in list(self._beacons.items()):
            while w and w[0]<now-self.config.beacon_window_seconds:w.popleft()
            if not w:del self._beacons[key]
    def process(self,event):
        try:now=_seconds(event.get('ts',event.get('timestamp')))
        except (ValueError,TypeError):return None
        client=str(event.get('client_ip','')).strip();qname=str(event.get('qname','')).rstrip('.').lower()
        if not client or not qname:return None
        self._expire(now);w=self._windows[client];w.append((now,event));events=[e for _,e in w];signals={}
        if len(events)>=self.config.min_window_events:
            nx=sum(str(e.get('rcode','')).upper()=='NXDOMAIN' for e in events)/len(events)
            if nx>=self.config.nxdomain_ratio:signals['nxdomain_ratio']={'ratio':round(nx,3),'threshold':self.config.nxdomain_ratio,'samples':len(events)}
        labels=qname.split('.');label=max(labels[:-2] or labels[:1],key=len,default='');entropy=_entropy(label)
        if entropy>=self.config.entropy:signals['entropy']={'value':round(entropy,3),'threshold':self.config.entropy}
        repeated=sum(str(e.get('qname','')).rstrip('.').lower()==qname for e in events)>1
        if len(label)>self.config.long_label and entropy>self.config.entropy and repeated:signals['long_high_entropy_repetition']={'label_length':len(label),'entropy':round(entropy,3)}
        e2ld=effective_tld_plus_one(qname);cnt=sum(effective_tld_plus_one(str(e.get('qname','')))==e2ld for e in events);rarity=1/max(1,cnt);typo=next((k for k in self.vocabulary if looks_like_typosquat(e2ld,k)),None)
        if (rarity>=self.config.rarity and len(label)<=self.config.long_label) or typo:signals['rarity']={'e2ld':e2ld,'rarity':round(rarity,3),'typosquat':bool(typo),'nearest_known_domain':typo}
        bw=self._beacons[(client,qname)];bw.append(now);stamps=list(bw);gaps=[b-a for a,b in zip(stamps,stamps[1:]) if b-a>=self.config.beacon_min_gap_seconds]
        if len(gaps)>=2:
            mean=sum(gaps)/len(gaps);var=sum((g-mean)**2 for g in gaps)/len(gaps)
            if var<=self.config.beacon_variance:signals['beaconing']={'interval_variance':round(var,3),'mean_interval_seconds':round(mean,3),'intervals':len(gaps),'window_seconds':self.config.beacon_window_seconds}
        escalates=any(n in signals for n in ('nxdomain_ratio','long_high_entropy_repetition','beaconing')) or ('entropy'in signals and 'rarity'in signals) or bool(typo)
        return {'qname':qname,'client_ip':client,'signals':signals,'timestamp':event.get('ts',event.get('timestamp'))} if escalates else None
