"""Shared DNS-domain primitives used by production and simulation code."""
from __future__ import annotations

DEFAULT_CLIENT_VOCABULARY=("microsoft.com","google.com","googleapis.com","apple.com","spotify.com","shodan.io","banco-pa.example","banco-col.example","gob-pa.example","hosp-pa.example")

def edit_distance(a:str,b:str,max_distance:int=2)->int:
    """Levenshtein distance with an early cutoff suitable for short domains."""
    if a==b:return 0
    if abs(len(a)-len(b))>max_distance:return max_distance+1
    prev=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        cur=[i]
        row_min=i
        for j,cb in enumerate(b,1):
            value=min(cur[-1]+1,prev[j]+1,prev[j-1]+(ca!=cb)); cur.append(value); row_min=min(row_min,value)
        if row_min>max_distance:return max_distance+1
        prev=cur
    return prev[-1]

def edit_distance_at_most_one(a:str,b:str)->bool:return edit_distance(a,b,1)<=1

def looks_like_typosquat(candidate:str,known:str)->bool:
    """Catch one-edit variants plus a single adjacent transposition."""
    if candidate==known:return False
    if edit_distance(candidate,known,1)<=1:return True
    if len(candidate)==len(known):
        diffs=[i for i,(x,y) in enumerate(zip(candidate,known)) if x!=y]
        if len(diffs)==2 and diffs[1]==diffs[0]+1:
            i,j=diffs; return candidate[i]==known[j] and candidate[j]==known[i]
    return False

def effective_tld_plus_one(qname:str)->str:
    labels=[x for x in qname.rstrip('.').lower().split('.') if x]
    return '.'.join(labels[-2:]) if len(labels)>=2 else (labels[0] if labels else '')
