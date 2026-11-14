"""Raw feature precision is retained for decisions; rounding belongs to presentation."""
from collections import Counter
from math import log2
from statistics import mean, pstdev

def shannon_entropy(value: str) -> float:
    value=value.lower()
    if not value: return 0.0
    return -sum((n/len(value))*log2(n/len(value)) for n in Counter(value).values())

def extract_tunnel_features(window: dict) -> dict:
    events=[e for e in window['events'] if e.get('is_query') is True]
    n=len(events)
    subs=[str(e.get('subdomain') or '') for e in events]
    lengths=[len(s.replace('.','')) for s in subs]
    entropies=[shannon_entropy(s.replace('.','')) for s in subs]
    unique=len(set(s for s in subs if s))
    times=sorted(float(e['timestamp']) for e in events)
    intervals=[b-a for a,b in zip(times,times[1:])]
    qtypes=Counter(str(e.get('qtype','UNKNOWN')).upper() for e in events)
    avg_iat=mean(intervals) if intervals else None
    return {'query_count':n,'unique_qnames':len(set(e.get('qname') for e in events)),
        'unique_subdomain_count':unique,'unique_subdomain_ratio':unique/n if n else 0.0,
        'avg_subdomain_length':mean(lengths) if n else 0.0,
        'max_subdomain_length':max(lengths,default=0),
        'avg_subdomain_entropy':mean(entropies) if n else 0.0,
        'qtype_distribution':dict(sorted(qtypes.items())),
        'txt_ratio':qtypes['TXT']/n if n else 0.0,
        'queries_per_second':n/window.get('window_seconds',60),
        'mean_interarrival_seconds':avg_iat,
        'interarrival_cv':pstdev(intervals)/avg_iat if avg_iat and intervals else None,
        'nxdomain_ratio':None}
