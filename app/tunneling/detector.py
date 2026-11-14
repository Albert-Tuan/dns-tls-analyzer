"""Explainable rules. Score 0..100 is NOT a probability."""
from dataclasses import dataclass, asdict, fields
import json
from math import isfinite
from app.dns.windowing import group_dns_windows
from app.tunneling.features import extract_tunnel_features

@dataclass(frozen=True)
class DetectorConfig:
    window_seconds: int = 60
    min_queries: int = 10
    min_unique_count: int = 10
    high_query_count: int = 30
    high_unique_ratio: float = 0.8
    long_avg_subdomain: float = 25.0
    high_avg_entropy: float = 3.6
    alert_score: int = 60
    min_independent_signals: int = 2

    def __post_init__(self):
        for name in ('window_seconds','min_queries','min_unique_count','high_query_count','alert_score','min_independent_signals'):
            if type(getattr(self,name)) is not int or getattr(self,name)<=0:
                raise ValueError(f'{name} must be a positive integer')
        for name in ('high_unique_ratio','long_avg_subdomain','high_avg_entropy'):
            v=getattr(self,name)
            if type(v) not in (float,int) or not isfinite(v) or v<=0:
                raise ValueError(f'{name} must be finite and positive')
        if self.high_unique_ratio>1 or self.alert_score>100 or self.min_independent_signals>3:
            raise ValueError('Invalid ratio, score, or independent group count')
        if self.high_query_count<self.min_queries:
            raise ValueError('high_query_count must be >= min_queries')

    @classmethod
    def from_file(cls,path):
        data=json.loads(__import__('pathlib').Path(path).read_text(encoding='utf-8'))
        if not isinstance(data,dict) or set(data)-{f.name for f in fields(cls)}:
            raise ValueError('Config must be an object with known DetectorConfig keys')
        return cls(**data)

    def to_dict(self): return asdict(self)

def analyze_windows(dns_events: list[dict], config: DetectorConfig | None = None) -> list[dict]:
    cfg=config or DetectorConfig(); results=[]
    for w in group_dns_windows(dns_events,cfg.window_seconds):
        f=extract_tunnel_features(w)
        rules=[('high_query_count',f['query_count']>=cfg.high_query_count,'volume'),
               ('many_unique_subdomains',f['unique_subdomain_count']>=cfg.min_unique_count and f['unique_subdomain_ratio']>=cfg.high_unique_ratio,'diversity'),
               ('long_subdomain_labels',f['avg_subdomain_length']>=cfg.long_avg_subdomain,'shape'),
               ('high_subdomain_entropy',f['avg_subdomain_entropy']>=cfg.high_avg_entropy,'shape')]
        reasons=[name for name,active,_ in rules if active]
        groups=sorted({group for _,active,group in rules if active})
        score=25*len(reasons)
        eligible=f['query_count']>=cfg.min_queries
        suspicious=eligible and len(groups)>=cfg.min_independent_signals and score>=cfg.alert_score
        results.append({'detector':'dns_tunnel',
            'classification':'suspected_dns_tunnel' if suspicious else 'not_flagged',
            'src_ip':w['src_ip'],'registered_domain':w['registered_domain'],
            'window_start':w['window_start'],'window_seconds':w['window_seconds'],
            'score':score,'features':f,'reasons':reasons,
            'signal_groups':groups,'eligible':eligible})
    return results

def detect_tunnels(dns_events: list[dict], config: DetectorConfig | None = None) -> list[dict]:
    return [w for w in analyze_windows(dns_events,config) if w['classification']=='suspected_dns_tunnel']
