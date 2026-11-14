"""Epoch-aligned, half-open [start,start+seconds) windows per client/domain."""
from collections import defaultdict
from math import isfinite

def group_dns_windows(dns_events: list[dict], seconds: int = 60) -> list[dict]:
    if type(seconds) is not int or seconds<=0:
        raise ValueError('seconds must be a positive integer')
    windows=defaultdict(list)
    for event in dns_events:
        if event.get('is_query') is not True: continue
        domain,ip=event.get('registered_domain'),event.get('src_ip')
        if not domain or not ip: continue
        try: stamp=float(event['timestamp'])
        except (KeyError,ValueError,TypeError) as exc: raise ValueError('Invalid event timestamp') from exc
        if not isfinite(stamp): raise ValueError('Event timestamp must be finite')
        start=int(stamp//seconds)*seconds
        windows[(start,ip,domain)].append(event)
    return [{'src_ip':ip,'registered_domain':domain,'window_start':float(start),
             'window_seconds':seconds,'events':sorted(events,key=lambda e:float(e['timestamp']))}
            for (start,ip,domain),events in sorted(windows.items())]
