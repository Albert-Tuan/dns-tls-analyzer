from dataclasses import replace
import math
import pytest
from app.dns.windowing import group_dns_windows
from app.tunneling.detector import DetectorConfig,analyze_windows,detect_tunnels
from app.tunneling.features import extract_tunnel_features

def event(stamp,sub='',ip='192.0.2.1'):
    return {'timestamp':stamp,'src_ip':ip,'registered_domain':'example.com','subdomain':sub,
            'qname':f'{sub}.example.com' if sub else 'example.com','qtype':'A','is_query':True}

@pytest.mark.parametrize('change',[{'window_seconds':0},{'window_seconds':True},{'min_queries':-1},
    {'high_unique_ratio':1.1},{'high_avg_entropy':float('nan')},{'alert_score':101},
    {'min_independent_signals':4},{'min_queries':40},{'long_avg_subdomain':'25'}])
def test_invalid_config(change):
    with pytest.raises(ValueError):replace(DetectorConfig(),**change)

@pytest.mark.parametrize('value',[float('nan'),float('inf'),'invalid',None])
def test_invalid_timestamp(value):
    with pytest.raises(ValueError):group_dns_windows([event(value)])

def test_sorted_across_clients():
    ws=group_dns_windows([event(65,ip='a'),event(1,ip='z')]);assert [w['window_start'] for w in ws]==[0,60]

def test_apex_queries_in_average():
    f=extract_tunnel_features({'events':[event(0,'a'*40),event(1)],'window_seconds':60})
    assert f['avg_subdomain_length']==20
    assert f['unique_subdomain_ratio']==.5

def test_shape_not_two_independent_groups():
    cfg=DetectorConfig(alert_score=50,high_query_count=100)
    ev=[event(i,'abcdefghijklmnopqrstuvwxyz0123456789') for i in range(15)]
    w=analyze_windows(ev,cfg)[0]
    assert w['score']==50 and w['signal_groups']==['shape']
    assert detect_tunnels(ev,cfg)==[]

def test_exact_threshold_boundary():
    cfg=DetectorConfig(high_query_count=30,long_avg_subdomain=25)
    ev=[event(i,f'{i:02d}'+'a'*23) for i in range(30)]
    assert len(detect_tunnels(ev,cfg))==1
    assert detect_tunnels(ev,replace(cfg,long_avg_subdomain=25.0001))==[]

def test_window_not_mutating_input():
    ev=[event(3,'x'),event(2,'y')];before=list(ev);group_dns_windows(ev);assert ev==before

def test_response_filtered_in_features():
    q=event(1);r={**q,'is_query':False};f=extract_tunnel_features({'events':[q,r]})
    assert f['query_count']==1 and f['qtype_distribution']=={'A':1}
