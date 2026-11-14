import json,subprocess,sys
from copy import deepcopy
from pathlib import Path
import pytest
from scripts.make_demo_pcap import generate
from app.tunneling.detector import DetectorConfig
from app.tunneling.reporting import analyze_pcap
from app.tunneling.evaluation import load_dataset,evaluate_loaded,metrics
from scripts.tune_thresholds import main as tune
from examples.integrate_tv3 import build_tv2_fragment

@pytest.fixture(scope='module')
def data(tmp_path_factory):
    p=tmp_path_factory.mktemp('dataset');generate(p);return p

@pytest.mark.parametrize('name,queries,alerts',[
    ('benign_dns.pcap',4,0),('synthetic_tunnel_like_dns.pcap',40,1),
    ('query_response.pcap',1,0),('empty.pcap',0,0),('no_dns.pcap',0,0),
    ('ipv6_dns.pcap',1,0),('dns.pcapng',4,0)])
def test_pipeline_cases(data,name,queries,alerts):
    r=analyze_pcap(data/name);assert r['summary']['dns_queries']==queries
    assert r['summary']['dns_tunnel_alerts']==alerts
    json.dumps(r,allow_nan=False)

def test_evaluation_truth(data):
    m,loaded=load_dataset(data/'test_manifest.json');r=evaluate_loaded(m,loaded,DetectorConfig())
    assert r['metrics']['n']==21
    assert r['metrics']['fp']>0 and r['metrics']['fn']>0
    assert r['metrics']['tp']+r['metrics']['fn']==9
    assert r['metrics']['tn']+r['metrics']['fp']==12

def test_label_coverage_strict(data):
    m,loaded=load_dataset(data/'test_manifest.json');loaded=deepcopy(loaded)
    loaded[0][2].pop(next(iter(loaded[0][2])))
    with pytest.raises(ValueError,match='coverage'):evaluate_loaded(m,loaded,DetectorConfig())

def test_window_mismatch(data):
    m,loaded=load_dataset(data/'test_manifest.json')
    with pytest.raises(ValueError):evaluate_loaded(m,loaded,DetectorConfig(window_seconds=120))

def test_no_tune_on_test(data,tmp_path):
    assert tune(['--manifest',str(data/'test_manifest.json'),'--output',str(tmp_path/'c.json')])==2
    assert not (tmp_path/'c.json').exists()

def test_tune_dev_and_freeze(data,tmp_path):
    target=tmp_path/'frozen.json'
    assert tune(['--manifest',str(data/'dev_manifest.json'),'--output',str(target)])==0
    cfg=DetectorConfig.from_file(target)
    m,loaded=load_dataset(data/'test_manifest.json');r=evaluate_loaded(m,loaded,cfg)
    assert r['split']=='test'

def test_missing_metrics_denominators():
    assert metrics([])['precision'] is None
    assert metrics([{'true_label':'benign','predicted_label':'benign'}])['recall'] is None

def test_cli_export(data,tmp_path):
    result=subprocess.run([sys.executable,'-m','scripts.run_tv2','--pcap',str(data/'synthetic_tunnel_like_dns.pcap'),
        '--output',str(tmp_path/'report.json'),'--csv',str(tmp_path/'windows.csv'),
        '--events-output',str(tmp_path/'events.json')],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert len(json.loads((tmp_path/'events.json').read_text()))==40
    assert json.loads((tmp_path/'report.json').read_text())['summary']['dns_tunnel_alerts']==1
    assert 'classification' in (tmp_path/'windows.csv').read_text()

def test_cli_bad_input_controlled(tmp_path):
    result=subprocess.run([sys.executable,'-m','scripts.run_tv2','--pcap',str(tmp_path/'missing.pcap'),
         '--output',str(tmp_path/'report.json')],capture_output=True,text=True)
    assert result.returncode==2 and 'ERROR' in result.stderr and 'Traceback' not in result.stderr

def test_cli_prevents_input_overwrite(data):
    p=data/'benign_dns.pcap';before=p.read_bytes()
    result=subprocess.run([sys.executable,'-m','scripts.run_tv2','--pcap',str(p),'--output',str(p)],capture_output=True)
    assert result.returncode==2 and p.read_bytes()==before

def test_integration_public_schema(data):
    from app.dns.parser import parse_dns_pcap
    from app.dns.windowing import group_dns_windows
    from app.tunneling.features import extract_tunnel_features
    from app.tunneling.detector import detect_tunnels
    events=parse_dns_pcap(str(data/'synthetic_tunnel_like_dns.pcap'))
    required={'timestamp','src_ip','dst_ip','dns_id','is_query','qname','registered_domain','subdomain','qtype','rcode','packet_length','frame_number'}
    assert required<=events[0].keys()
    features=extract_tunnel_features(group_dns_windows(events)[0]);assert features['query_count']==40
    alerts=detect_tunnels(events);assert 0<=alerts[0]['score']<=100
    same,fragment=build_tv2_fragment(str(data/'synthetic_tunnel_like_dns.pcap'))
    assert same==events and fragment['dns_tunnel_findings']==alerts

def test_manifest_hash_rejects_modified_capture(data,tmp_path):
    m=json.loads((data/'test_manifest.json').read_text());m['captures'][0]['path']=str(data/'test.pcap')
    m['captures'][0]['sha256']='0'*64;p=tmp_path/'m.json';p.write_text(json.dumps(m))
    with pytest.raises(ValueError,match='SHA256'):load_dataset(p)


def test_evaluation_output_cannot_be_csv(data,tmp_path):
    from scripts.evaluate_dataset import main
    out=tmp_path/'output.csv'
    assert main(['--manifest',str(data/'test_manifest.json'),'--output',str(out)])==2
    assert not out.exists()

def test_fixture_reproducible(data,tmp_path):
    from app.tunneling.reporting import file_sha256
    generate(tmp_path)
    for name in ['benign_dns.pcap','synthetic_tunnel_like_dns.pcap','dev.pcap','test.pcap','no_dns.pcap','dns.pcapng']:
        assert file_sha256(data/name)==file_sha256(tmp_path/name)
