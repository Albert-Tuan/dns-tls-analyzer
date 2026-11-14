"""One-command reproducible acceptance workflow. No dependency installation or networking."""
import json,platform,shutil,subprocess,sys,os
from pathlib import Path
from datetime import datetime,timezone
from importlib.metadata import version
from app.tunneling.reporting import write_json

ROOT=Path(__file__).resolve().parents[1]

def main():
    os.chdir(ROOT)
    evidence=ROOT/'reports';evidence.mkdir(exist_ok=True)
    steps=[]
    def run(label,args):
        cmd=[sys.executable,*args]
        print(f'[{label}]', ' '.join(args),flush=True)
        p=subprocess.run(cmd,capture_output=True,text=True)
        (evidence/f'{label}.log').write_text(p.stdout+p.stderr,encoding='utf-8')
        print(p.stdout,end='');print(p.stderr,end='',file=sys.stderr)
        steps.append({'step':label,'command':args,'exit_code':p.returncode,'log':f'{label}.log'})
        if p.returncode:raise RuntimeError(f'{label} failed; see reports/{label}.log')
    status='failed';error=None;parity='not_run'
    try:
        run('01_generate',['-m','scripts.make_demo_pcap'])
        run('02_tests',['-m','pytest','-q','--junitxml=reports/junit.xml'])
        run('03_tune_dev',['-m','scripts.tune_thresholds','--manifest','samples/dev_manifest.json','--output','configs/frozen.json'])
        for label,name in [('04_benign','benign_dns'),('05_tunnel','synthetic_tunnel_like_dns'),('06_response','query_response')]:
            run(label,['-m','scripts.run_tv2','--pcap',f'samples/{name}.pcap','--output',f'reports/{name}.json',
                       '--csv',f'reports/{name}.csv','--events-output',f'reports/{name}_events.json','--config','configs/frozen.json'])
        run('07_eval_dev',['-m','scripts.evaluate_dataset','--manifest','samples/dev_manifest.json','--config','configs/frozen.json','--output','reports/dev_metrics.json'])
        run('08_eval_test',['-m','scripts.evaluate_dataset','--manifest','samples/test_manifest.json','--config','configs/frozen.json','--output','reports/test_metrics.json'])
        run('09_integration',['-m','examples.integrate_tv3','--pcap','samples/synthetic_tunnel_like_dns.pcap','--config','configs/frozen.json','--output','reports/tv3_fragment.json'])
        if shutil.which('tshark'):
            parity='failed'  # A failed comparison must remain visible in acceptance.json.
            for i,name in enumerate(['benign_dns.pcap','synthetic_tunnel_like_dns.pcap','query_response.pcap','ipv6_dns.pcap','dns.pcapng']):
                run(f'10_tshark_{i}',['-m','scripts.verify_tshark','--pcap',f'samples/{name}'])
            parity='passed'
        else:
            parity='pending_tshark_not_installed'
            print('TShark parity pending: install wireshark-cli and rerun this command.')
        # Sanity-check the independent CLI outputs, not just successful process exits.
        for name,queries,alerts in [('benign_dns',4,0),('synthetic_tunnel_like_dns',40,1),('query_response',1,0)]:
            r=json.loads((evidence/f'{name}.json').read_text())
            if r['summary']['dns_queries']!=queries or r['summary']['dns_tunnel_alerts']!=alerts:
                raise RuntimeError(f'Unexpected demo result for {name}')
        status='passed'
    except (RuntimeError,OSError,ValueError) as exc:
        error=str(exc);print('ERROR:',error,file=sys.stderr)
    result={'status':status,'created_at':datetime.now(timezone.utc).isoformat(),
        'python':platform.python_version(),'platform':platform.platform(),
        'dependencies':{p:version(p) for p in ['scapy','dnspython','tldextract','pytest']},
        'tshark_parity':parity,'dataset_type':'synthetic','steps':steps,'error':error,
        'integration_scope':'public contract + TV2 fragment; teammate implementations not supplied'}
    write_json(evidence/'acceptance.json',result)
    print(f'TV2 overall acceptance: {status}; TShark parity: {parity}')
    return 0 if status=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
