"""Window-level evaluation from capture+host+domain+epoch labels; strict coverage."""
import json
from pathlib import Path
from math import isfinite
from .reporting import file_sha256
from .detector import analyze_windows
from app.dns.parser import parse_dns_pcap_detailed

def metrics(rows):
    tp=sum(r['true_label']=='tunnel' and r['predicted_label']=='tunnel' for r in rows)
    fp=sum(r['true_label']=='benign' and r['predicted_label']=='tunnel' for r in rows)
    tn=sum(r['true_label']=='benign' and r['predicted_label']=='benign' for r in rows)
    fn=sum(r['true_label']=='tunnel' and r['predicted_label']=='benign' for r in rows)
    ratio=lambda a,b:a/b if b else None
    return {'n':len(rows),'tp':tp,'fp':fp,'tn':tn,'fn':fn,'precision':ratio(tp,tp+fp),
            'recall':ratio(tp,tp+fn),'f1':ratio(2*tp,2*tp+fp+fn),'false_positive_rate':ratio(fp,fp+tn)}

def load_dataset(manifest_path):
    path=Path(manifest_path);manifest=json.loads(path.read_text(encoding='utf-8'))
    if manifest.get('split') not in ('dev','test') or manifest.get('dataset_type') not in ('synthetic','real'):
        raise ValueError('Manifest requires split dev/test and dataset_type synthetic/real')
    seconds=manifest.get('window_seconds')
    if type(seconds) is not int or seconds<=0: raise ValueError('Invalid manifest window_seconds')
    captures=manifest.get('captures')
    if not isinstance(captures,list) or not captures: raise ValueError('Manifest has no captures')
    loaded=[];seen_paths=set()
    for capture in captures:
        capture_path=(path.parent/capture['path']).resolve()
        if capture_path in seen_paths: raise ValueError('Duplicate capture path')
        seen_paths.add(capture_path)
        if capture.get('sha256')!=file_sha256(capture_path): raise ValueError('Capture SHA256 mismatch')
        labels={}
        for label in capture['labels']:
            start=float(label['window_start'])
            if not isfinite(start) or start%seconds or label['label'] not in ('benign','tunnel'):
                raise ValueError('Invalid label/window alignment')
            if not label.get('provenance'): raise ValueError('Each label requires provenance')
            key=(label['src_ip'],label['registered_domain'],start)
            if key in labels: raise ValueError('Duplicate ground truth window')
            labels[key]=label
        if not labels: raise ValueError('Capture has no labelled windows')
        parsed=parse_dns_pcap_detailed(str(capture_path))
        loaded.append((capture['path'],parsed,labels))
    return manifest,loaded

def evaluate_loaded(manifest,loaded,config):
    if manifest['window_seconds']!=config.window_seconds:
        raise ValueError('Config window size differs from ground truth')
    rows=[];warnings=[]
    for name,parsed,labels in loaded:
        windows=analyze_windows(parsed.events,config)
        observed={(w['src_ip'],w['registered_domain'],w['window_start']):w for w in windows}
        if observed.keys()!=labels.keys():
            missing=set(labels)-set(observed);unlabelled=set(observed)-set(labels)
            raise ValueError(f'Label coverage mismatch: missing={len(missing)}, unlabelled={len(unlabelled)}')
        warnings.extend({'capture':name,**w} for w in parsed.warnings)
        for key,label in labels.items():
            w=observed[key]
            rows.append({'capture':name,'src_ip':key[0],'registered_domain':key[1],'window_start':key[2],
                'scenario':label.get('scenario','unspecified'),'true_label':label['label'],
                'predicted_label':'tunnel' if w['classification']=='suspected_dns_tunnel' else 'benign',
                'score':w['score'],'query_count':w['features']['query_count'],'reasons':';'.join(w['reasons'])})
    return {'dataset_type':manifest['dataset_type'],'split':manifest['split'],
            'window_seconds':config.window_seconds,'config':config.to_dict(),'metrics':metrics(rows),
            'rows':rows,'warnings':warnings,
            'interpretation':'not_flagged is not a benign verdict; predicted_label benign is evaluation shorthand'}
