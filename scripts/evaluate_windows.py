"""Legacy CSV helper, kept for old commands; prefer evaluate_dataset for trusted predictions."""
import argparse,csv,json
from app.tunneling.evaluation import metrics

def main():
    p=argparse.ArgumentParser(description='Metrics from externally supplied predictions; does not verify provenance')
    p.add_argument('--csv',required=True);a=p.parse_args()
    with open(a.csv,encoding='utf-8',newline='') as f:rows=list(csv.DictReader(f))
    for row in rows:
        if row.get('true_label') not in ('benign','tunnel') or row.get('predicted_label') not in ('benign','tunnel'):
            p.error('CSV requires true_label,predicted_label with benign/tunnel values')
    print(json.dumps(metrics(rows),allow_nan=False,indent=2))
if __name__=='__main__':main()
