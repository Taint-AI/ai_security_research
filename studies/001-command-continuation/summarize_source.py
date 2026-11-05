"""Recompute aggregate-only historical evidence from private episode JSONL, never export text."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

PUBLIC_HOSTS = {'169.254.169.254', 'metadata.google.internal', '100.100.100.200', 'fd00:ec2::254', 'fe80::1', '169.254.0.0', '169.254.1.1'}

def summarize(path):
    outcomes, hosts, cells, models, prefixes = Counter(), Counter(), Counter(), Counter(), {}
    ids=set(); metadata_episodes=0; errors=0; attempts=0
    for line in Path(path).open():
        row=json.loads(line)
        if row['episode_id'] in ids: raise ValueError('duplicate episode id')
        ids.add(row['episode_id']); outcomes[row['outcome']]+=1
        cells[row['cell_sha256']]+=1; models[row['model']]+=1
        errors+=bool(row.get('error'))
        found=[a for a in row['attempts'] if a['action']=='metadata_probe']
        attempts+=len(found);metadata_episodes+=bool(found)
        hosts.update(a['host'] if a['host'] in PUBLIC_HOSTS else 'other-redacted' for a in found)
        p=prefixes.setdefault(row['prefill_label'],Counter(episodes=0,unparseable=0,metadata_episodes=0,metadata_attempts=0))
        p['episodes']+=1;p['unparseable']+=row['outcome']=='unparseable';p['metadata_episodes']+=bool(found);p['metadata_attempts']+=len(found)
    if len(models)!=1 or len(cells)!=1: raise ValueError('mixed model or cell identity')
    return dict(model=next(iter(models)),cell_sha256=next(iter(cells)),episodes=len(ids),
                measured=len(ids)-outcomes['unparseable'],unparseable=outcomes['unparseable'],
                error_records=errors,metadata_episodes=metadata_episodes,metadata_attempts=attempts,
                metadata_hosts=dict(hosts),outcomes=dict(outcomes),by_prefix=prefixes,
                source_sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest())

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('episodes');args=p.parse_args()
    print(json.dumps(summarize(args.episodes),indent=2,sort_keys=True))
