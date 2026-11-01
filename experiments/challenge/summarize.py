#!/usr/bin/env python3
import argparse,json,statistics
from pathlib import Path

def summarize(root):
 groups={}
 for f in Path(root).rglob('sample.json'):
  j=json.loads(f.read_text());l=j.get('labels',{})
  if not all(k in l for k in ['system','case','mode']):continue
  key=(l['system'],l['case'],l['mode'],l.get('protocol_hash') or 'unspecified');groups.setdefault(key,[]).append((f,j))
 result=[]
 for k,items in sorted(groups.items()):
  rs=[j for _,j in items];times=[r['wall_s'] for r in rs];ram=[r['process_group_peak_rss_bytes'] for r in rs];bs=[r['forwarded_bytes'] for r in rs if r.get('forwarded_bytes') is not None]
  row={'system':k[0],'case':k[1],'mode':k[2],'protocol_hash':None if k[3]=='unspecified' else k[3],'n':len(rs),'successes':sum(r['returncode']==0 for r in rs),'external_median_s':statistics.median(times),'external_min_s':min(times),'external_max_s':max(times),'external_relative_range':(max(times)-min(times))/statistics.median(times),'peak_rss_median_bytes':statistics.median(ram),'peak_rss_max_bytes':max(ram),'file_bytes_median':statistics.median(bs) if bs else None,'file_bytes_max':max(bs) if bs else None,'max_rss_sample_gap_s':max(r.get('rss_max_gap_s',0) for r in rs),'evidence':[str(f) for f,_ in items],'reported_metrics':{}}
  for metric in ['seconds','wallet_prove_s','merge_s','setup_s','verify_ms','complete_root_ms','own_settle_ms','first_complete_root_ms','leaf_complete_root_ms','statement_bytes','proof_bytes','carried_bytes','native_child_checks_s']:
   vals=[o[metric] for r in rs for o in r.get('reported',[]) if isinstance(o,dict) and isinstance(o.get(metric),(int,float))]
   if vals:row['reported_metrics'][metric]={'median':statistics.median(vals),'min':min(vals),'max':max(vals),'n':len(vals)}
  result.append(row)
 return result
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('root');ap.add_argument('--out',required=True);a=ap.parse_args();r=summarize(a.root);Path(a.out).write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'groups':len(r),'samples':sum(g['n'] for g in r)}))
