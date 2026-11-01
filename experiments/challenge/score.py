#!/usr/bin/env python3
"""Gate reporting is conservative: missing scope is never a passing gate."""
import argparse,json,statistics,math
from pathlib import Path
GATES={'merge_first':('First-level mixed merge median',1,'s'),'merge_node':('Node mixed merge median',1,'s'),'root':('Complete root acceptance at 1, 2, 3 applications',10,'ms per identity'),'wallet_ram':('Wallet peak RAM',1073741824,'bytes'),'wallet_bytes':('Complete wallet certificate',300000,'bytes'),'admission':('Incoming proof admission',20,'ms'),'setup_time':('Setup per application including compilation',60,'s'),'setup_key':('Retained application key',67108864,'bytes'),'rejections':('Coordinator verifier-target rejection corpus',None,None),'upgrade':('Independent bit-level unchanged-generator upgrade',None,None)}

def component_receipts(entry, values):
 errors=[];required=list(values)
 for component in required:
  paths=entry.get('score_component_evidence',{}).get(component,[])
  if not isinstance(paths,list) or len(paths)<10:errors.append(component+': ten complete raw receipts required');continue
  if len(set(paths))!=len(paths):errors.append(component+': duplicate receipt references')
  times=[];rounds=set()
  for name in paths:
   try:
    receipt=json.loads(Path(name).read_text());labels=receipt.get('labels',{});wall=receipt.get('wall_s');files=receipt.get('forwarded_files',[])
    if receipt.get('returncode')!=0 or not isinstance(wall,(int,float)) or not math.isfinite(wall) or wall<0:raise ValueError('unsuccessful or invalid timing')
    if labels.get('score_component')!=component or labels.get('mode')!='warm' or labels.get('fresh') is not True or labels.get('complete_transport') is not True:raise ValueError('missing scored fresh complete scope')
    if component in ['first_A_B','node_AB_AH'] and labels.get('independent_children') is not True:raise ValueError('independent children absent')
    if not files:raise ValueError('forwarded files absent')
    for f in files:
     path=Path(f['path'])
     if not path.is_file() or path.stat().st_size!=f['bytes']:raise ValueError('missing or changed forwarded file')
     import hashlib
     if hashlib.sha256(path.read_bytes()).hexdigest()!=f['sha256']:raise ValueError('forwarded hash mismatch')
    times.append(wall);rounds.add(labels.get('round'))
   except (OSError,ValueError,KeyError,TypeError) as exc:errors.append(component+': '+str(exc))
  if len(rounds)<5:errors.append(component+': five rounds required')
  if times and (not isinstance(values[component],(int,float)) or not math.isclose(statistics.median(times),values[component],rel_tol=1e-9,abs_tol=1e-9)):errors.append(component+': declared median differs from receipts')
 return errors

def evaluate(entry):
 rows=[]
 for key,(name,limit,unit) in GATES.items():
  evidence=entry.get('gates',{}).get(key,{})
  status=evidence.get('status','not measurable')
  if status not in ['pass','fail','not measurable']:raise ValueError('invalid gate status')
  if status=='pass' and not evidence.get('scope_complete',False):status='not measurable'
  if status=='pass':
   paths=evidence.get('evidence',[])
   if isinstance(paths,str):paths=[paths]
   if not paths or not all(Path(p).exists() for p in paths):status='not measurable'
  if status=='not measurable':binding='uncalibrated'
  elif status=='fail':binding='binding'
  else:binding=evidence.get('calibration','non-binding')
  row={'id':key,'gate':name,'status':status,'calibration':binding,'limit':limit,'unit':unit,**{k:v for k,v in evidence.items() if k not in ['status','calibration']}}
  if key.startswith('merge_') and not entry.get('both_matched_keccak_protocols',False):
   row['enforced']=False
   if row['status']=='fail':row['calibration']='uncalibrated'
   row['reason_gate_deferred']='1 s gate deferred until both systems have matched Keccak protocols'
  else:row['enforced']=True
  rows.append(row)
 components=entry.get('score_components',{})
 required=['wallet_A','wallet_B','first_A_B','node_AB_AH']
 values={k:components.get(k) for k in required}
 measurable=all(isinstance(v,(float,int)) and math.isfinite(v) and v>=0 for v in values.values())
 receipt_errors=component_receipts(entry,values) if measurable else ['Required scored component missing']
 prereqs=entry.get('prerequisites',{})
 eligible=all(r['status']=='pass' or not r['enforced'] for r in rows) and all(prereqs.get(k)=='pass' for k in ['protocol_hash','security','frozen_aggregate_key','fresh_inputs','statement_parity','held_out_admission'])
 return {'entry':entry['id'],'protocol_hash':entry.get('protocol_hash'),'score_s':sum(values.values()) if measurable and not receipt_errors else None,'score_components':values,'eligible':eligible and measurable and not receipt_errors,'score_receipt_errors':receipt_errors,'gates':rows,'prerequisites':prereqs,'cost_vector':entry.get('cost_vector',{}),'score_note':'No substitution of a Merkle control merge for the required A+B or three-application node component'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('evidence');ap.add_argument('out');a=ap.parse_args();data=json.loads(Path(a.evidence).read_text());results=[evaluate(e) for e in data['entries']];Path(a.out).write_text(json.dumps({'scoreboards':results},indent=2)+'\n');print(json.dumps(results))
if __name__=='__main__':main()
