#!/usr/bin/env python3
"""Assemble conservative machine-readable calibration gates from retained receipts."""
import json
from pathlib import Path
from harness import TRIAL
from summarize import summarize
from score import evaluate

def main():
 entries=[]
 for protocol in ['blake2s','keccak']:
  wallet=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab');merges=TRIAL/('complete-merges-'+protocol);admission=TRIAL/('admission-'+protocol)
  summaries={}
  for label,path in [('wallet',wallet),('merge_controls',merges),('admission',admission)]:
   if path.exists():
    rows=summarize(path);(path/'summary.json').write_text(json.dumps(rows,indent=2)+'\n');summaries[label]=rows
  for system in ['r1cs','vm']:
   ws=[r for r in summaries.get('wallet',[]) if r['system']==system];ads=[r for r in summaries.get('admission',[]) if r['system']==system];ms=[r for r in summaries.get('merge_controls',[]) if r['system']==system]
   def gate(status,paths,**kw):return {'status':status,'scope_complete':status!='not measurable','evidence':[str(p) for p in paths],**kw}
   wcomplete=(wallet/'done.json').exists() and len(ws)==4 and all(r['successes']==r['n']==10 for r in ws)
   peak=max((r['peak_rss_max_bytes'] for r in ws),default=0);size=max((r['file_bytes_max'] or 0 for r in ws),default=0)
   admission_complete=(admission/'done.json').exists() and len(ads)==2 and all(r['successes']==r['n']==10 for r in ads)
   admission_max_median=max((r['external_median_s']*1000 for r in ads),default=0)
   gates={
    'wallet_ram':gate('pass' if peak<=2**30 else 'fail',[wallet/'summary.json'],max_observed_bytes=peak) if wcomplete else gate('not measurable',[]),
    'wallet_bytes':gate('pass' if size<=300000 else 'fail',[wallet/'summary.json'],max_observed_bytes=size) if wcomplete else gate('not measurable',[]),
    'merge_first':gate('not measurable',[merges/'summary.json'],reason='Controls do not establish matched A+B under a common application-independent aggregate key'),
    'merge_node':gate('not measurable',[merges/'summary.json'],reason='Required independent AB+AH node unavailable; VM duplicates a child and R1CS is shielded+Merkle'),
    'root':gate('not measurable',[merges/'summary.json'],reason='Complete control roots measured; no 1/2/3 real-application series and identity denominator ambiguous'),
    'admission':gate('not measurable' if admission_max_median<=20 else 'fail',[admission/'summary.json'],max_case_external_median_ms=admission_max_median,scope_note='Wallet A/B observations only; merge-certificate admission and consumer validity semantics separate; no full admission pass claimed') if admission_complete else gate('not measurable',[]),
    'setup_time':gate('not measurable',[wallet/'provenance.json'],reason='Compiler/setup stage reported but public-generator-only setup and retained-key cold separation not established'),
    'setup_key':gate('not measurable',[wallet/'provenance.json'],reason='Complete application retained-key export not available'),
    'rejections':gate('not measurable',[TRIAL/'certificate-rejections/coverage.json'],reason='Partial direct verifier-target regressions only; full coordinator corpus unavailable'),
    'upgrade':gate('not measurable',[],reason='Independent hashed bit-level reference backend not supplied')}
   def warm(case):return next((r['external_median_s'] for r in ws if r['case']==case and r['mode']=='warm'),None)
   entries.append({'id':system+'-'+protocol,'protocol_hash':protocol,'both_matched_keccak_protocols':False,'gates':gates,'score_components':{'wallet_A':warm('A'),'wallet_B':warm('B'),'first_A_B':None,'node_AB_AH':None},'prerequisites':{'protocol_hash':'pass' if protocol=='keccak' else 'fail','security':'not measurable','frozen_aggregate_key':'not measurable','fresh_inputs':'pass' if wcomplete else 'not measurable','statement_parity':'not measurable','held_out_admission':'not measurable'},'cost_vector':{'wallet':ws,'merge_controls':ms,'cold_merge_controls':[r for r in json.loads((TRIAL/'cold-complete-merges/summary.json').read_text()) if r['system']==system and r['protocol_hash']==protocol] if (TRIAL/'cold-complete-merges/summary.json').exists() else [],'admission':ads,'cadence':{s:json.loads((merges/f'cadence-{s}/summary.json').read_text()) for s in [system] if (merges/f'cadence-{s}/summary.json').exists()}},'scope':'Calibration controls, no competition winner'})
 for entrant in ['entry-2','entry-4','entry-5','entry-6','entry-7','entry-8']:
  folder=TRIAL/('entry-6-external-referee' if entrant=='entry-6' else entrant+'-referee')
  if not folder.exists():continue
  m=json.loads((TRIAL/'freezes'/entrant/'manifest.json').read_text());rows=summarize(folder);(folder/'summary.json').write_text(json.dumps(rows,indent=2)+'\n');done=json.loads((folder/'done.json').read_text()) if (folder/'done.json').exists() else {};protocol='blake2s' if entrant=='entry-2' else 'keccak';gates={key:{'status':'not measurable','scope_complete':False,'reason':'Mandatory Falcon and exact A+B tree missing; local/held-out observations retained','evidence':[str(folder/'summary.json')]} for key in ['merge_first','merge_node','root','wallet_ram','wallet_bytes','admission','setup_time','setup_key','rejections','upgrade']}
  observed_wallets=[r for r in rows if r['case'].startswith('wallet')];peak=max((r['peak_rss_max_bytes'] for r in observed_wallets),default=0)
  if entrant!='entry-2' and peak>2**30:gates['wallet_ram']={'status':'fail','scope_complete':True,'max_observed_bytes':peak,'evidence':[str(folder/'summary.json')],'scope_note':'Observed A/held-out wallet requests exceed cap; Falcon unavailable'}
  setup_files=list(folder.glob('setup-*-retained.json'));setup_records=[json.loads(p.read_text()) for p in setup_files]
  if setup_records and max(r['total_bytes'] for r in setup_records)>2**26:gates['setup_key']={'status':'fail','scope_complete':True,'max_application_retained_bytes':max(r['total_bytes'] for r in setup_records),'evidence':list(map(str,setup_files)),'scope_note':'Per-application files exceed cap independently of shared aggregate state'}
  values=[]
  for path in folder.rglob('sample.json'):
   j=json.loads(path.read_text())
   if j.get('labels',{}).get('mode')=='warm' and any(x.get('phase')=='wallet' and x.get('case')=='shielded' for x in j.get('reported',[])):values.append(j['wall_s'])
  frozen=done.get('frozen_surface',{}).get('unchanged',False)
  entries.append({'id':entrant,'protocol_hash':protocol,'both_matched_keccak_protocols':False,'gates':gates,'score_components':{'wallet_A':__import__('statistics').median(values) if values and entrant!='entry-2' else None,'wallet_B':None,'first_A_B':None,'node_AB_AH':None},'prerequisites':{'protocol_hash':'pass' if protocol=='keccak' else 'fail','security':'not measurable','frozen_aggregate_key':'pass' if frozen else 'not measurable','fresh_inputs':'pass' if done and not done.get('failures') else 'not measurable','statement_parity':'not measurable','held_out_admission':'not measurable'},'cost_vector':{'observed_control_rows':rows,'aggregate_retained_bytes':m['aggregate_key']['retained_bytes'],'application_retention':setup_records,'completed':bool(done)},'scope':'Entrant structural calibration only; finite known decoder pool; full Falcon and required tree unavailable'})
 (TRIAL/'score-evidence.json').write_text(json.dumps({'entries':entries},indent=2)+'\n')
 (TRIAL/'scoreboard.json').write_text(json.dumps({'scoreboards':[evaluate(e) for e in entries]},indent=2)+'\n')
 print(json.dumps([{'entry':e['id'],'eligible':evaluate(e)['eligible'],'score_s':evaluate(e)['score_s']} for e in entries]))
if __name__=='__main__':main()
