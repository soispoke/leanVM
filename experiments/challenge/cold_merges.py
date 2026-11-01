#!/usr/bin/env python3
"""Combined setup/process-cold complete merge controls, not retained-key-only cold."""
import json,sys,time
from pathlib import Path
from harness import TRIAL,measure,digest

def main():
 root=TRIAL/'cold-complete-merges';root.mkdir(exist_ok=False);samples=[]
 for protocol in ['blake2s','keccak']:
  merge=TRIAL/('complete-merges-'+protocol);wallet=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab');w=json.loads((wallet/'provenance.json').read_text());bins=merge/'bin'
  for rnd in range(5):
   for case in (['first','node'] if rnd%2==0 else ['node','first']):
    for pair in range(2):
     for system in ['r1cs','vm']:
      tag=f'{protocol}-{case}-r{rnd}-p{pair}-{system}';out=root/(tag+'.certificate');request=root/(tag+'.json');request.write_text(json.dumps({'input':'fixed-child-control','output':str(out)})+'\n')
      if system=='r1cs':cmd=[bins/'r1cs-node','mixed','serve'] if case=='node' else [bins/'r1cs-first','merkle','B','B','carried','serve']
      else:cmd=[bins/'vm','serve','mixed' if case=='first' else 'node-mixed',w['elf']['A']['path'],wallet/'cold-A-r0-p0-vm',w['elf']['B']['path'],wallet/'cold-B-r0-p0-vm','unused',merge/'vm-first-child']
      labels={'system':system,'case':case+' complete control','mode':'cold combined process/setup','round':rnd,'pair':pair,'protocol_hash':protocol,'scope':'Fixed-child calibration control, not scored node; parent Python transport adapter included','complete_transport':True}
      sample=measure([sys.executable,Path(__file__).with_name('one_request.py'),request]+cmd,root/tag,forwarded=[out],labels=labels,timeout=600);assert sample['returncode']==0;print(tag,round(sample['wall_s'],3),sample['forwarded_bytes'],flush=True);samples.append(str(root/tag/'sample.json'));(root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n')
 (root/'done.json').write_text(json.dumps({'samples':len(samples),'finished_unix':time.time()},indent=2)+'\n')
if __name__=='__main__':main()
