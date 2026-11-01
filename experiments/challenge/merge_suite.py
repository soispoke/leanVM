#!/usr/bin/env python3
import argparse,json,shutil,time
from pathlib import Path
from harness import TRIAL,measure,WarmSession,digest
from cadence import run as cadence
P=TRIAL.parents[1]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--name',default='merge-controls');ap.add_argument('--rounds',type=int,default=5);ap.add_argument('--no-cold',action='store_true');a=ap.parse_args()
 root=TRIAL/a.name;root.mkdir(parents=True,exist_ok=False);bins=root/'bin';bins.mkdir()
 sources={'r1cs-node':P/'target-trial-ref/release/examples/trial_sparse','r1cs-first':P/'target-trial-ref/release/examples/trial_first','r1cs-node-cold':P/'target-trial-ref/release/examples/sparse_tree','r1cs-first-cold':P/'target-trial-ref/release/examples/deferred_merge','vm':P/'target-trial-vm/release/trial_merge'}
 for n,p in sources.items():shutil.copyfile(p,bins/n);(bins/n).chmod(0o755)
 (root/'provenance.json').write_text(json.dumps({'frozen_unix':time.time(),'binaries':{n:{'source':str(p),'sha256':digest(bins/n)} for n,p in sources.items()},'scope':{'r1cs':'BLAKE2s shielded + BLAKE2s Merkle control; not challenge A+B','vm':'fresh A+B wallet receipts; fixed-pair aggregate key; node repeats one child, not AB+AH'},'held_out_admission':False},indent=2)+'\n')
 elves=P/'artifacts/hometurf-L7/wallet-abab/bin';wallet=TRIAL/'wallet-abab';pa=wallet/'cold-A-r0-p0-vm';pb=wallet/'cold-B-r0-p0-vm';child=root/'vm-first-child'
 def vmcmd(mode,case,out):return [bins/'vm',mode,case,elves/'shielded-B.elf',pa,elves/'falcon-B.elf',pb,out,child]
 first=measure(vmcmd('prove','mixed',child),root/'vm-child-preparation',forwarded=[Path(str(child)+'.proof')],labels={'role':'child preparation','system':'vm','case':'first_A_B','mode':'cold combined setup'})
 if first['returncode']!=0:raise RuntimeError('VM A+B merge unavailable')
 samples=[]
 if not a.no_cold:
  for rnd in range(a.rounds):
   for case in (['first','node'] if rnd%2==0 else ['node','first']):
    for pair in range(2):
     for system in ['r1cs','vm']:
      tag=f'cold-{case}-r{rnd}-p{pair}-{system}';out=root/tag;forwarded=[]
      if system=='vm':cmd=vmcmd('prove','mixed' if case=='first' else 'node-mixed',out);forwarded=[Path(str(out)+'.proof')]
      elif case=='first':cmd=[bins/'r1cs-first-cold','merkle','B','B','carried']
      else:cmd=[bins/'r1cs-node-cold','mixed']
      row=measure(cmd,out,forwarded=forwarded,labels={'system':system,'case':case+' control','mode':'cold','round':rnd,'pair':pair,'boundary':'whole process includes input proof loading or leaf preparation, setup, and root checks; not retained-key-only cold'})
      samples.append(str(out/'sample.json'));print(tag,row['returncode'],round(row['wall_s'],4),flush=True)
      if row['returncode']!=0:raise RuntimeError('merge control failed '+tag)
      (root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n')
 for case in ['first','node']:
  sessions={}
  try:
   sessions['r1cs']=WarmSession([bins/('r1cs-'+case),'mixed','serve'] if case=='node' else [bins/'r1cs-first','merkle','B','B','carried','serve'],root/(case+'-r1cs-session'))
   sessions['vm']=WarmSession(vmcmd('serve','mixed' if case=='first' else 'node-mixed',root/'unused'),root/(case+'-vm-session'))
   for rnd in range(a.rounds):
    for pair in range(2):
     for system in ['r1cs','vm']:
      tag=f'warm-{case}-r{rnd}-p{pair}-{system}';out=root/(tag+'.certificate')
      row=sessions[system].request('fixed-child-control',out,root/tag,[out],{'system':system,'case':case+' control','mode':'warm','round':rnd,'pair':pair,'fixed_children':True})
      samples.append(str(root/tag/'sample.json'));print(tag,round(row['wall_s'],4),flush=True)
   if case=='node':
    for system in ['r1cs','vm']:
     result=cadence(sessions[system],root/('cadence-'+system),system);print('cadence',json.dumps(result),flush=True)
  finally:
   for s in sessions.values():s.close()
  (root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n')
 (root/'done.json').write_text(json.dumps({'completed_unix':time.time(),'samples':len(samples)},indent=2)+'\n')
if __name__=='__main__':main()
