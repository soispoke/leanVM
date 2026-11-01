#!/usr/bin/env python3
import argparse,json,shutil,time
from pathlib import Path
from harness import TRIAL,WarmSession,measure,digest
from cadence import run as cadence
P=TRIAL.parents[1]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--protocol',choices=['blake2s','keccak'],default='blake2s');args=ap.parse_args();protocol=args.protocol;root=TRIAL/('complete-merges-'+protocol);root.mkdir(parents=True,exist_ok=False);bins=root/'bin';bins.mkdir();suffix='' if protocol=='blake2s' else '-keccak'
 sources={'r1cs-first':P/f'target-trial-ref{suffix}/release/examples/trial_first','r1cs-node':P/f'target-trial-ref{suffix}/release/examples/trial_sparse','r1cs-root':P/f'target-trial-ref{suffix}/release/examples/trial_sparse_admission','vm':P/f'target-trial-vm{suffix}/release/trial_merge_complete'}
 for n,p in sources.items():shutil.copyfile(p,bins/n);(bins/n).chmod(0o755)
 wallet=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab');w=json.loads((wallet/'provenance.json').read_text());pa=wallet/'cold-A-r0-p0-vm';pb=wallet/'cold-B-r0-p0-vm';child=root/'vm-first-child'
 def vmcmd(mode,case):return [bins/'vm',mode,case,w['elf']['A']['path'],pa,w['elf']['B']['path'],pb,child,child]
 (root/'provenance.json').write_text(json.dumps({'recorded_unix':time.time(),'protocol_hash':protocol,'binaries':{n:{'source':str(p),'sha256':digest(bins/n)} for n,p in sources.items()},'scope':{'r1cs':'shielded+Merkle control, same protocol/application hash family; not A+B','vm':'fresh A+B receipts, fixed pair; duplicated node child, not AB+AH'},'wallet_source':str(wallet),'node_independent_children':{'r1cs':True,'vm':False}},indent=2)+'\n')
 prep=measure(vmcmd('prove','mixed'),root/'vm-child-preparation',labels={'system':'vm','case':'first A+B preparation','mode':'cold combined setup'},forwarded=[Path(str(child)+'.proof')]);assert prep['returncode']==0
 rows=[]
 for case in ['first','node']:
  sessions={};roots={}
  try:
   sessions['r1cs']=WarmSession([bins/'r1cs-node','mixed','serve'] if case=='node' else [bins/'r1cs-first','merkle','B','B','carried','serve'],root/f'{case}-r1cs-session')
   sessions['vm']=WarmSession(vmcmd('serve','mixed' if case=='first' else 'node-mixed'),root/f'{case}-vm-session')
   for rnd in range(5):
    for pair in range(2):
     for system in ['r1cs','vm']:
      tag=f'{case}-r{rnd}-p{pair}-{system}';out=root/(tag+'.certificate');row=sessions[system].request('fixed-child-control',out,root/tag,[out],{'system':system,'case':case+' complete control','mode':'warm','round':rnd,'pair':pair,'protocol_hash':protocol,'complete_transport':True});rows.append(str(root/tag/'sample.json'));print(tag,round(row['wall_s'],4),row['forwarded_bytes'],flush=True)
   if case=='node':
    for system in ['r1cs','vm']:
     result=cadence(sessions[system],root/('cadence-'+system),system);print('cadence',json.dumps(result),flush=True)
    roots['r1cs']=WarmSession([bins/'r1cs-root','mixed','serve-admit'],root/'root-r1cs-session')
    roots['vm']=WarmSession(vmcmd('serve-admit','node-mixed'),root/'root-vm-session')
    for rnd in range(5):
     for pair in range(2):
      for system in ['r1cs','vm']:
       tag=f'root-r{rnd}-p{pair}-{system}';incoming=root/f'node-r{rnd}-p{pair}-{system}.certificate';row=roots[system].request(incoming,'unused',root/tag,[],{'system':system,'case':'complete root two real apps control','mode':'warm','round':rnd,'pair':pair,'protocol_hash':protocol});verification=next(r for r in row['reported'] if r.get('kind')=='verification');assert verification['accepted'];rows.append(str(root/tag/'sample.json'));print(tag,round(row['wall_s']*1000,3),verification['verify_ms'],flush=True)
  finally:
   for s in list(sessions.values())+list(roots.values()):s.close()
  (root/'index.json').write_text(json.dumps({'samples':rows},indent=2)+'\n')
 (root/'done.json').write_text(json.dumps({'completed_unix':time.time(),'samples':len(rows),'all_success':True},indent=2)+'\n')
if __name__=='__main__':main()
