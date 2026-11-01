#!/usr/bin/env python3
import argparse,json,shutil,time
from pathlib import Path
from harness import TRIAL,WarmSession,digest
P=TRIAL.parents[1]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--protocol',choices=['blake2s','keccak'],default='blake2s');args=ap.parse_args();protocol=args.protocol;root=TRIAL/('admission-'+protocol);root.mkdir(parents=True,exist_ok=False);bins=root/'bin';bins.mkdir();wallet=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab')
 shutil.copyfile(wallet/'bin/r1cs',bins/'r1cs');(bins/'r1cs').chmod(0o755);src=P/('target-trial-vm/release/trial_admission' if protocol=='blake2s' else 'target-trial-vm-keccak/release/trial_admission');shutil.copyfile(src,bins/'vm');(bins/'vm').chmod(0o755)
 provenance=json.loads((wallet/'provenance.json').read_text());(root/'provenance.json').write_text(json.dumps({'recorded_unix':time.time(),'protocol_hash':protocol,'binaries':{n:digest(bins/n) for n in ['r1cs','vm']},'wallet_run':str(wallet),'scope':'certificate admission with public setup retained; R1CS authenticates its fixed identity and public anchors; consumer transaction validity semantics are separate'},indent=2)+'\n');sessions={};samples=[]
 try:
  for app in ['A','B']:
   for system in ['r1cs','vm']:
    if system=='r1cs':cmd=[bins/'r1cs','shielded' if app=='A' else 'falcon','rows','serve-admit','unused','0','unused']
    else:cmd=[bins/'vm','shielded' if app=='A' else 'falcon','serve-admit',provenance['elf'][app]['path'],'unused','unused']
    sessions[system,app]=WarmSession(cmd,root/f'{system}-{app}-session')
  for rnd in range(5):
   for app in (['A','B'] if rnd%2==0 else ['B','A']):
    for pair in range(2):
     for system in ['r1cs','vm']:
      tag=f'{app}-r{rnd}-p{pair}-{system}';prefix=wallet/f'cold-{app}-r{rnd}-p{pair}-{system}';incoming=Path(str(prefix)+'.proof') if system=='r1cs' else prefix
      row=sessions[system,app].request(incoming,'unused',root/tag,[],{'system':system,'case':app+' admission','mode':'warm','round':rnd,'pair':pair,'protocol_hash':protocol})
      verification=next(r for r in row['reported'] if r.get('kind')=='verification');assert verification['accepted'];samples.append(str(root/tag/'sample.json'));print(tag,round(row['wall_s']*1000,3),verification['verify_ms'],flush=True)
      (root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n')
 finally:
  for s in sessions.values():s.close()
 (root/'done.json').write_text(json.dumps({'completed_unix':time.time(),'samples':len(samples),'all_accepted':True},indent=2)+'\n')
if __name__=='__main__':main()
