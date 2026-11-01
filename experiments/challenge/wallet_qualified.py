#!/usr/bin/env python3
"""Complete-certificate ABAB run, rotating A/B order between rounds."""
import argparse,json,secrets,shutil,subprocess,time
from pathlib import Path
from harness import TRIAL,WarmSession,measure,digest
P=TRIAL.parents[1]
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--protocol',choices=['blake2s','keccak'],default='blake2s');args=ap.parse_args();protocol=args.protocol
 root=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab');root.mkdir(parents=True,exist_ok=False);bins=root/'bin';bins.mkdir();sources={'r1cs':P/('target-trial-ref/release/examples/trial_wallet_v2' if protocol=='blake2s' else 'target-trial-ref-keccak/release/examples/trial_wallet_v2'),'vm':P/('target-trial-vm/release/trial_wallet' if protocol=='blake2s' else 'target-trial-vm-keccak/release/trial_wallet'),'inputgen':P/'target-trial-inputgen/release/trial-inputgen'}
 for name,p in sources.items():shutil.copyfile(p,bins/name);(bins/name).chmod(0o755)
 elves={app:(P/'artifacts/hometurf-L7/wallet-abab/bin'/f'{name}-B.elf' if protocol=='blake2s' else TRIAL/'protocol-published-snapshots'/f'vm-{name}.elf') for app,name in [('A','shielded'),('B','falcon')]}
 provenance={'frozen_unix':time.time(),'binaries':{n:{'source':str(p),'sha256':digest(bins/n)} for n,p in sources.items()},'elf':{n:{'path':str(p),'sha256':digest(p)} for n,p in elves.items()},'protocol_hash':protocol,'aggregate_key_freeze':False,'held_out_draw':False,'B_relations':{'r1cs':'decoded inputs reduced','vm':'compressed body/public key parsing; header bytes implied'},'order':'five rounds, A/B order rotates, R1CS VM R1CS VM in each case','r1cs_certificate':'public values, context, identity, proof; bincode tuple','cold_limitation':'compilation/setup inseparable; full process is an upper bound, not retained-key-only cold'}
 (root/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n');samples=[]
 def argv(system,app,mode,output,inp):
  if system=='r1cs':return [bins/'r1cs','shielded' if app=='A' else 'falcon','rows',mode,output,'0',inp]
  return [bins/'vm','shielded' if app=='A' else 'falcon',mode,elves[app],output,inp]
 for mode in ['cold','warm']:
  sessions={}
  try:
   if mode=='warm':
    for app in ['A','B']:
     for system in ['r1cs','vm']:sessions[system,app]=WarmSession(argv(system,app,'serve',root/'unused','unused'),root/f'{mode}-{app}-{system}-session')
   for rnd in range(5):
    for app in (['A','B'] if rnd%2==0 else ['B','A']):
     for pair in range(2):
      seed=secrets.randbits(31);inp=root/f'{mode}-{app}-r{rnd}-p{pair}-input';subprocess.run([bins/'inputgen',app,str(seed),inp],check=True,stdout=subprocess.DEVNULL)
      for system in ['r1cs','vm']:
       tag=f'{mode}-{app}-r{rnd}-p{pair}-{system}';base=root/tag;proof=Path(str(base)+'.proof');out=proof if system=='r1cs' else base;forwarded=[proof]+([Path(str(base)+'.output')] if system=='vm' else [])
       labels={'system':system,'case':app,'mode':mode,'round':rnd,'pair':pair,'seed':seed,'fresh':True,'protocol_hash':protocol,'boundary':'cold full process includes compilation/setup' if mode=='cold' else 'warm external request through complete serialized certificate','complete_transport':True}
       if mode=='cold':row=measure(argv(system,app,'prove',out,inp/'instance.json'),base,forwarded=forwarded,timeout=600,labels=labels)
       else:row=sessions[system,app].request(inp/'instance.json',out,base,forwarded,labels,timeout=600)
       samples.append(str(base/'sample.json'));print(tag,row['returncode'],round(row['wall_s'],4),row['forwarded_bytes'],flush=True)
       (root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n')
       if row['returncode']!=0:raise RuntimeError('failed '+tag)
  finally:
   for s in sessions.values():s.close()
 (root/'done.json').write_text(json.dumps({'completed_unix':time.time(),'samples':len(samples),'failures':[]},indent=2)+'\n')
if __name__=='__main__':main()
