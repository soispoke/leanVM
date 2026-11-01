#!/usr/bin/env python3
import argparse,json,secrets,shutil,subprocess,time
from pathlib import Path
from harness import TRIAL,measure,digest,WarmSession,deadline
P=TRIAL.parents[1]

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--r1cs-binary',default='trial_wallet');ap.add_argument('--rounds',type=int,default=5);ap.add_argument('--name',default='wallet-abab');ap.add_argument('--mode',choices=['cold','warm','both'],default='both');ap.add_argument('--apps',nargs='+',default=['A','B']);a=ap.parse_args()
 root=TRIAL/a.name;root.mkdir(parents=True,exist_ok=False);bins=root/'bin';bins.mkdir()
 sources={'r1cs':P/('target-trial-ref/release/examples/'+a.r1cs_binary),'vm':P/'target-trial-vm/release/trial_wallet','inputgen':P/'target-trial-inputgen/release/trial-inputgen'}
 for name,path in sources.items():shutil.copyfile(path,bins/name);(bins/name).chmod(0o755)
 elves={app:P/'artifacts/hometurf-L7/wallet-abab/bin'/f'{name}-B.elf' for app,name in [('A','shielded'),('B','falcon'),('keccak1k','keccak1k'),('merkle-keccak','merkle')]}
 provenance={'frozen_unix':time.time(),'binaries':{n:{'source':str(p),'sha256':digest(bins/n)} for n,p in sources.items()},'elf':{app:{'path':str(path),'sha256':digest(path)} for app,path in elves.items()},'protocol_hash':'blake2s','r1cs_base':'65745ca1 + shielded Keccak statement + referee adapter','vm_base':'ef342ea4 (a40a7fa6 + L7 Keccak instruction)','aggregate_key_freeze':False,'held_out_draw':False,'B_relations':{'r1cs':'decoded inputs reduced','vm':'compressed body and public key parsing with implied headers'},'fresh_private_inputs_revealed_after_binary_freeze':True}
 (root/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
 modes=['cold','warm'] if a.mode=='both' else [a.mode];rows=[];failures=[]
 for mode in modes:
  for app in a.apps:
   sessions={}
   def argv(system,runmode,output,inputfile):
    if system=='r1cs':return [bins/system,{'A':'shielded','B':'falcon','keccak1k':'keccak','mpt':'mpt','merkle-keccak':'merkle'}[app],'rows',runmode,output,'0',inputfile]
    return [bins/system,{'A':'shielded','B':'falcon','keccak1k':'keccak1k','merkle-keccak':'merkle'}[app],runmode,elves[app],output,inputfile]
   try:
    if mode=='warm':
     for system in ('r1cs','vm'):sessions[system]=WarmSession(argv(system,'serve',root/'unused','unused'),root/f'{mode}-{app}-{system}-session')
    for rnd in range(a.rounds):
     for pair in range(2):
      seed=secrets.randbits(31);inp=root/f'{mode}-{app}-r{rnd}-pair{pair}-input'
      subprocess.run([str(bins/'inputgen'),app,str(seed),str(inp)],check=True,stdout=subprocess.DEVNULL)
      for system in ('r1cs','vm'):
       tag=f'{mode}-{app}-r{rnd}-p{pair}-{system}';base=root/tag;proof=Path(str(base)+'.proof');output=proof if system=='r1cs' else base;forwarded=[proof]+([Path(str(base)+'.output')] if system=='vm' else [])
       labels={'system':system,'case':app,'mode':mode,'round':rnd,'pair':pair,'seed':seed,'fresh':True,'protocol_hash':'blake2s','boundary':'cold full process including public compilation/setup' if mode=='cold' else 'warm request to serialized proof; public setup retained','complete_bytes_scope':('complete public-context-identity-proof-v1 certificate' if a.r1cs_binary=='trial_wallet_v2' else 'proof only, incomplete public claim transport') if system=='r1cs' else 'proof plus output sidecar; program authenticated from frozen ELF registry'}
       if mode=='cold':row=measure(argv(system,'prove',output,inp/'instance.json'),base,timeout=600,forwarded=forwarded,labels=labels)
       else:row=sessions[system].request(inp/'instance.json',output,base,forwarded,labels,timeout=600)
       rows.append(str(base/'sample.json'));print(tag,row['returncode'],round(row['wall_s'],4),flush=True)
       if row['returncode']!=0:failures.append(tag);raise RuntimeError('failed case '+tag)
   except Exception as exc:
    failures.append(str(exc));print('ERROR',str(exc),flush=True)
   finally:
    for session in sessions.values():session.close()
   (root/'index.json').write_text(json.dumps({'samples':rows,'failures':failures},indent=2)+'\n')
 (root/'done.json').write_text(json.dumps({'completed_unix':time.time(),'samples':len(rows),'failures':failures},indent=2)+'\n')
if __name__=='__main__':main()
