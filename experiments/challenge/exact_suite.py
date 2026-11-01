#!/usr/bin/env python3
"""Fresh shared-input Falcon/MPT statement parity screen using published exact guests."""
import json,secrets,shutil,subprocess,time
from pathlib import Path
from harness import TRIAL,WarmSession,measure,digest
P=TRIAL.parents[1]
def main():
 while not (TRIAL/"root-series-entry-2/done.json").exists():time.sleep(2)
 for protocol in ['blake2s','keccak']:
  root=TRIAL/('exact-wallet-'+protocol);root.mkdir(exist_ok=False);bins=root/'bin';bins.mkdir();sources={'inputgen':P/'target-trial-inputgen/release/trial-inputgen','vm':P/('target-trial-vm/release/trial_wallet_exact' if protocol=='blake2s' else 'target-trial-vm-keccak/release/trial_wallet_exact'),'r1cs':TRIAL/('wallet-complete-abab/bin/r1cs' if protocol=='blake2s' else 'wallet-keccak-complete-abab/bin/r1cs')}
  for name,path in sources.items():shutil.copyfile(path,bins/name);(bins/name).chmod(0o755)
  elves={}
  for app,name in [('B','falcon-l6'),('mpt','mpt-l6')]:
   path=P/'artifacts/hometurf-L7/exact-l6-wallet-abab/bin'/f'{name}-{"A" if protocol=="blake2s" else "B"}.elf'
   shutil.copyfile(path,bins/(name+'.elf'));elves[app]=bins/(name+'.elf')
  (root/'provenance.json').write_text(json.dumps({'protocol':protocol,'binaries':{n:{'source':str(p),'sha256':digest(bins/n)} for n,p in sources.items()},'elf':{a:{'path':str(p),'sha256':digest(p)} for a,p in elves.items()},'scope':'Shared fresh Falcon/MPT inputs with exact 64-byte circuit statement; R1CS Falcon is still reduced decoded, VM checks compressed body and implied headers; no aggregate held-out admission','vm_application_hash_implementation':'software Keccak guest control' if protocol=='blake2s' else 'native Keccak instruction','cold':'full process includes compilation/setup'},indent=2)+'\n');samples=[]
  def argv(system,app,mode,out,inp):
   if system=='r1cs':return [bins/'r1cs','falcon' if app=='B' else 'mpt','rows',mode,out,'0',inp]
   return [bins/'vm','falcon-l6' if app=='B' else 'mpt-l6',mode,elves[app],out,inp]
  for mode in ['cold','warm']:
   sessions={}
   try:
    if mode=='warm':
     for app in ['B','mpt']:
      for system in ['r1cs','vm']:sessions[system,app]=WarmSession(argv(system,app,'serve','unused','unused'),root/f'{system}-{app}-session')
    for rnd in range(5):
     for app in (['B','mpt'] if rnd%2==0 else ['mpt','B']):
      for pair in range(2):
       inp=root/f'{mode}-{app}-{rnd}-{pair}-input';subprocess.run([bins/'inputgen',app,str(secrets.randbits(31)),inp],check=True,stdout=subprocess.DEVNULL)
       for system in ['r1cs','vm']:
        tag=f'{mode}-{app}-{rnd}-{pair}-{system}';base=root/tag;proof=Path(str(base)+'.proof');out=proof if system=='r1cs' else base;files=[proof]+([Path(str(base)+'.output')] if system=='vm' else [])
        labels={'system':system,'case':app+' exact statement','mode':mode,'round':rnd,'pair':pair,'protocol_hash':protocol,'fresh':True,'statement_parity':'exact shared 64-byte circuit statement; certificate commits via system-specific envelope','complete_transport':True}
        sample=measure(argv(system,app,'prove',out,inp/'instance.json'),base,forwarded=files,labels=labels) if mode=='cold' else sessions[system,app].request(inp/'instance.json',out,base,files,labels)
        print(tag,sample['returncode'],round(sample['wall_s'],4),sample['forwarded_bytes'],flush=True);samples.append(str(base/'sample.json'));(root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n');assert sample['returncode']==0
   finally:
    for session in sessions.values():session.close()
  (root/'done.json').write_text(json.dumps({'samples':len(samples),'finished_unix':time.time()},indent=2)+'\n')
if __name__=='__main__':main()
