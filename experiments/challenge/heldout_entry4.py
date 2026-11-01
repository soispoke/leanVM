#!/usr/bin/env python3
"""Post-freeze public setup and real held-out composition screen for entry 4."""
import argparse,json,secrets,time,shutil
from pathlib import Path
from harness import TRIAL,WarmSession,measure,check_freeze,digest

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--entry',default='entry-4');entry=parser.parse_args().entry
 root=TRIAL/(entry+'-referee');root.mkdir(exist_ok=False);m=json.loads((TRIAL/'freezes'/entry/'manifest.json').read_text());binary=Path(m['binaries'][0]['path']);original_setup=Path(m['setup']['output_directory']);setup=root/'setup';setup.mkdir();frozen=TRIAL/'freezes'/entry;freeze_record=json.loads((frozen/'freeze.json').read_text());
 for item in m['aggregate_key']['retained_artifacts']:
  source=Path(item['path']);shutil.copyfile(freeze_record['snapshots'][str(source)],setup/source.name)
 held=json.loads((TRIAL/('heldout-'+entry+'.json')).read_text());apps=['shielded']+[{'merkle-keccak':'merkle'}.get(app,app) for app in held['applications']];samples=[];failures=[]
 def record():
  (root/'index.json').write_text(json.dumps({'samples':samples,'failures':failures},indent=2)+'\n')
  (root/'freeze-check.json').write_text(json.dumps(check_freeze(frozen),indent=2)+'\n')
 try:
  check_freeze(frozen)
  (root/'provenance.json').write_text(json.dumps({'entry':entry,'binary_sha256':digest(binary),'heldout':held,'scope':'A with two drawn held-out applications; no Falcon; does not meet the required A+B/AB+AH score','preknown_decoder_pool':True,'app_setup_after_draw_before_fresh_seeds':True},indent=2)+'\n')
  for app in apps:
   dest=root/('setup-'+app)
   if (setup/'apps'/app/'public-cache').exists():
    (root/('setup-'+app+'-preexisting.json')).write_text(json.dumps({'status':'preexisting public application setup; construction not referee timed','path':str(setup/'apps'/app)})+'\n')
   else:
    sample=measure([binary,m.get('application_setup',[None,'app-setup'])[1],setup,app],dest,timeout=600,labels={'system':entry,'case':app+' public application setup','mode':'setup'});samples.append(str(dest/'sample.json'));print('setup',app,sample['returncode'],sample['wall_s'],flush=True)
    if sample['returncode']!=0:failures.append({'phase':'app-setup','case':app,'evidence':str(dest/'sample.json')});return
   paths=[p for p in (setup/'apps'/app).rglob('*') if p.is_file()];(root/('setup-'+app+'-retained.json')).write_text(json.dumps({'artifacts':[{'path':str(p),'bytes':p.stat().st_size,'sha256':digest(p)} for p in paths],'total_bytes':sum(p.stat().st_size for p in paths)},indent=2)+'\n');record()
  registry=[{'slot':i,'case':app} for i,app in enumerate(apps)]
  for mode in ['cold','warm']:
   session=WarmSession([binary,'serve',setup,','.join(apps)],root/'warm-session',timeout=600) if mode=='warm' else None
   try:
    for rnd in range(5):
     case=root/f'{mode}-{rnd}';case.mkdir()
     def call(command,name,obj,out=None):
      inp=case/(name+'.json');inp.write_text(json.dumps(obj)+'\n');dest=case/name;output=out or case/(name+'-output');files=[output] if out else [];labels={'system':entry,'case':name.split('-')[0]+' heldout control','mode':mode,'round':rnd,'protocol_hash':'keccak'}
      sample=session.request(inp,output,dest,files,labels,timeout=600,command=command) if session else measure([binary,command,setup,inp]+([output] if out else []),dest,forwarded=files,labels=labels,timeout=600);samples.append(str(dest/'sample.json'));print(mode,rnd,name,sample['returncode'],round(sample['wall_s'],4),sample['forwarded_bytes'],flush=True)
      if sample['returncode']!=0:failures.append({'phase':name,'evidence':str(dest/'sample.json')});raise RuntimeError(name+' failed')
      return sample
     wallets=[]
     for i,app in enumerate([apps[0],apps[1],apps[0],apps[2]]):
      out=case/f'wallet-{i}-certificate';call('wallet','wallet-'+str(i),{'case':app,'seed':secrets.randbits(31)},out);wallets.append(out)
     first=[]
     for i in range(2):
      out=case/f'first-{i}-certificate';call('merge','first-'+str(i),{'children':list(map(str,wallets[i*2:i*2+2])),'registry':registry},out);first.append(out)
     node=case/'node-certificate';sample=call('merge','node',{'children':list(map(str,first)),'registry':registry},node);report=next(r for r in sample['reported'] if r.get('phase')=='merge')
     call('root','root',{'certificate':str(node),'expected_digest':report['digest'],'registry':registry});call('admission','admission',{'certificate':str(node)});record()
   finally:
    if session:session.close()
 finally:
  record();completed_trees=sum((root/f'{mode}-{rnd}/admission/sample.json').exists() for mode in ['cold','warm'] for rnd in range(5));(root/'done.json').write_text(json.dumps({'finished_unix':time.time(),'samples':len(samples),'completed_trees':completed_trees,'complete_5_rounds_both_modes':completed_trees==10,'failures':failures,'full_challenge_admission_pass':False,'frozen_surface':check_freeze(frozen)},indent=2)+'\n')
if __name__=='__main__':main()
