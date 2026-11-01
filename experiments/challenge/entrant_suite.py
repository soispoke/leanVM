#!/usr/bin/env python3
"""Referee measurements of entry 2's composable local BLAKE controls."""
import json,secrets,time
from pathlib import Path
from harness import TRIAL,WarmSession,measure,check_freeze,digest

def main():
 root=TRIAL/'entry-2-referee';root.mkdir(exist_ok=False);manifest=json.loads((TRIAL/'freezes/entry-2/manifest.json').read_text());binary=Path(manifest['binaries'][0]['path']);setup=Path(manifest['setup']['output_directory']);frozen=TRIAL/'freezes/entry-2';check_freeze(frozen)
 (root/'provenance.json').write_text(json.dumps({'binary':str(binary),'sha256':digest(binary),'freeze':str(frozen),'scope':'three local BLAKE2s applications: shielded, Merkle, hash3; no challenge A/B or held-out composition','fresh_witnesses':True,'ordered_tree':'((shielded+Merkle)+(hash3+shielded))','same_aggregate_key_all_levels':True},indent=2)+'\n');registry=[{'slot':i,'case':c} for i,c in enumerate(['shielded','merkle','hash3'])];rows=[]
 for mode in ['cold','warm']:
  session=WarmSession([binary,'serve',setup,'shielded,merkle,hash3'],root/'warm-session') if mode=='warm' else None
  try:
   for rnd in range(5):
    case=root/f'{mode}-r{rnd}';case.mkdir()
    def call(command,name,obj,out=None):
     inp=case/(name+'.json');inp.write_text(json.dumps(obj)+'\n');dest=case/name;output=out or case/(name+'-output');forwarded=[output] if out else [];labels={'system':'entry-2','case':name.split('-')[0]+' local control','mode':mode,'round':rnd,'protocol_hash':'blake2s','scope':'local applications only'}
     check_freeze(frozen)
     if session:sample=session.request(inp,output,dest,forwarded,labels,command=command)
     else:sample=measure([binary,command,setup,inp]+([output] if out else []),dest,forwarded=forwarded,labels=labels)
     assert sample['returncode']==0,(name,sample['returncode']);rows.append(str(dest/'sample.json'));print(mode,rnd,name,round(sample['wall_s'],4),sample['forwarded_bytes'],flush=True);check_freeze(frozen);return sample
    wallets=[]
    for i,c in enumerate(['shielded','merkle','hash3','shielded']):
     out=case/f'wallet-{i}-certificate';call('wallet',f'wallet-{i}',{'case':c,'seed':secrets.randbits(31)},out);wallets.append(out)
    first=[]
    for i in range(2):
     out=case/f'first-{i}-certificate';call('merge',f'first-{i}',{'children':list(map(str,wallets[i*2:i*2+2])),'registry':registry},out);first.append(out)
    node=case/'node-certificate';sample=call('merge','node',{'children':list(map(str,first)),'registry':registry},node);report=next(r for r in sample['reported'] if r.get('phase')=='merge')
    call('root','root',{'certificate':str(node),'expected_digest':report['digest'],'registry':registry});call('admission','admission',{'certificate':str(node)})
    (root/'index.json').write_text(json.dumps({'samples':rows},indent=2)+'\n')
  finally:
   if session:session.close()
 # Unsupported held-out decoding is recorded as missing capability, not a verifier rejection pass.
 held=json.loads((TRIAL/'heldout-entry-2.json').read_text());unsupported=[]
 for app in held['applications']:
  inp=root/('heldout-'+app+'.json');inp.write_text(json.dumps({'case':app,'seed':secrets.randbits(31)})+'\n')
  sample=measure([binary,'wallet',setup,inp,root/('heldout-'+app+'-output')],root/('heldout-'+app),labels={'system':'entry-2','case':app+' unsupported decoder','mode':'heldout'})
  unsupported.append({'application':app,'status':'not measurable','returncode':sample['returncode'],'reason':'Frozen decoder supports only shielded, Merkle and hash3','evidence':str(root/('heldout-'+app)/'sample.json')});check_freeze(frozen)
 (root/'heldout-admission.json').write_text(json.dumps(unsupported,indent=2)+'\n');(root/'done.json').write_text(json.dumps({'finished_unix':time.time(),'samples':len(rows),'frozen_surface':check_freeze(frozen),'eligible':False},indent=2)+'\n')
if __name__=='__main__':main()
