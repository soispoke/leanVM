#!/usr/bin/env python3
"""One/two/three application root controls under entry 2's single frozen key."""
import json,time
from harness import TRIAL,WarmSession,measure,check_freeze

def main():
 root=TRIAL/'root-series-entry-2';root.mkdir(exist_ok=False);m=json.loads((TRIAL/'freezes/entry-2/manifest.json').read_text());binary=m['binaries'][0]['path'];setup=m['setup']['output_directory'];base=TRIAL/'entry-2-referee/warm-r4';registry=[{'slot':i,'case':c} for i,c in enumerate(['shielded','merkle','hash3'])];s=WarmSession([binary,'serve',setup,'shielded,merkle,hash3'],root/'preparation-session');inp=root/'one-app-merge.json';inp.write_text(json.dumps({'children':[str(base/'wallet-0-certificate'),str(base/'wallet-3-certificate')],'registry':registry[:1]})+'\n');certificate=root/'one-app-certificate'
 try:
  sample=s.request(inp,certificate,root/'one-app-merge',[certificate],{'system':'entry-2','case':'one application root preparation','mode':'warm'},command='merge');report=next(r for r in sample['reported'] if r.get('phase')=='merge');one=report['digest']
 finally:s.close()
 two=next(r for r in json.loads((base/'first-0/sample.json').read_text())['reported'] if r.get('phase')=='merge')['digest'];three=next(r for r in json.loads((base/'node/sample.json').read_text())['reported'] if r.get('phase')=='merge')['digest'];inputs={}
 for count,cert,digest in [(1,certificate,one),(2,base/'first-0-certificate',two),(3,base/'node-certificate',three)]:
  p=root/f'root-{count}.json';p.write_text(json.dumps({'certificate':str(cert),'expected_digest':digest,'registry':registry[:count]})+'\n');inputs[count]=p
 for mode in ['cold','warm']:
  session=WarmSession([binary,'serve',setup,'shielded,merkle,hash3'],root/'warm-session') if mode=='warm' else None
  try:
   for rnd in range(5):
    for count in ([1,2,3] if rnd%2==0 else [3,2,1]):
     dest=root/f'{mode}-{count}-{rnd}';labels={'system':'entry-2','case':str(count)+' real applications local root','mode':mode,'round':rnd,'matrix_identities':count+1,'scope':'Local BLAKE applications only; complete aggregate finalization included'}
     sample=session.request(inputs[count],'unused',dest,[],labels,command='root') if session else measure([binary,'root',setup,inputs[count]],dest,labels=labels);assert sample['returncode']==0;print(mode,count,rnd,round(sample['wall_s']*1000,2),flush=True)
  finally:
   if session:session.close()
 (root/'done.json').write_text(json.dumps({'finished_unix':time.time(),'freeze':check_freeze(TRIAL/'freezes/entry-2'),'scope':'One/two/three local real applications plus one aggregate identity'},indent=2)+'\n')
if __name__=='__main__':main()
