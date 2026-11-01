#!/usr/bin/env python3
"""Novel post-freeze native graph, encoded independently by the referee."""
import json,secrets,shutil,struct,time
from pathlib import Path
from harness import TRIAL,measure,check_freeze,digest

def main():
 root=TRIAL/'entry-6-external-referee';root.mkdir(exist_ok=False);setup=root/'setup';setup.mkdir();frozen=TRIAL/'freezes/entry-6';fr=json.loads((frozen/'freeze.json').read_text());m=json.loads((frozen/'manifest.json').read_text());binary=Path(m['binaries'][0]['path']);old=Path(m['setup']['output_directory'])
 for name in ['aggregate.key','aggregate.trace','aggregate.setup','aggregate.public-cache']:shutil.copyfile(fr['snapshots'][str(old/name)],setup/name)
 check_freeze(frozen);q=lambda x:struct.pack('<Q',x);u32=lambda x:struct.pack('<I',x);scalar=lambda x:q(x)+q(0)+q(0)
 constant=secrets.randbits(64);rows=[[3,4,2,5],[3,1,2,6],[4,1,2,7],[3,4,3,8]];public=[0,1,2,5,6,7,8]
 encoded=u32(2)+q(9)+q(len(rows))+b''.join(q(i) for row in rows for i in row)+q(len(public))+b''.join(q(i) for i in public)+q(0)+q(3)+q(3)+b''.join(scalar(i) for i in [0,1,constant]);generator=root/'novel.generator';generator.write_bytes(encoded)
 (root/'generator-description.json').write_text(json.dumps({'created_unix':time.time(),'freeze_sha256':digest(frozen/'freeze.json'),'constant_hex':hex(constant),'variables':9,'rows_x_y_u_z':rows,'public_indices':public,'fixed_public_indices':[0,1,2],'relation':'four outputs x*y+C, x+C, y+C, x*y+x over characteristic two; inputs x,y chosen after public setup','native_hash_blocks':0,'purpose':'generic structural admission only, not challenge A/B or security evidence','generator_sha256':digest(generator),'witness_construction':'independent Python bincode encoding; external wallet timer excludes witness construction'},indent=2)+'\n')
 samples=[];sample=measure([binary,'generator-setup',setup,'refgraph',generator],root/'public-setup',labels={'system':'entry-6','case':'novel public generator setup','mode':'setup'});samples.append(str(root/'public-setup/sample.json'));assert sample['returncode']==0
 # GF(2^64) multiplication needs no reduction for eight-bit input operands.
 def mul(x,y):
  result=0
  for i in range(8):
   if y>>i&1:result^=x<<i
  return result
 certs=[]
 for i in range(4):
  x=secrets.randbits(8);y=secrets.randbits(8);seed=secrets.randbits(31);xy=mul(x,y);values=[0,1,constant,x,y,xy^constant,x^constant,y^constant,xy^x];witness=root/f'witness-{i}.bin';witness.write_bytes(u32(1)+q(seed)+q(len(values))+b''.join(scalar(v) for v in values)+q(0));inp=root/f'wallet-{i}.json';inp.write_text(json.dumps({'case':'refgraph','seed':seed,'witness':str(witness)})+'\n');out=root/f'wallet-{i}-certificate';sample=measure([binary,'wallet',setup,inp,out],root/f'wallet-{i}',forwarded=[out],labels={'system':'entry-6','case':'external novel wallet structural','mode':'cold file mode; upstream witness construction excluded'});assert sample['returncode']==0;samples.append(str(root/f'wallet-{i}/sample.json'));certs.append(out);print('wallet',i,round(sample['wall_s'],3),flush=True)
 registry=[{'slot':0,'case':'refgraph'}]
 def merge(name,children):
  inp=root/(name+'.json');inp.write_text(json.dumps({'children':list(map(str,children)),'registry':registry})+'\n');out=root/(name+'-certificate');sample=measure([binary,'merge',setup,inp,out],root/name,forwarded=[out],labels={'system':'entry-6','case':'novel external '+name,'mode':'cold combined public loading'});assert sample['returncode']==0;samples.append(str(root/name/'sample.json'));report=next(r for r in sample['reported'] if r.get('phase')=='merge');print(name,round(sample['wall_s'],3),flush=True);return out,report
 first=[merge('first-'+str(i),certs[2*i:2*i+2])[0] for i in range(2)];node,report=merge('node',first);inp=root/'root.json';request={'certificate':str(node),'expected_digest':report['digest'],'registry':registry};inp.write_text(json.dumps(request)+'\n');sample=measure([binary,'root',setup,inp],root/'root',labels={'system':'entry-6','case':'novel external complete root','mode':'cold combined public loading'});assert sample['returncode']==0;samples.append(str(root/'root/sample.json'))
 rejections=[]
 for label,offset,value,width in [('wrong version',0,255,4),('excess variables',4,(1<<22)+1,8),('out of range index',20,9,8),('wrong anchor index',164,0,8),('false fixed zero',236,1,8)]:
  bad=bytearray(encoded);bad[offset:offset+width]=value.to_bytes(width,'little');path=root/(label.replace(' ','-')+'.generator');path.write_bytes(bad);dest=root/('reject-'+label.replace(' ','-'));sample=measure([binary,'generator-setup',setup,'bad'+str(len(rejections)),path],dest,labels={'system':'entry-6','case':'malformed generator: '+label,'mode':'public generator admission rejection'});rejections.append({'system':'r1cs','protocol':'keccak','case':'malformed generator','status':'pass' if sample['returncode']!=0 else 'fail','prover_prechecks_bypassed':True,'scope':'Public generator admission/derivation validator, no private witness or prover; process failure may be a panic, no graceful-service claim','mutation':label,'evidence':str(dest/'sample.json')})
 path=root/'trailing.generator';path.write_bytes(encoded+b'\x00');dest=root/'reject-trailing';sample=measure([binary,'generator-setup',setup,'badtrailing',path],dest,labels={'system':'entry-6','case':'malformed generator: trailing byte','mode':'public generator admission rejection'});rejections.append({'system':'r1cs','protocol':'keccak','case':'malformed generator','status':'pass' if sample['returncode']!=0 else 'fail','prover_prechecks_bypassed':True,'scope':'Strict canonical public-generator decoder only; process failure, no graceful-service claim','evidence':str(dest/'sample.json')});(root/'rejections.json').write_text(json.dumps(rejections,indent=2)+'\n')
 (root/'index.json').write_text(json.dumps({'samples':samples},indent=2)+'\n');(root/'done.json').write_text(json.dumps({'finished_unix':time.time(),'frozen_surface':check_freeze(frozen),'novel_generator_admitted':True,'same_key_first_and_node':True,'full_challenge_score_eligible':False,'upstream_external_witness_timer_complete':False},indent=2)+'\n')
if __name__=='__main__':
 try:main()
 finally:
  folder=TRIAL/'entry-6-external-referee';folder.mkdir(exist_ok=True);(folder/'finished.json').write_text(json.dumps({'finished_unix':time.time(),'successful':(folder/'done.json').exists()})+'\n')
