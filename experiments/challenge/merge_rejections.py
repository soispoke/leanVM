#!/usr/bin/env python3
"""Direct VM complete-root claim-envelope mutations, after proof creation."""
import copy,json,time
from harness import TRIAL,WarmSession,digest

def main():
 root=TRIAL/'merge-certificate-rejections';root.mkdir(exist_ok=False);rows=[]
 for protocol in ['blake2s','keccak']:
  merge=TRIAL/('complete-merges-'+protocol);wallet=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab');w=json.loads((wallet/'provenance.json').read_text());source=merge/'node-r0-p0-vm.certificate';data=source.read_bytes();n=int.from_bytes(data[:8],'little');proof=data[:8+n];meta=json.loads(data[8+n:]);mutations={}
  def change(case,fn):
   v=copy.deepcopy(meta);fn(v['ordered_claims']);mutations[case]=v
  change('substituted key',lambda c:c[0]['program_digest'].__setitem__(0,c[0]['program_digest'][0]^1))
  change('wrong statement',lambda c:c[0]['output'].__setitem__(0,c[0]['output'][0]^1))
  change('omitted claim',lambda c:c.pop())
  change('duplicated claim',lambda c:c.append(copy.deepcopy(c[0])))
  change('duplicate identity different claims',lambda c:c[1].__setitem__('program_digest',copy.deepcopy(c[0]['program_digest'])))
  change('reordered children unchanged digest',lambda c:c.__setitem__(slice(0,2),[c[1],c[0]]))
  cmd=[merge/'bin/vm','serve-admit','node-mixed',w['elf']['A']['path'],wallet/'cold-A-r0-p0-vm',w['elf']['B']['path'],wallet/'cold-B-r0-p0-vm','unused','unused'];session=WarmSession(cmd,root/(protocol+'-session'))
  try:
   for i,(case,modified) in enumerate(mutations.items()):
    incoming=root/f'{protocol}-{i}.certificate';incoming.write_bytes(proof+json.dumps(modified,separators=(',',':')).encode());dest=root/f'{protocol}-{i}';sample=session.request(incoming,'unused',dest,[],{'system':'vm','case':case,'mode':'rejection','protocol_hash':protocol});report=next(r for r in sample['reported'] if r.get('kind')=='verification');rows.append({'system':'vm','protocol':protocol,'case':case,'status':'pass' if report['accepted'] is False else 'fail','prover_prechecks_bypassed':True,'scope':'One complete-root ordered-claim mutation; node repeats one child; does not demonstrate arbitrary-application key admission','evidence':str(dest/'sample.json'),'source_sha256':digest(source),'mutated_sha256':digest(incoming)});print(protocol,case,report['accepted'],flush=True)
  finally:session.close()
 (root/'coverage.json').write_text(json.dumps({'samples':rows,'warning':'Partial regression evidence only'},indent=2)+'\n');(root/'done.json').write_text(json.dumps({'samples':len(rows),'finished_unix':time.time()},indent=2)+'\n')
if __name__=='__main__':main()
