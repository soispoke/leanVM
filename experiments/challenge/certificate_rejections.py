#!/usr/bin/env python3
"""Mutate complete certificates after proving; no prover prechecks involved."""
import json,struct,time
from pathlib import Path
from harness import TRIAL,WarmSession,digest,measure
from rejections import CASES

def main():
 root=TRIAL/'certificate-rejections';root.mkdir(exist_ok=False);results=[]
 for protocol in ['blake2s','keccak']:
  wallet=TRIAL/('wallet-complete-abab' if protocol=='blake2s' else 'wallet-keccak-complete-abab');prov=json.loads((wallet/'provenance.json').read_text());adm=TRIAL/('admission-'+protocol)
  for system in ['r1cs','vm']:
   app='A';source=wallet/'cold-A-r0-p0-r1cs.proof' if system=='r1cs' else wallet/'cold-A-r0-p0-vm'
   cmd=[adm/'bin/r1cs','shielded','rows','serve-admit','unused','0','unused'] if system=='r1cs' else [adm/'bin/vm','shielded','serve-admit',prov['elf']['A']['path'],'unused','unused']
   session=WarmSession(cmd,root/f'{protocol}-{system}-session')
   try:
    data=source.read_bytes() if system=='r1cs' else Path(str(source)+'.proof').read_bytes()
    mutations={}
    bad=bytearray(data);bad[len(bad)//2]^=1;mutations['tampered proof']=bytes(bad)
    if system=='r1cs':
     n=struct.unpack('<Q',data[:8])[0];assert 8+n*24+64<len(data)
     for name,offset in [('wrong statement',8+(n-1)*24),('substituted key',8+n*24+32),('transcript mutation',8+n*24)]:
      bad=bytearray(data);bad[offset]^=1;mutations[name]=bytes(bad)
     mutations['malformed shape']=data[:9]
    else: mutations['wrong statement']=data
    for case,mutated in mutations.items():
     tag=f'{protocol}-{system}-{CASES.index(case):02d}';prefix=root/tag;prefix.mkdir();incoming=prefix/'incoming'
     if system=='r1cs':incoming.write_bytes(mutated)
     else:
      Path(str(incoming)+'.proof').write_bytes(mutated);out=json.loads(Path(str(source)+'.output').read_text())
      if case=='wrong statement':out[0]^=1
      Path(str(incoming)+'.output').write_text(json.dumps(out))
     sample=session.request(incoming,'unused',prefix/'measurement',[],{'system':system,'case':case,'mode':'rejection','protocol_hash':protocol})
     verification=next((x for x in sample['reported'] if x.get('kind')=='verification'),{})
     results.append({'protocol':protocol,'system':system,'case':case,'status':'pass' if sample['returncode']==0 and verification.get('accepted') is False else 'fail','prover_prechecks_bypassed':True,'scope':'one post-proof complete-certificate mutation; wallet A only','evidence':str(prefix/'measurement/sample.json'),'mutated_sha256':digest(incoming if system=='r1cs' else Path(str(incoming)+'.proof'))})
     (root/'results-live.json').write_text(json.dumps(results,indent=2)+'\n')
   finally:session.close()
 # Existing sparse-tree example performs direct root/recorder mutations and emits its inventory.
 for protocol in ['blake2s','keccak']:
  merge=TRIAL/('complete-merges-'+protocol)
  sample=measure([merge/'bin/r1cs-node','mixed'],root/(protocol+'-r1cs-existing-probes'),timeout=600,labels={'system':'r1cs','case':'existing sparse verifier-target probes','mode':'rejection','protocol_hash':protocol})
  report=next((r for r in sample['reported'] if r.get('verified') and 'verifier_rejections' in r),{})
  mapping={'false carried evaluation':'false carried evaluation','substituted app key':'substituted key','omitted claim':'omitted claim','duplicated claim':'duplicated claim','wrong child kind':'wrong child kind','swapped children unchanged reduction':'reordered children unchanged digest','tampered child proof':'tampered proof','tampered root proof':'tampered proof'}
  for named in report.get('verifier_rejections',[]):
   if named in mapping:results.append({'protocol':protocol,'system':'r1cs','case':mapping[named],'status':'pass' if sample['returncode']==0 else 'fail','prover_prechecks_bypassed':True,'scope':'existing direct root verifier or verifier-recorder assertion: '+named,'evidence':str(root/(protocol+'-r1cs-existing-probes')/'sample.json')})
 coverage=[]
 for system in ['r1cs','vm']:
  for case in CASES:
   rows=[r for r in results if r['system']==system and r['case']==case]
   coverage.append({'system':system,'case':case,'status':'pass' if rows and all(r['status']=='pass' for r in rows) else ('fail' if rows else 'not measurable'),'evidence':[r['evidence'] for r in rows],'scope':'single wallet mutations across both protocols; not complete coordinator coverage' if rows else 'No direct complete-certificate mutation recipe implemented'})
 (root/'coverage.json').write_text(json.dumps({'cases':coverage,'samples':results,'neither_system_expresses_or_has_runnable_evidence':[c for c in CASES if not any(r['case']==c and r['status']=='pass' for r in coverage)],'warning':'Partial regression evidence, not a soundness theorem. Historical relation-specific tests are recorded separately.'},indent=2)+'\n')
 (root/'done.json').write_text(json.dumps({'finished_unix':time.time(),'samples':len(results)},indent=2)+'\n')
if __name__=='__main__':main()
