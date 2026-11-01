#!/usr/bin/env python3
"""Wire existing VM direct deferred-checker regressions into retained receipts."""
import json,shutil,time
from harness import TRIAL,measure,digest

def main():
 root=TRIAL/'verifier-unit-rejections';root.mkdir(exist_ok=False);(root/'bin').mkdir();results=[]
 for protocol,log in [('blake2s','vm-verifier-rejection-build.jsonl'),('keccak','keccak-vm-verifier-rejection-build.jsonl')]:
  events=[]
  for line in (TRIAL/log).read_text().splitlines():
   try:events.append(json.loads(line))
   except ValueError:pass
  artifacts=[e for e in events if e.get('reason')=='compiler-artifact' and e.get('target',{}).get('name')=='verifiers' and e.get('executable')]
  assert artifacts,'no built verifier test binary for '+protocol
  source=artifacts[-1]['executable'];binary=root/'bin'/protocol;shutil.copyfile(source,binary);binary.chmod(0o755)
  sample=measure([binary,'deferred::','--test-threads=1','--nocapture'],root/protocol,timeout=300,labels={'system':'vm','case':'existing direct deferred checker regressions','mode':'rejection','protocol_hash':protocol})
  stdout=(root/protocol/'stdout.log').read_text();passed=sample['returncode']==0 and '2 passed; 0 failed' in stdout
  for case in ['false carried evaluation','malformed shape']:
   results.append({'system':'vm','protocol':protocol,'case':case,'status':'pass' if passed else 'fail','prover_prechecks_bypassed':True,'scope':'Direct Program::check_deferred mutation tests; tiny instruction program, rate MIN; not whole coordinator corpus','evidence':str(root/protocol/'sample.json'),'binary_sha256':digest(binary),'source_executable':source})
 (root/'coverage.json').write_text(json.dumps({'samples':results},indent=2)+'\n');(root/'done.json').write_text(json.dumps({'finished_unix':time.time(),'cases':len(results)},indent=2)+'\n')
if __name__=='__main__':main()
