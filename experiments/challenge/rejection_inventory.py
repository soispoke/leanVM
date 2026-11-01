#!/usr/bin/env python3
"""Combine regression inventories without upgrading partial coverage to eligibility."""
import json
from harness import TRIAL
from rejections import CASES

def main():
 rows=[]
 for folder in ['certificate-rejections','merge-certificate-rejections','verifier-unit-rejections']:
  p=TRIAL/folder/'coverage.json'
  if p.exists():rows.extend(json.loads(p.read_text())['samples'])
 p=TRIAL/'entry-3-referee-rejections/sample.json'
 if p.exists():
  sample=json.loads(p.read_text());probes=[r for r in sample.get('reported',[]) if r.get('kind')=='rejection'];passed=sample['returncode']==0 and len(probes)==6 and all(r.get('rejected') and r.get('prover_prechecks_bypassed') for r in probes)
  rows.append({'system':'r1cs','protocol':'blake2s','case':'invalid signature','status':'pass' if passed else 'fail','prover_prechecks_bypassed':True,'scope':'Auxiliary entry 3 fixed-padded encoded Falcon; six mutations, no variable-length or composition claim; not the baseline reduced parser relation','evidence':str(p)})
 external=TRIAL/'entry-6-external-referee/rejections.json'
 if external.exists():rows.extend(json.loads(external.read_text()))
 coverage=[]
 for system in ['r1cs','vm']:
  for case in CASES:
   matches=[r for r in rows if r['system']==system and r['case']==case]
   coverage.append({'system':system,'case':case,'status':'fail' if any(r['status']=='fail' for r in matches) else ('partial regression pass' if matches else 'not measurable'),'evidence':matches})
 missing=[c for c in CASES if all(r['status']=='not measurable' for r in coverage if r['case']==c)]
 (TRIAL/'rejection-coverage.json').write_text(json.dumps({'cases':coverage,'neither_system_has_runnable_direct_evidence':missing,'full_suite_status':'not measurable','warning':'All positive rows are limited regression scopes, not complete coordinator coverage or a soundness theorem'},indent=2)+'\n');print(json.dumps({'evidence_rows':len(rows),'uncovered':missing}))
if __name__=='__main__':main()
