#!/usr/bin/env python3
"""Run explicit verifier-target recipes and retain unsupported-case coverage."""
import argparse,json
from pathlib import Path
from harness import measure
CASES=['tampered proof','wrong statement','invalid spend','invalid signature','false carried evaluation','substituted key','unauthenticated key','omitted claim','duplicated claim','duplicate identity different claims','wrong child kind','reordered children unchanged digest','malformed shape','malformed generator','transcript mutation','cross-version key','downgraded proof']
def run(config,out):
 root=Path(out);root.mkdir(parents=True,exist_ok=False);results=[]
 for system,recipes in config['systems'].items():
  for case in CASES:
   recipe=recipes.get(case)
   if recipe is None:
    results.append({'system':system,'case':case,'status':'not measurable','reason':'No runnable verifier-target recipe supplied'});continue
   sample=measure(recipe['argv'],root/f'{system}-{CASES.index(case):02d}',timeout=recipe.get('timeout',300),labels={'system':system,'case':case,'role':'rejection'})
   confirmation=recipe['confirmation'];confirmed=any(all(r.get(k)==v for k,v in confirmation.items()) for r in sample['reported'] if isinstance(r,dict))
   bypass=recipe.get('prover_prechecks_bypassed',False)
   status='pass' if sample['returncode']==0 and confirmed and bypass else ('fail' if sample['returncode']!=0 else 'not measurable')
   results.append({'system':system,'case':case,'status':status,'prover_prechecks_bypassed':bypass,'confirmation_found':confirmed,'evidence':str(root/f'{system}-{CASES.index(case):02d}'/'sample.json'),'coverage_note':recipe.get('coverage_note','single mutation only')})
 neither=[case for case in CASES if all(not any(r['system']==s and r['case']==case and r['status']=='pass' for r in results) for s in config['systems'])]
 result={'cases':results,'neither_system_expresses_or_has_runnable_evidence':neither,'warning':'Regression evidence only; no soundness theorem'}
 (root/'coverage.json').write_text(json.dumps(result,indent=2)+'\n');return result
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('config');ap.add_argument('out');a=ap.parse_args();print(json.dumps(run(json.loads(Path(a.config).read_text()),a.out)))
