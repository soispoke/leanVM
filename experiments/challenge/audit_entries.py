#!/usr/bin/env python3
"""Read-only structural entry audit; capability declarations are not proof of gates."""
import json,time
from pathlib import Path
from harness import TRIAL,digest,check_freeze

def main():
 rows=[]
 for path in sorted((TRIAL/'entries').glob('*/manifest.json')):
  m=json.loads(path.read_text());problems=[];hashes=[]
  for obj in m.get('binaries',[])+list(m.get('generators',{}).values()):
   p=Path(obj['path']) if obj.get('path') else None
   actual=digest(p) if p and p.is_file() else None
   hashes.append({'path':str(p),'sha256':actual,'matches_declared':bool(actual and actual==obj.get('sha256'))})
   if actual!=obj.get('sha256') or actual is None:problems.append('Missing or mismatched artifact: '+str(p))
  for command in ['wallet','merge_first','merge_node','admission','root','reject']:
   if not m.get('commands',{}).get(command):problems.append('No separate runnable command: '+command)
  for name,g in m.get('generators',{}).items():
   if not g.get('application_id_keccak256'):problems.append('No published canonical generator Keccak ID: '+name)
  freeze=TRIAL/'freezes'/m['id'];frozen=None
  if freeze.exists():
   try:frozen=check_freeze(freeze)
   except (ValueError,OSError) as e:frozen={'unchanged':False,'error':str(e)};problems.append('Frozen surface check failed')
  else:problems.append('No recorded complete frozen-surface snapshot')
  retained={}
  for owner in [m.get('aggregate_key') or {},m.get('setup') or {}]:
   for a in owner.get('retained_artifacts',[])+owner.get('application_retained_artifacts',[]):
    p=Path(a['path'] if isinstance(a,dict) else a)
    retained[str(p)]=p.stat().st_size if p.is_file() else None
  rows.append({'entry':m['id'],'manifest':str(path),'manifest_sha256':digest(path),'checked_unix':time.time(),'structural_findings':problems,'artifact_hashes':hashes,'freeze_check':frozen,'unique_declared_retained_artifacts':retained,'retained_bytes':sum(v for v in retained.values() if v is not None),'admission_status':'not measurable unless actual complete certificates and held-out merges are supplied','score_eligible':False})
 (TRIAL/'entry-audit.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps([{'entry':r['entry'],'findings':len(r['structural_findings']),'freeze':r['freeze_check']} for r in rows]))
if __name__=='__main__':main()
