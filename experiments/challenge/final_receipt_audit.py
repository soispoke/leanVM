#!/usr/bin/env python3
"""Read-only final audit of retained forwarded artifacts from referee suites."""
import json,time
from pathlib import Path
from harness import TRIAL,digest,deadline
from receipt_inventory import FOLDERS

def main():
 findings=[];samples=0;files=0;byte_count=0;late=[]
 for name in FOLDERS:
  for path in (TRIAL/name).rglob('sample.json'):
   r=json.loads(path.read_text());samples+=1
   if r.get('started_unix',0)+r.get('wall_s',0)>deadline():late.append(str(path))
   forwarded=r.get('forwarded_files',[])
   for f in forwarded:
    target=Path(f['path']);files+=1;byte_count+=f['bytes']
    if not target.is_file():findings.append({'receipt':str(path),'file':str(target),'issue':'missing'})
    elif target.stat().st_size!=f['bytes'] or digest(target)!=f['sha256']:findings.append({'receipt':str(path),'file':str(target),'issue':'size or digest mismatch'})
   if forwarded and sum(f['bytes'] for f in forwarded)!=r.get('forwarded_bytes'):
    findings.append({'receipt':str(path),'issue':'forwarded byte sum mismatch'})
 result={'checked_unix':time.time(),'scope':'Listed referee suites only; artifact integrity, not soundness or eligibility','samples':samples,'forwarded_file_references':files,'forwarded_bytes_references':byte_count,'findings':findings,'receipts_finishing_after_deadline':late}
 (TRIAL/'final-receipt-audit.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
if __name__=='__main__':main()
