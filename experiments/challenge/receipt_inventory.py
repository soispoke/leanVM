#!/usr/bin/env python3
"""Count retained raw receipts without treating rejected requests as pass evidence."""
import json
from harness import TRIAL

FOLDERS = [
 'wallet-complete-abab','wallet-keccak-complete-abab',
 'complete-merges-blake2s','complete-merges-keccak',
 'admission-blake2s','admission-keccak','cold-complete-merges',
 'entry-2-referee','entry-4-referee','entry-5-referee',
 'entry-6-external-referee','entry-7-referee','entry-8-referee',
 'exact-wallet-blake2s','exact-wallet-keccak','root-series-entry-2',
]

def main():
 rows=[]
 for name in FOLDERS:
  folder=TRIAL/name
  samples=[]
  for path in folder.rglob('sample.json'):
   r=json.loads(path.read_text())
   samples.append(r)
  rows.append({'directory':name,'samples':len(samples),
   'successful_samples':sum(r.get('returncode')==0 for r in samples),
   'failed_samples':sum(r.get('returncode')!=0 for r in samples),
   'done':(folder/'done.json').is_file()})
 (TRIAL/'receipt-inventory.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(json.dumps(rows))
if __name__=='__main__':main()
