#!/usr/bin/env python3
"""Validate archived receipt bytes without extracting executable contents."""
from pathlib import Path
import hashlib,json,tarfile
ROOT=Path(__file__).resolve().parent
archive=ROOT/'raw-evidence.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==(ROOT/'archive.sha256').read_text().split()[0]
with tarfile.open(archive,'r:gz') as tar:
 members=tar.getmembers()
 assert len({p.name for p in members})==len(members)
 assert all(p.isfile() and not Path(p.name).is_absolute() and '..' not in Path(p.name).parts for p in members)
 expected=json.load(tar.extractfile('archive-manifest.json'))
 assert set(expected)=={p.name for p in members}-{'archive-manifest.json'}
 for name,digest in expected.items():
  assert hashlib.sha256(tar.extractfile(name).read()).hexdigest()==digest,name
 for name in ['retention-audit.json','pgo-audit-expanded.json','links-audit-expanded.json','restart-reconciliation.json','restart-protocol.md']:
  assert (ROOT/name).read_bytes()==tar.extractfile(name).read(),name
report=json.loads((ROOT/'retention-audit.json').read_text())
assert report['ok'] and report['all_sizes_and_shapes_unchanged']
print(json.dumps(dict(ok=True,archive_files=len(expected),counts=report['counts'])))
