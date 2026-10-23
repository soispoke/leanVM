#!/usr/bin/env python3
"""Verify the published archive without extracting executable contents."""
from pathlib import Path
import hashlib,json,tarfile
root=Path(__file__).resolve().parent
archive=root/'raw-evidence.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest()==(root/'archive.sha256').read_text().split()[0]
with tarfile.open(archive,'r:gz') as tar:
    members=tar.getmembers()
    assert len({m.name for m in members})==len(members)
    assert all(m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
    expected=json.load(tar.extractfile('archive-manifest.json'))
    assert set(expected)=={m.name for m in members}-{'archive-manifest.json'}
    for name,digest in expected.items():
        assert hashlib.sha256(tar.extractfile(name).read()).hexdigest()==digest,name
    assert (root/'results.json').read_bytes()==tar.extractfile('results.json').read()
r=json.loads((root/'results.json').read_text())
assert r['ok'] and not r['retained'] and r['proof_bytes_identical']
assert r['processes']==16 and r['certificates']==48
print(json.dumps({'ok':True,'archive_files':len(expected),'processes':r['processes'],'certificates':r['certificates']}))
