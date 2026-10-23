#!/usr/bin/env python3
"""Verify source-bound archive bytes without extracting executable contents."""
import hashlib
import json
from pathlib import Path
import tarfile
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
    assert (ROOT/'results.json').read_bytes()==tar.extractfile('results.json').read()
report=json.loads((ROOT/'results.json').read_text())
assert report['ok'] and report['keys_and_geometry_stable_within_each_backend']
print(json.dumps({'ok':True,'archive_files':len(expected),'processes':report['processes'],'certificates':report['certificates']}))
