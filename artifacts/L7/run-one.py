#!/usr/bin/env python3
"""One fresh process: child ru_maxrss includes setup and verification when present."""
import json,resource,subprocess,sys,time
from pathlib import Path
prefix, *command = sys.argv[1:]
start=time.monotonic()
r = subprocess.run(command,capture_output=True,text=True)
elapsed=time.monotonic()-start
usage=resource.getrusage(resource.RUSAGE_CHILDREN)
Path(prefix+'.stdout').write_text(r.stdout)
Path(prefix+'.stderr').write_text(r.stderr)
record={'command':command,'elapsed_s':elapsed,'peak_rss_kib':usage.ru_maxrss,'exit_code':r.returncode}
Path(prefix+'.resources.json').write_text(json.dumps(record,indent=2)+'\n')
print(r.stdout,end='')
print(json.dumps(record),flush=True)
if r.returncode:
 print(r.stderr,file=sys.stderr)
 raise SystemExit(r.returncode)
