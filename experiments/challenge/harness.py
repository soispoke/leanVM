#!/usr/bin/env python3
"""External trial runner. Measurements carry explicit boundary/coverage labels."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time

os.sched_setaffinity(0, set(range(48,64)))

TRIAL = Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022/artifacts/trial')

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()

def deadline():
    from datetime import datetime
    return datetime.fromisoformat(json.loads((TRIAL/'state.json').read_text())['deadline_utc'].replace('Z','+00:00')).timestamp()

def process_group_rss(group):
    total = 0; members = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit(): continue
        try:
            stat = (p/'stat').read_text().rsplit(')',1)[1].split()
            if int(stat[2]) != group: continue
            rss = int(stat[21]) * os.sysconf('SC_PAGE_SIZE')
            total += rss; members.append(int(p.name))
        except (OSError, ValueError, IndexError): pass
    return total, members

def measure(argv, dest, cwd=None, timeout=600, forwarded=(), labels=None):
    """No shell; fresh process group; simultaneous resident pages sampled every 5 ms."""
    dest=Path(dest); dest.mkdir(parents=True,exist_ok=False)
    if time.time() >= deadline(): raise RuntimeError('trial deadline reached')
    actual=['taskset','-c','36-47','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12']+list(map(str,argv))
    started=time.time(); begin=time.monotonic(); peak=0; samples=0; max_gap=0; last=begin; timed_out=False; max_members=0
    with (dest/'stdout.log').open('wb') as stdout, (dest/'stderr.log').open('wb') as stderr:
        proc=subprocess.Popen(actual,cwd=cwd,stdout=stdout,stderr=stderr,start_new_session=True)
        while True:
            now=time.monotonic(); max_gap=max(max_gap,now-last); last=now
            rss,members=process_group_rss(proc.pid); peak=max(peak,rss); max_members=max(max_members,len(members)); samples+=1
            status=proc.poll()
            if status is not None: break
            if now-begin > timeout or time.time() >= deadline():
                timed_out=True; os.killpg(proc.pid,signal.SIGKILL); proc.wait(); break
            time.sleep(.005)
    elapsed=time.monotonic()-begin
    # File flush and exit are included; the boundary is an upper bound when setup is inseparable.
    files=[]
    for name in forwarded:
        p=Path(name)
        if p.is_dir(): paths=sorted(x for x in p.rglob('*') if x.is_file())
        else: paths=[p]
        for f in paths:
            files.append({'path':str(f),'bytes':f.stat().st_size if f.exists() else None,'sha256':digest(f) if f.exists() else None})
    result={'argv':actual,'cwd':str(cwd) if cwd else None,'started_unix':started,'wall_s':elapsed,'returncode':proc.returncode,'timeout':timed_out,'process_group_peak_rss_bytes':peak,'rss_method':'5ms simultaneous /proc process-group RSS sum; shared pages counted per process; short-lived children may be missed; escaped groups not included','rss_samples':samples,'rss_max_gap_s':max_gap,'max_processes':max_members,'forwarded_files':files,'forwarded_bytes':sum(f['bytes'] for f in files) if files and all(f['bytes'] is not None for f in files) else None,'labels':labels or {},'binary_sha256':digest(argv[0]) if Path(argv[0]).is_file() else None}
    result['reported']=[]
    for line in (dest/'stdout.log').read_text(errors='replace').splitlines():
        try: result['reported'].append(json.loads(line))
        except ValueError: pass
    (dest/'sample.json').write_text(json.dumps(result,indent=2)+'\n')
    return result

def freeze(manifest, dest):
    import shutil
    m=json.loads(Path(manifest).read_text()); target=Path(dest)
    key=m.get('aggregate_key',{}).get('path')
    if not key or not Path(key).is_file(): raise ValueError('aggregate key bytes absent; held-out draw forbidden')
    objects=[key]+[b['path'] for b in m.get('binaries',[])]
    for owner in [m.get('aggregate_key',{}),m.get('setup',{})]:
        for item in owner.get('retained_artifacts',[])+owner.get('application_retained_artifacts',[]):objects.append(item['path'] if isinstance(item,dict) else item)
    for item in m.get('generators',{}).values():
        if item.get('path'):objects.append(item['path'])
    for name in ['claim_schema','frozen_surface','soundness_note']:
        if m.get(name):objects.append(m[name])
    objects=list(dict.fromkeys(objects));hashes={p:digest(p) for p in objects}
    for item in m.get('binaries',[]):
        if item.get('sha256') and hashes[item['path']]!=item['sha256']:raise ValueError('submitted binary hash mismatch')
    if m.get('aggregate_key',{}).get('sha256') and hashes[key]!=m['aggregate_key']['sha256']:raise ValueError('submitted aggregate-key hash mismatch')
    target.mkdir(parents=True,exist_ok=False);(target/'objects').mkdir()
    shutil.copyfile(manifest,target/'manifest.json');snapshots={}
    for i,p in enumerate(objects):
        name=target/'objects'/f'{i:03d}-{Path(p).name}';shutil.copyfile(p,name)
        if digest(name)!=hashes[p] or digest(p)!=hashes[p]:raise ValueError('object changed while freezing: '+p)
        snapshots[p]=str(name)
    shutil.copyfile(key,target/'aggregate-key.bin')
    record={'recorded_unix':time.time(),'manifest_sha256':digest(manifest),'hashes':hashes,'snapshots':snapshots,'entry':m['id'],'scope':'all declared key/setup artifacts, binary, generator bytes and interface notes; undeclared dependencies remain an audit concern'}
    (target/'freeze.json').write_text(json.dumps(record,indent=2)+'\n')
    return record

def check_freeze(frozen):
    record=json.loads((Path(frozen)/'freeze.json').read_text())
    for name,h in record['hashes'].items():
        if digest(name)!=h: raise ValueError('frozen object changed: '+name)
        snapshot=record.get('snapshots',{}).get(name)
        if snapshot and digest(snapshot)!=h:raise ValueError('snapshot changed: '+snapshot)
    return {'checked_unix':time.time(),'entry':record['entry'],'objects':len(record['hashes']),'unchanged':True}

def draw(frozen, out):
    check_freeze(frozen)
    record=json.loads((Path(frozen)/'freeze.json').read_text())
    import secrets, random
    seed=secrets.randbits(64); apps=random.Random(seed).sample(['merkle-keccak','keccak1k','mpt'],2)
    result={'entry':record['entry'],'freeze_sha256':digest(Path(frozen)/'freeze.json'),'draw_unix':time.time(),'seed':seed,'applications':apps,'scope':'draw only; admission must be demonstrated separately'}
    Path(out).write_text(json.dumps(result,indent=2)+'\n'); return result

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest='action',required=True)
    run=sub.add_parser('run'); run.add_argument('--out',required=True); run.add_argument('--cwd'); run.add_argument('--timeout',type=float,default=600); run.add_argument('--forwarded',action='append',default=[]); run.add_argument('command',nargs=argparse.REMAINDER)
    fr=sub.add_parser('freeze'); fr.add_argument('manifest'); fr.add_argument('out')
    dr=sub.add_parser('draw'); dr.add_argument('frozen'); dr.add_argument('out')
    a=ap.parse_args()
    if a.action=='run': result=measure(a.command[1:] if a.command[:1]==['--'] else a.command,a.out,a.cwd,a.timeout,a.forwarded)
    elif a.action=='freeze': result=freeze(a.manifest,a.out)
    else: result=draw(a.frozen,a.out)
    print(json.dumps(result))
    if a.action=='run' and result['returncode']!=0:raise SystemExit(1)
if __name__=='__main__': main()

class WarmSession:
    """One public-setup process, one fresh private input per JSON-line request."""
    def __init__(self, argv, directory, timeout=300):
        if time.time()>=deadline():raise TimeoutError('trial deadline before warm startup')
        import selectors
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=False)
        self.argv=list(map(str,argv));self.buffer=b'';self.reported=[];self.log=(self.directory/'stdout.log').open('ab');self.error=(self.directory/'stderr.log').open('wb')
        self.proc=subprocess.Popen(['taskset','-c','36-47','env','RAYON_NUM_THREADS=12','LEANVM_NUM_THREADS=12']+self.argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.error,start_new_session=True)
        self.selector=selectors.DefaultSelector();self.selector.register(self.proc.stdout,selectors.EVENT_READ)
        start=time.monotonic();self.setup_peak=0
        while True:
            self.setup_peak=max(self.setup_peak,process_group_rss(self.proc.pid)[0])
            for row in self.read_rows():
                self.reported.append(row)
                if row.get('kind')=='ready' or row.get('ready') is True:
                    self.setup_wall=time.monotonic()-start
                    (self.directory/'setup.json').write_text(json.dumps({'wall_s':self.setup_wall,'peak_rss_bytes':self.setup_peak,'reported':self.reported,'argv':self.argv,'binary_sha256':digest(self.argv[0])},indent=2)+'\n');return
            if self.proc.poll() is not None: raise RuntimeError('warm setup exited: '+str(self.directory))
            if time.monotonic()-start>timeout or time.time()>=deadline():self.close(force=True);raise TimeoutError('warm setup')
    def read_rows(self):
        rows=[]
        if self.selector.select(.005):
            chunk=os.read(self.proc.stdout.fileno(),65536)
            self.log.write(chunk);self.log.flush();self.buffer+=chunk
            while b'\n' in self.buffer:
                line,self.buffer=self.buffer.split(b'\n',1)
                try: rows.append(json.loads(line))
                except ValueError: pass
        return rows
    def request(self, input_path, output, sample_dir, forwarded, labels, timeout=300, command=None):
        if time.time()>=deadline():self.close(force=True);raise TimeoutError('trial deadline before request')
        d=Path(sample_dir);d.mkdir(parents=True,exist_ok=False);start=time.monotonic();t=time.time();peak=process_group_rss(self.proc.pid)[0];n=0;gap=0;last=start
        payload={'input':str(input_path),'output':str(output)}
        if command is not None:payload['command']=command
        self.proc.stdin.write((json.dumps(payload)+'\n').encode());self.proc.stdin.flush()
        while True:
            now=time.monotonic();gap=max(gap,now-last);last=now;peak=max(peak,process_group_rss(self.proc.pid)[0]);n+=1
            rows=self.read_rows()
            wallet=next((r for r in rows if r.get('kind') in ('wallet','merge','verification') or r.get('phase') in ('wallet','merge','root','admission')),None)
            if wallet is not None:break
            if self.proc.poll() is not None:raise RuntimeError('warm process exited: '+str(self.directory))
            if now-start>timeout or time.time()>=deadline():self.close(force=True);raise TimeoutError('warm request')
        elapsed=time.monotonic()-start
        paths=[]
        for name in forwarded:
            p=Path(name);paths.extend(sorted(x for x in p.rglob('*') if x.is_file()) if p.is_dir() else [p])
        files=[{'path':str(p),'bytes':p.stat().st_size,'sha256':digest(p)} for p in paths]
        result={'argv':self.argv,'started_unix':t,'wall_s':elapsed,'process_group_peak_rss_bytes':peak,'rss_method':'simultaneous process-group RSS, polling; retained public state and allocator pages included','rss_samples':n,'rss_max_gap_s':gap,'returncode':0,'forwarded_files':files,'forwarded_bytes':sum(f['bytes'] for f in files),'reported':rows,'labels':labels,'setup_record':str(self.directory/'setup.json'),'binary_sha256':digest(self.argv[0])}
        (d/'sample.json').write_text(json.dumps(result,indent=2)+'\n');return result
    def close(self, force=False):
        if self.proc.poll() is None and force:
            os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
        if self.proc.poll() is None:
            self.proc.stdin.close()
            try:self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:os.killpg(self.proc.pid,signal.SIGKILL);self.proc.wait()
        self.log.close();self.error.close();self.selector.close()
