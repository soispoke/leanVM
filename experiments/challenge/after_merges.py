import json,os,subprocess,time
from pathlib import Path
from harness import TRIAL,deadline
pid=447298
while True:
 try:os.kill(pid,0)
 except ProcessLookupError:break
 if time.time()>=deadline():raise SystemExit('deadline')
 time.sleep(1)
if not (TRIAL/'merge-controls/done.json').exists():raise SystemExit('merge suite stopped without success marker; inspect before continuing')
with (TRIAL/'wallet-complete-suite.log').open('wb') as f:
 result=subprocess.run(['python3',str(Path(__file__).with_name('wallet_qualified.py'))],stdout=f,stderr=subprocess.STDOUT)
(TRIAL/'followup-pipeline.json').write_text(json.dumps({'returncode':result.returncode,'completed_unix':time.time()},indent=2)+'\n')
