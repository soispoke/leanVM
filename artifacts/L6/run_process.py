import json, os, resource, subprocess, sys, time
out = sys.argv[1]
start = time.monotonic()
with open(out + '.stdout', 'w') as stdout, open(out + '.stderr', 'w') as stderr:
    p = subprocess.Popen(sys.argv[2:], stdout=stdout, stderr=stderr)
    pid, status, usage = os.wait4(p.pid, 0)
    p.returncode = os.waitstatus_to_exitcode(status)
receipt = {'command':sys.argv[2:], 'exit_code':p.returncode, 'whole_process_s':time.monotonic()-start, 'peak_rss_kib':usage.ru_maxrss}
with open(out + '.receipt.json','w') as f:json.dump(receipt,f,indent=2)
print(json.dumps(receipt))
sys.exit(p.returncode)
