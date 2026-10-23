#!/usr/bin/env python3
"""Run one proof role in a fresh child and record whole-process wait4 RSS."""
import json
import os
import sys
import time

if len(sys.argv) < 3:
    raise SystemExit('usage: measure_keccak_rows.py OUTPUT_PREFIX COMMAND [ARGS...]')
prefix, command = sys.argv[1], sys.argv[2:]
start = time.monotonic()
pid = os.fork()
if pid == 0:
    out = os.open(prefix + '.stdout', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    err = os.open(prefix + '.stderr', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    os.dup2(out, 1)
    os.dup2(err, 2)
    os.execvp(command[0], command)
_, status, usage = os.wait4(pid, 0)
result = {'command': command, 'process_wall_s': time.monotonic() - start,
          'whole_process_peak_rss_kib': usage.ru_maxrss,
          'exit_code': os.waitstatus_to_exitcode(status)}
with open(prefix + '.process.json', 'w') as f:
    json.dump(result, f, indent=2)
print(json.dumps(result))
raise SystemExit(result['exit_code'])
