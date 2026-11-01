#!/usr/bin/env python3
"""FCFS node arrivals at 1000 ms for 60 seconds, with queueing latency."""
import json,math,time
from pathlib import Path

def run(session, root, system, seconds=60):
    root=Path(root);root.mkdir(parents=True,exist_ok=False);begin=time.monotonic();rows=[]
    for i in range(seconds):
        scheduled=begin+i
        delay=scheduled-time.monotonic()
        if delay>0:time.sleep(delay)
        start=time.monotonic();output=root/f'node-{i}.certificate'
        sample=session.request('fixed-child-control',output,root/f'tick-{i}',[output],{'system':system,'case':'node cadence control','mode':'warm','round':i,'fixed_children':True},timeout=300)
        completed=time.monotonic()
        row={'arrival_s':i,'started_s':start-begin,'completed_s':completed-begin,'queue_delay_s':start-scheduled,'service_s':completed-start,'latency_s':completed-scheduled,'sample':str(root/f'tick-{i}'/'sample.json')};rows.append(row)
        (root/'arrivals.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
    elapsed=max(seconds,time.monotonic()-begin)
    latency=sorted(r['latency_s'] for r in rows);service=sorted(r['service_s'] for r in rows)
    result={'system':system,'arrivals':seconds,'arrival_interval_ms':1000,'arrival_window_s':seconds,'completed':len(rows),'drain_included_s':elapsed,'throughput_per_s':len(rows)/elapsed,'p95_latency_s':latency[math.ceil(.95*len(latency))-1],'p95_service_s':service[math.ceil(.95*len(service))-1],'backlog_at_60s':sum(r['completed_s']>seconds for r in rows),'scope':'repeated fixed-child node merge control; not the required three-application score node'}
    (root/'summary.json').write_text(json.dumps(result,indent=2)+'\n');return result
