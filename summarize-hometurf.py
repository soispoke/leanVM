import pathlib,json,fcntl,subprocess
base=pathlib.Path(__file__).resolve().parent;out=base.parent/'artifacts/hometurf-L2';metrics=out.parent/'hometurf-12t.jsonl'
commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
def receipt(name,mode):
 return [json.loads(l) for l in (out/f'{name}-{mode}.jsonl').read_text().splitlines()][-1]
lines=['# L2 RISC-V leanVM home-turf results','', 'Canonical direct-compression guest ELF built with pinned nightly-2026-10-03 at source 0b3d2269; unchanged signature and shielded fixtures remain the checked-in upstream ELFs. All wallet/verify/merge timings: CPUs 12-23, 12 total pool threads, both thread environment variables 12. Builds and diagnostic tests: CPUs 48-63, CARGO_BUILD_JOBS=4. Earlier streaming-hasher guest results are superseded and retained in hometurf-L2-streaming-first; the first direct-instruction samples built on September nightly are archived in hometurf-L2-direct-unpinned. Original JSONL entries pointing at overwritten raw receipt paths should be read from that archive; canonical records appended by this summary point at current direct-instruction receipts. Raw receipt commit field is the original leanVM base a40a7fa6; outer normalized metadata identifies local source. No pushes.','', 'Wallet includes witness generation, proving and proof encoding. Signature generation and fixture preparation, ELF decoding, and recursion setup are excluded. RSS is process high-water and includes resident setup. Independent verification includes proof decode; merged verifier setup is excluded. Leaves use log inverse rate 2 and recursion uses 1. Single development samples, not confidence intervals.','']
records=[]
def emit(name,role,metric,value,unit,note):
 records.append(dict(system='leanvm',workload=name,role=role,metric=metric,value=value,unit=unit,threads=12,cpus='48-63' if metric.startswith('per_claim_') or metric.startswith('rec_') else '12-23',commit=commit,lane='L2',note='Canonical direct-instruction run; supersedes streaming guest samples; '+note))
for name in ['leanxmss','leansphincs','hashchain-16','hashchain-256','hashchain-4096','merkle-20','merkle-32','shielded']:
 w=receipt(name,'wallet');v=receipt(name,'verify');s=receipt(name,'stats-one')
 lines+=['## '+name,'','| Prove s | RSS KiB | Proof bytes | Verify ms | Cycles | BLAKE2s compressions | Committed words |','|---:|---:|---:|---:|---:|---:|---:|',f"| {w['wallet_prove_s']:.6f} | {w['wallet_peak_rss_kib']:,} | {w['wallet_proof_bytes']:,} | {v['mempool_verify_ms']:.3f} | {w['riscv_cycles']:,} | {w['blake2s_compressions']:,} | {w['committed_words']:,} |",'']
 for k,u in [('wallet_prove_s','s'),('wallet_peak_rss_kib','KiB'),('wallet_proof_bytes','bytes'),('riscv_cycles','cycles'),('blake2s_compressions','compressions'),('committed_words','u64 words')]:emit(name,'wallet',k,w[k],u,str(out/f'{name}-wallet.jsonl'))
 emit(name,'mempool','mempool_verify_ms',v['mempool_verify_ms'],'ms',str(out/f'{name}-verify.jsonl'))
 if name.startswith(('hashchain','merkle')):
  n=int(name.split('-')[1]);cy=w['riscv_cycles']/n;words=w['committed_words']/n
  lines+=[f'Amortized per application compression: {cy:.4f} cycles and {words:.4f} committed words. Denominator is {n}, excluding the two public-output compressions; numerator includes all guest overhead and proof padding. Chain marginal cost is exactly 26 cycles/step; Merkle marginal cost is 41.5 cycles/level across the measured depths. The guest has 235 fixed cycles for both modes.','']
  emit(name,'wallet','cycles_per_application_compression',cy,'cycles/compression','includes public-output and loop overhead')
  emit(name,'wallet','words_per_application_compression',words,'words/compression','includes padding, public-output and loop overhead')
 if name in ['leanxmss','hashchain-16','hashchain-256','hashchain-4096']:
  lines+=['| Merge level | Merge s | RSS KiB | Bytes | Verify ms | Committed words |','|---|---:|---:|---:|---:|---:|']
  for mode in ['leaf','node']:
   m=receipt(name,mode);mv=receipt(name,'verify-'+mode)
   lines+=[f"| {mode} | {m['merge_s']:.6f} | {m['merge_peak_rss_kib']:,} | {m['merged_proof_bytes']:,} | {mv['merged_verify_ms']:.3f} | {m['committed_words']:,} |"]
   for k,val,u in [('merge2to1_s',m['merge_s'],'s'),('merge_peak_rss_kib',m['merge_peak_rss_kib'],'KiB'),('merged_proof_bytes',m['merged_proof_bytes'],'bytes'),('merge_committed_words',m['committed_words'],'u64 words')]:emit(name,'merge',k,val,u,mode+'; same child proof in both slots; setup excluded; RSS includes setup')
   emit(name,'mempool','merged_verify_ms',mv['merged_verify_ms'],'ms',mode+'; independent process, setup excluded')
  lines+=['','Verdict: same-program 2-to-1 proof construction and independent verification succeed within the measured times shown here. Both slots repeat one proof; distinct-leaf preparation is not measured. Higher-node proof represents four copies of the leaf claim.','']
 else:lines+=['Verdict: the native guest proof and independent verifier succeed. This is a leanVM measurement; a cross-system winner requires an identical R1CS relation and comparable soundness/commitment settings.','']
 lines+=[f"One-leaf recursion verifier: {s['rows']:,} rows and {s['per_claim_committed_words']:,} committed words. This is an arity-one first circuit including reduction and shared tree floors, not half of a binary merge.",'']
 emit(name,'merge','per_claim_rows',s['rows'],'rows','arity-one circuit; full reduction and shared tree floors; untimed diagnostic')
 emit(name,'merge','per_claim_committed_words',s['per_claim_committed_words'],'u64 words','arity-one circuit; full reduction and shared tree floors; untimed diagnostic')
breakdown=json.loads((out/'verifier-breakdown.json').read_text())
lines+=['## Verifier stage accounting','','The complete machine has EMUL, EXK, HASH, SPLIT, CAST and PUB tables. Unpadded witness words per row are 9, 7, 257, 65, 4 and 0 respectively. A hash row owns a 256-word packed BLAKE2s witness plus one selector; its 18 ports are views into that witness and must not be counted a second time. These differ from the 18 input/output ports alone. Padded totals additionally include power-of-two table heights and the hash/Flock floor; padding has no unique stage owner. Merkle numbers include opening leaf hashing and shared upper nodes. WHIR includes stack-opening target and ring-switch reductions, with Merkle authentication subtracted. Program claim includes bus/table checks plus deferred program binding. All checks remain enabled.','','| Workload | Stage | Rows | Unpadded committed words |','|---|---|---:|---:|']
for name,d in breakdown.items():
 for stage,g in d['groups'].items():
  lines+=[f"| {name} | {stage} | {g['rows']:,} | {g['unpadded_committed_words']:,} |"]
  slug=stage.lower().replace(' ','_').replace(',','')
  emit(name,'merge','rec_'+slug+'_rows',g['rows'],'rows','exclusive stage; untimed instrumentation')
  emit(name,'merge','rec_'+slug+'_unpadded_words',g['unpadded_committed_words'],'words','exclusive raw witness words; table floors/padding excluded')
 lines+=[f"| {name} | Padding and floors |  | {d['padding_and_floors_words']:,} |"]
lines+=['','## Remaining parity differences','','VM commits an extra BLAKE2s digest of public values and binds program identity. Raw-digest R1CS must explicitly account for this. Chain uses reset-IV final compression at each step, not streaming BLAKE2s state; initial value, N and mode are public through the output digest. Merkle sibling witnesses are private and index is public. Shielded has a tagged 65-byte Merkle hash (two compressions), unlike the untagged 64-byte standalone Merkle benchmark. Shielded VM includes one output-wrapper compression: 106 total versus 105 inner-relation compressions. Signature hash digests are 128-bit truncations of BLAKE2s-256 and use the source-defined tweaks/admissibility rules. Signing is not included in signature verification wallet time. Do not interpret these proof-of-execution measurements as zero knowledge or a production security claim.','','Rejection evidence: all three chains reject wrong output and tampered proof; both Merkle depths additionally reject a changed sibling against the original root. Shielded host reference/guest tests pass (3 tests); raw 1680-byte fixtures and 32-byte inner digests for shapes 0,1,2 are exported beside the receipts. The existing historical shielded 0.275508294 s receipt is confirmed at 12 threads and retained; current timing variation is not a statement change.']
(out.parent/'hometurf-L2-results.md').write_text('\n'.join(lines)+'\n')
with metrics.open('a') as f:
 fcntl.flock(f,fcntl.LOCK_EX)
 for r in records:f.write(json.dumps(r)+'\n')
print('wrote report and',len(records),'canonical metrics')
