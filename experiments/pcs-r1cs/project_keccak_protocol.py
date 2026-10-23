#!/usr/bin/env python3
"""Conditional layout model, not a re-recorded Keccak protocol merge."""
import json,math
from pathlib import Path

def power(x): return 1<<(x-1).bit_length()
def layout(rows,hashes,keccak):
 slots=power(max(hashes,8))
 # Keep 128 public rows and the measured arithmetic trace fixed. The changed
 # protocol must be re-recorded before these can become implementation counts.
 connector_start=((rows+128+slots-1)//slots)*slots
 occupied=connector_start+(17 if keccak else 6)*slots
 padded=power(max(occupied,8192))
 packed=slots*(1024 if keccak else 256)
 offset=((12*padded+packed-1)//packed)*packed
 return dict(projected_hash_slots=slots,projected_occupied_rows=occupied,projected_padded_rows=padded,projected_committed_words=offset+packed)
results={}
for name,rows,hashes,times in [('blake64',578847,14598,[.88,.97]),('shielded',736150,21990,[1.22,1.27])]:
 b=layout(rows,hashes,False);k=layout(rows,hashes,True)
 ratio=k['projected_committed_words']/b['projected_committed_words']
 results[name]={'assumptions':'fixed BLAKE trace, one Keccak permutation per BLAKE compression, unchanged public prefix; not a real Keccak-protocol merge census','blake_proxy':b,'keccak_proxy':k,'projected_word_ratio':ratio,'projected_merge_s_word_scaled':[t*ratio for t in times]}
print(json.dumps(results,indent=2))
Path('../artifacts/hometurf-L4k/protocol-projection.json').write_text(json.dumps(results,indent=2))
