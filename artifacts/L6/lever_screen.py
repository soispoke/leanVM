"""Exact call/byte census; these are layout screens, not measured merge times."""
import json,pathlib
P=pathlib.Path('/root/yukon-autoresearch/workspaces/leanr1cs-closure-20261022')
def calls(n):return n//136+1
rows=[]
for arity,depth in [(2,16),(4,8),(16,4)]:
    rows.append(dict(lever='Merkle arity',arity=arity,leaves=65536,depth=depth,path_permutations=depth*calls(32*arity),sibling_bytes=depth*(arity-1)*32,node_bytes=32*arity,permutations_per_node=calls(32*arity)))
for leaf_bytes in [32,64,128,256,512,1024]:
    rows.append(dict(lever='leaf packing',leaf_bytes=leaf_bytes,permutations=calls(leaf_bytes),rate_utilization=leaf_bytes/(136*calls(leaf_bytes))))
for n in [1,2,3,4,8,16,32]:
    rows.append(dict(lever='transcript absorb packing',scalars=n,current_observe_plus_squeeze_calls=n+1,candidate_calls=calls(32+24*n+8),candidate_preimage_bytes=32+24*n+8,requires='new domain-separated absorb-block encoding mirrored in host and recorder; original grinding retained'))
for block_log,row_log in [(14,21),(15,22)]:
    rows.append(dict(lever='dense connector optimistic layout bound',blocks=1<<block_log,compiler_padded_rows=1<<row_log,connector_rows_17=17<<block_log,connector_rows_6=6<<block_log,rows_saved=11<<block_log,q_words=1<<(16-6+block_log),note='Metadata-only: six rows cannot directly hold 50 independent 64-bit lanes in three scalar columns; requires packed-limb binding. Sparse backend already uses explicit lane columns and explicit wrapper dimensions; this dense row subtraction is not a sparse implementation.'))
(P/'artifacts/L6-lever-layout-screen.json').write_text(json.dumps(rows,indent=2))
print(json.dumps(rows,indent=2))
