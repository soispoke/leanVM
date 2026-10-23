#!/usr/bin/env python3
import json
from pathlib import Path
from statistics import median

out = Path(__file__).resolve().parent
rows = [json.loads(s) for s in (out/'pinned.jsonl').read_text().splitlines()]
summary = {}
for case in ['shielded','merge']:
    digests = {r['source_program_digest'] for r in rows if r['case']==case}
    assert len(digests)==1
    for fmt in 'ABC':
        ps=[r for r in rows if r['case']==case and r['format']==fmt and r['mode']=='prove']
        vs=[r for r in rows if r['case']==case and r['format']==fmt and r['mode']=='verify']
        assert len(ps)==len(vs)==3 and all(v['verified'] for v in vs)
        item={}
        for samples, keys in [(ps,['wallet_s','source_witness_s','peak_rss_kib','additional_peak_rss_kib','proof_bytes','committed_words','setup_s','fixture_s']),
                              (vs,['verify_ms','matrix_eval_ms'])]:
            for key in keys:
                if key in samples[0]:
                    values=[r[key] for r in samples]
                    item[key]={'median':median(values),'min':min(values),'max':max(values)}
        item['census']=ps[0].get('census',{k:ps[0][k] for k in ['constraints','witness_variables_f192','r1cs_shadow_nonzeros'] if k in ps[0]})
        item['stage_census']=vs[0].get('stage_census')
        item['source_program_digest']=ps[0]['source_program_digest']
        summary[case+'-'+fmt]=item
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
components=[json.loads(s) for s in (out/'sparse-pcs-components.jsonl').read_text().splitlines()]
model={}
for case in ['shielded','merge']:
    parts={}
    for part in ['fixed','derefs']:
        samples=[r for r in components if r['case']==case and r['component']==part]
        assert len(samples)==3
        parts[part]={k:median(r[k] for r in samples) for k in ['commit_s','opening_s','verify_ms','proof_bytes','words']}
        assert len({json.dumps(r['recursive_census'],sort_keys=True) for r in samples})==1
        parts[part]['recursive_census']=samples[0]['recursive_census']
    model[case]={'components':parts,
       'wallet_subtotal_s':summary[case+'-B']['wallet_s']['median']+parts['fixed']['opening_s']+parts['derefs']['commit_s']+parts['derefs']['opening_s'],
       'additional_private_words':parts['derefs']['words'],
       'fixed_index_words':parts['fixed']['words'],
       'two_pcs_native_rows':sum(parts[p]['recursive_census']['native_rows'] for p in parts),
       'two_pcs_compressions':sum(parts[p]['recursive_census']['compressions'] for p in parts),
       'kind':'conditional separate-stack SPARK model; omits dereference construction, memory/product checks and their openings'}
(out/'modeled-costs.json').write_text(json.dumps(model,indent=2)+'\n')
print(json.dumps(model,indent=2))
