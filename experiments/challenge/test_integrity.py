import json,sys,tempfile,unittest
from pathlib import Path
from harness import freeze,draw,measure
from score import evaluate,GATES
class Integrity(unittest.TestCase):
 def test_no_heldout_draw_without_key(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);m=p/'manifest.json';m.write_text(json.dumps({'id':'missing','aggregate_key':{'path':None}}))
   with self.assertRaises(ValueError):freeze(m,p/'freeze')
   self.assertFalse((p/'freeze/freeze.json').exists())
 def test_mutated_binary_blocks_draw(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);key=p/'key';key.write_bytes(b'key');binary=p/'bin';binary.write_bytes(b'original');m=p/'manifest.json';m.write_text(json.dumps({'id':'test','aggregate_key':{'path':str(key)},'binaries':[{'path':str(binary)}]}));freeze(m,p/'freeze');binary.write_bytes(b'mutated')
   with self.assertRaises(ValueError):draw(p/'freeze',p/'draw.json')
   self.assertFalse((p/'draw.json').exists())
 def test_forged_pass_and_partial_score_are_not_eligible(self):
  e={'id':'test','gates':{'wallet_ram':{'status':'pass','scope_complete':True,'evidence':'/definitely/missing/receipt'}},'score_components':{'wallet_A':1,'wallet_B':2,'first_A_B':3}}
  result=evaluate(e);self.assertIsNone(result['score_s']);self.assertFalse(result['eligible']);self.assertEqual(next(g for g in result['gates'] if g['id']=='wallet_ram')['status'],'not measurable')
 def test_existing_file_cannot_authenticate_a_fabricated_complete_score(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'receipt.json';p.write_text('{}')
   entry={'id':'fabricated','both_matched_keccak_protocols':True,'gates':{g:{'status':'pass','scope_complete':True,'evidence':[str(p)]} for g in GATES},'score_components':{k:1.0 for k in ['wallet_A','wallet_B','first_A_B','node_AB_AH']},'score_component_evidence':{k:[str(p)]*10 for k in ['wallet_A','wallet_B','first_A_B','node_AB_AH']},'prerequisites':{k:'pass' for k in ['protocol_hash','security','frozen_aggregate_key','fresh_inputs','statement_parity','held_out_admission']}}
   result=evaluate(entry);self.assertFalse(result['eligible']);self.assertIsNone(result['score_s']);self.assertTrue(result['score_receipt_errors'])
if __name__=='__main__':unittest.main()
