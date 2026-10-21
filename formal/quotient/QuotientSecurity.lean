import QuotientSecurity.Bits
import QuotientSecurity.RandomOracle
import QuotientSecurity.ZeroKnowledge
import QuotientSecurity.Encoding
import QuotientSecurity.NonInteractive
import QuotientSecurity.Distance
import QuotientSecurity.Instance
import QuotientSecurity.Circuit
import QuotientSecurity.Witness
import QuotientSecurity.Cantor
import QuotientSecurity.Assembly
import QuotientSecurity.CantorExists
import QuotientSecurity.Concrete
import QuotientSecurity.PublicWeight
import QuotientSecurity.ConcreteZK
import QuotientSecurity.Sequence
import QuotientSecurity.Joint
import QuotientSecurity.Statement
import QuotientSecurity.R1CS
import QuotientSecurity.Format
import QuotientSecurity.Described

/-- info: 'QuotientSecurity.verifier_rbrKnowledgeSoundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.verifier_rbrKnowledgeSoundness

/-- info: 'QuotientSecurity.rbrError_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.rbrError_le

/-- info: 'QuotientSecurity.knowledgeSoundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness

/-- info: 'QuotientSecurity.knowledgeSoundness_bits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_bits

/-- info: 'QuotientSecurity.realValues_uniform' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.realValues_uniform

/-- info: 'QuotientSecurity.baseValues_uniform' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.baseValues_uniform

/-- info: 'QuotientSecurity.Params.honest_consistent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.honest_consistent

/-- info: 'QuotientSecurity.Params.accepts_of_consistent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.accepts_of_consistent

/-- info: 'QuotientSecurity.realView_eq_simView' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.realView_eq_simView

/-- info: 'QuotientSecurity.realNI_eq_simNI' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.realNI_eq_simNI

/-- info: 'QuotientSecurity.card_not_good_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.card_not_good_le

/-- info: 'QuotientSecurity.zeroKnowledge' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.zeroKnowledge

/-- info: 'QuotientSecurity.zkError_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.zkError_le

/-- info: 'QuotientSecurity.sum_digitsEval' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.sum_digitsEval

/-- info: 'QuotientSecurity.Params.ofData_exact' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.ofData_exact

/-- info: 'QuotientSecurity.realValues_eq_simValues' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.realValues_eq_simValues

/-- info: 'QuotientSecurity.mle_eq_digitsEval_div' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.mle_eq_digitsEval_div

/-- info: 'QuotientSecurity.Params.card_consistent_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.card_consistent_le

/-- info: 'QuotientSecurity.mle_ones' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.mle_ones

/-- info: 'QuotientSecurity.exists_handles' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_handles

/-- info: 'QuotientSecurity.AdderCircuit.determined' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.AdderCircuit.determined

/-- info: 'QuotientSecurity.Params.exists_witness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.exists_witness

/-- info: 'QuotientSecurity.cells_determined' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.cells_determined

/-- info: 'QuotientSecurity.maskedValue_bijective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.maskedValue_bijective

/-- info: 'QuotientSecurity.input_is_bit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.input_is_bit

/-- info: 'QuotientSecurity.copy_iterate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.copy_iterate

/-- info: 'QuotientSecurity.word_pins' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.word_pins

/-- info: 'QuotientSecurity.gate_output' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.gate_output

/-- info: 'QuotientSecurity.Params.rowPoly_injOn' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.rowPoly_injOn

/-- info: 'QuotientSecurity.CantorBasis.digit_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.CantorBasis.digit_eq

/-- info: 'QuotientSecurity.CantorBasis.sum_cells' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.CantorBasis.sum_cells

/-- info: 'QuotientSecurity.mle_eq_tablePoly_eval' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.mle_eq_tablePoly_eval

/-- info: 'QuotientSecurity.sum_tablePoly' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.sum_tablePoly

/-- info: 'QuotientSecurity.mle_snoc' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.mle_snoc

/-- info: 'QuotientSecurity.claims_iff_accepts' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.claims_iff_accepts

/-- info: 'QuotientSecurity.witness_claim' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.witness_claim

/-- info: 'QuotientSecurity.wiring_claim' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.wiring_claim

/-- info: 'QuotientSecurity.quotient_mle' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.quotient_mle

/-- info: 'QuotientSecurity.sum_mle' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.sum_mle

/-- info: 'QuotientSecurity.tables_within_bounds' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.tables_within_bounds

/-- info: 'QuotientSecurity.natDegree_tablePoly_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.natDegree_tablePoly_le

/-- info: 'QuotientSecurity.exists_cantorBasis' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_cantorBasis

/-- info: 'QuotientSecurity.exists_cantorBasis_big' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_cantorBasis_big

/-- info: 'QuotientSecurity.knowledgeSoundness_ofCantor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_ofCantor

/-- info: 'QuotientSecurity.exists_instance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_instance

/-- info: 'QuotientSecurity.claims_iff_accepts_ofCantor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.claims_iff_accepts_ofCantor

/-- info: 'QuotientSecurity.Params.ofCantor_exact' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.ofCantor_exact

/-- info: 'QuotientSecurity.CantorBasis.exists_table' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.CantorBasis.exists_table

/-- info: 'QuotientSecurity.CantorBasis.point_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.CantorBasis.point_injective

/-- info: 'QuotientSecurity.exists_pub' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_pub

/-- info: 'QuotientSecurity.knowledgeSoundness_membership' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_membership

/-- info: 'QuotientSecurity.membershipPub_hPub' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.membershipPub_hPub

/-- info: 'QuotientSecurity.membership_target' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.membership_target

/-- info: 'QuotientSecurity.rowsPoly_eq_vRows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.rowsPoly_eq_vRows

/-- info: 'QuotientSecurity.CantorBasis.tablePoly_ext' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.CantorBasis.tablePoly_ext

/-- info: 'QuotientSecurity.coordPoly_point' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.coordPoly_point

/-- info: 'QuotientSecurity.completeness_prob' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.completeness_prob

/-- info: 'QuotientSecurity.completeness_ofCantor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.completeness_ofCantor

/-- info: 'QuotientSecurity.zeroKnowledge_ofCantor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.zeroKnowledge_ofCantor

/-- info: 'QuotientSecurity.zkError_ofCantor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.zkError_ofCantor

/-- info: 'QuotientSecurity.exists_subfield' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_subfield

/-- info: 'QuotientSecurity.zeroKnowledge_seq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.zeroKnowledge_seq

/-- info: 'QuotientSecurity.prob_not_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.prob_not_good

/-- info: 'QuotientSecurity.knowledgeSoundness_handles' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_handles

/-- info: 'QuotientSecurity.soundness_after' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.soundness_after

/-- info: 'QuotientSecurity.simRun_eq_simNI' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.simRun_eq_simNI

/-- info: 'QuotientSecurity.simulationSoundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.simulationSoundness

/-- info: 'QuotientSecurity.Instance.soundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.soundness

/-- info: 'QuotientSecurity.Instance.zero_knowledge' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.zero_knowledge

/-- info: 'QuotientSecurity.Instance.zero_knowledge_fresh' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.zero_knowledge_fresh

/-- info: 'QuotientSecurity.Instance.completeness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.completeness

/-- info: 'QuotientSecurity.Instance.honest_messages_fit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.honest_messages_fit

/-- info: 'QuotientSecurity.Instance.exists_instance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.exists_instance

/-- info: 'QuotientSecurity.Instance.sat_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.sat_iff

/-- info: 'QuotientSecurity.StructuredR1CS.aux_unique' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.StructuredR1CS.aux_unique

/-- info: 'QuotientSecurity.StructuredR1CS.row_extend_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.StructuredR1CS.row_extend_iff

/-- info: 'QuotientSecurity.StructuredR1CS.row_iff' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.StructuredR1CS.row_iff

/-- info: 'QuotientSecurity.Instance.r1cs_iff_relation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.r1cs_iff_relation

/-- info: 'QuotientSecurity.Instance.exists_r1cs_iff_relation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.exists_r1cs_iff_relation

/-- info: 'QuotientSecurity.Instance.r1cs_aux_unique' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.r1cs_aux_unique

/-- info: 'QuotientSecurity.Instance.r1cs_soundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.r1cs_soundness

/-- info: 'QuotientSecurity.firstRound_fits_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.firstRound_fits_iff

/-- info: 'QuotientSecurity.rbrError_le_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.rbrError_le_n

/-- info: 'QuotientSecurity.rbrError_first_gt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.rbrError_first_gt

/-- info: 'QuotientSecurity.knowledgeSoundness_bits_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_bits_n

/-- info: 'QuotientSecurity.Params.ofCantor_identity_eq' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.ofCantor_identity_eq

/-- info: 'QuotientSecurity.Params.ofCantor_identity_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.ofCantor_identity_n

/-- info: 'QuotientSecurity.Params.ofCantor_identity_le_64' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Params.ofCantor_identity_le_64

/-- info: 'QuotientSecurity.knowledgeSoundness_ofCantor_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_ofCantor_n

/-- info: 'QuotientSecurity.exists_instance_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.exists_instance_n

/-- info: 'QuotientSecurity.membershipPub_hPub_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.membershipPub_hPub_n

/-- info: 'QuotientSecurity.natDegree_membershipPub_le_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.natDegree_membershipPub_le_n

/-- info: 'QuotientSecurity.knowledgeSoundness_membership_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.knowledgeSoundness_membership_n

/-- info: 'QuotientSecurity.membership_target_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.membership_target_n

/-- info: 'QuotientSecurity.regionWeightN_twenty' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.regionWeightN_twenty

/-- info: 'QuotientSecurity.zkError_le_n' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.zkError_le_n

/-- info: 'QuotientSecurity.InstanceN.sat_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.sat_iff

/-- info: 'QuotientSecurity.InstanceN.soundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.soundness

/-- info: 'QuotientSecurity.InstanceN.exists_instance' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.exists_instance

/-- info: 'QuotientSecurity.InstanceN.r1cs_iff_relation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.r1cs_iff_relation

/-- info: 'QuotientSecurity.InstanceN.exists_r1cs_iff_relation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.exists_r1cs_iff_relation

/-- info: 'QuotientSecurity.InstanceN.r1cs_aux_unique' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.r1cs_aux_unique

/-- info: 'QuotientSecurity.InstanceN.r1cs_soundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.r1cs_soundness

/-- info: 'QuotientSecurity.InstanceN.honest_legal' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.honest_legal

/-- info: 'QuotientSecurity.InstanceN.zero_knowledge' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.zero_knowledge

/-- info: 'QuotientSecurity.InstanceN.completeness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.completeness

/-- info: 'QuotientSecurity.InstanceN.honest_messages_fit' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.honest_messages_fit

/-- info: 'QuotientSecurity.Instance.relation_toN' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.relation_toN

/-- info: 'QuotientSecurity.Instance.cellsOf_toN' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Instance.cellsOf_toN

/-- info: 'QuotientSecurity.Desc.eval_gate' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.eval_gate

/-- info: 'QuotientSecurity.Desc.eval_satisfies' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.eval_satisfies

/-- info: 'QuotientSecurity.Desc.gate_enc' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.gate_enc

/-- info: 'QuotientSecurity.Desc.regionWeightN_cellOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.regionWeightN_cellOf

/-- info: 'QuotientSecurity.Desc.wordSum_pack' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.wordSum_pack

/-- info: 'QuotientSecurity.Desc.pack_injective' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.pack_injective

/-- info: 'QuotientSecurity.Desc.bitIndex_of' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.bitIndex_of

/-- info: 'QuotientSecurity.Desc.fiberPerm_reach' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.fiberPerm_reach

/-- info: 'QuotientSecurity.Desc.wiringOf_reach' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.wiringOf_reach

/-- info: 'QuotientSecurity.Desc.wiringOf_wired' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.wiringOf_wired

/-- info: 'QuotientSecurity.InstanceN.statement_of_relation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.statement_of_relation

/-- info: 'QuotientSecurity.InstanceN.statementBits_of_relation' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.statementBits_of_relation

/-- info: 'QuotientSecurity.InstanceN.circuit_soundness' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.circuit_soundness

/-- info: 'QuotientSecurity.InstanceN.circuit_soundness_bits' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.InstanceN.circuit_soundness_bits

/-- info: 'QuotientSecurity.Desc.exists_instanceOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.exists_instanceOf

/-- info: 'QuotientSecurity.Desc.soundness_ofRows' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms QuotientSecurity.Desc.soundness_ofRows
