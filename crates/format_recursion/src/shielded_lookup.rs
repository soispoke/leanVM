//! Lookup-table prototype for the shielded spend.
//!
//! The production bus is `leanvm_core::leaf`: fixed table blocks push every
//! table row, a committed multiplicity column expands reads, and one batched
//! GKR grand product proves push/pull balance. This module fixes the exact
//! table domains and counts the rows that the spend emits. The experimental
//! `private_bridge::lookup` module binds this bus to the joint witness.

/// Fixed lookup domains proposed for the shielded relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// Every 16-bit value, used for range checks and 16-bit carry limbs.
    Range16,
    /// `(a,b) -> (a xor b, a and b)` for byte masks and equality/zero logic.
    ByteLogic,
    /// `(a,b,carry) -> (sum,carry_out)` for balance addition.
    ByteAdd,
}

pub fn small_tables() -> bool {
    static SMALL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SMALL.get_or_init(|| std::env::var_os("LOOKUP_SMALL").is_some())
}
pub fn table_log() -> usize {
    if small_tables() { 10 } else { 18 }
}

impl Table {
    /// Number of fixed rows in the table side of the bus.
    pub fn rows(self) -> usize {
        if small_tables() {
            return match self {
                Self::Range16 => 256,
                Self::ByteLogic => 256,
                Self::ByteAdd => 512,
            };
        }
        match self {
            Self::Range16 => 1 << 16,
            Self::ByteLogic => 1 << 16,
            Self::ByteAdd => 1 << 17,
        }
    }
    /// Canonical fixed tuple at an index. These columns are public/index data,
    /// never supplied by the prover.
    pub fn tuple(self, index: usize) -> Option<Vec<u64>> {
        if index >= self.rows() {
            return None;
        }
        let bits = if small_tables() { 4 } else { 8 };
        let mask = (1 << bits) - 1;
        Some(match self {
            Self::Range16 => vec![index as u64],
            Self::ByteLogic => {
                let a = (index & mask) as u64;
                let b = (index >> bits) as u64;
                vec![a, b, a ^ b, a & b]
            }
            Self::ByteAdd => {
                let a = (index & mask) as u64;
                let b = ((index >> bits) & mask) as u64;
                let carry = (index >> (2 * bits)) as u64;
                let sum = a + b + carry;
                vec![a, b, carry, sum & mask as u64, sum >> bits]
            }
        })
    }
    /// Return the table index only when every supplied coordinate matches the
    /// fixed table. This is witness generation/checking, not a lookup proof.
    pub fn index(self, values: &[u64]) -> Option<usize> {
        if values.len() != self.tuple_width() {
            return None;
        }
        let radix = if small_tables() { 16 } else { 256 };
        let range = if small_tables() { 256 } else { 65536 };
        let index = match self {
            Self::Range16 if values[0] < range => values[0] as usize,
            Self::ByteLogic if values[0] < radix && values[1] < radix => (values[0] + radix * values[1]) as usize,
            Self::ByteAdd if values[0] < radix && values[1] < radix && values[2] < 2 => {
                (values[0] + radix * values[1] + radix * radix * values[2]) as usize
            }
            _ => return None,
        };
        (self.tuple(index)?.as_slice() == values).then_some(index)
    }
    /// Number of tuple coordinates fingerprinted by the bus.
    pub const fn tuple_width(self) -> usize {
        match self {
            Self::Range16 => 1,
            Self::ByteLogic => 4,
            Self::ByteAdd => 5,
        }
    }
}

/// Canonical lookup-table columns, concatenated in this exact index order.
/// Every tuple includes a table tag and is zero-extended to six coordinates.
/// This public relation is never populated from witness values.
pub fn fixed_columns() -> [Vec<primitives::field::F64>; 6] {
    use primitives::field::F64;
    let mut columns: [Vec<F64>; 6] = std::array::from_fn(|_| Vec::with_capacity(1 << 18));
    for (tag, table) in [Table::Range16, Table::ByteLogic, Table::ByteAdd]
        .into_iter()
        .enumerate()
    {
        for index in 0..table.rows() {
            let tuple = table.tuple(index).expect("fixed table index");
            columns[0].push(F64(tag as u64));
            for (coordinate, column) in columns[1..].iter_mut().enumerate() {
                column.push(F64(tuple.get(coordinate).copied().unwrap_or(0)));
            }
        }
    }
    columns
}

/// Placement of the query table inside the *same* native arithmetic commitment.
/// There is no independently chosen query witness or query root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryLayout {
    /// Absolute row index, including public rows, of coordinate zero.
    pub start: usize,
    pub log_queries: usize,
    pub actual_queries: usize,
}
impl QueryLayout {
    pub fn coordinate_offset(&self, native_log_rows: usize, coordinate: usize, limb: usize) -> Option<usize> {
        let width = 1usize.checked_shl(self.log_queries as u32)?;
        let rows = 1usize.checked_shl(native_log_rows as u32)?;
        if coordinate >= 6 || limb >= 3 || self.start + 6 * width > rows {
            return None;
        }
        // Every copy row stores the original variable in the x column.
        Some(limb * rows + self.start + coordinate * width)
    }
}

/// The 148,272-row native shielded circuit's non-hash census.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Census {
    pub total_rows: usize,
    pub hash_rows: usize,
    pub swaps: usize,
    pub rules: usize,
    pub packing_and_decomposition: usize,
}

impl Census {
    pub const NATIVE: Self = Self {
        total_rows: 148_272,
        hash_rows: 106 * 16_384,
        swaps: 40_960,
        rules: 10_382,
        packing_and_decomposition: 148_272 - 40_960 - 10_382,
    };

    /// Conservative first pass: one lookup row replaces one Boolean arithmetic
    /// row for swaps/rules. Packing stays unchanged until BYTE_LOGIC is threaded
    /// through the hash bridge.
    pub const fn after_swap_rule_lookups(self) -> usize {
        self.total_rows - self.swaps - self.rules
    }

    /// If byte packing/decomposition is also table-backed, every non-hash row is
    /// a lookup read; this is the lower-bound row model, not a measured proof.
    pub const fn all_nonhash_lookup_lower_bound(self) -> usize {
        self.hash_rows
    }
}

/// A compact multiplicity vector for a fixed table. The table side is fixed in
/// the index; only this vector is witness data and is opened by the bus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Multiplicities {
    pub table: Table,
    pub counts: Vec<u64>,
}

impl Multiplicities {
    pub fn new(table: Table) -> Self {
        Self {
            table,
            counts: vec![0; table.rows()],
        }
    }
    pub fn add(&mut self, row: usize) {
        assert!(row < self.counts.len());
        self.counts[row] = self.counts[row].checked_add(1).expect("multiplicity overflow");
    }

    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }
    /// A wrong multiplicity cannot pass a bus balance check when the table
    /// fingerprint is nonzero; this is the local invariant checked by tests.
    pub fn same_multiset(&self, other: &Self) -> bool {
        self.table == other.table && self.counts == other.counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_tables_match_integer_semantics_and_reject_malformed_requests() {
        let bits = if small_tables() { 4 } else { 8 };
        let mask = (1u64 << bits) - 1;
        for a in 0..=mask {
            for b in 0..=mask {
                let logic = [a, b, a ^ b, a & b];
                assert!(Table::ByteLogic.index(&logic).is_some());
                for carry in 0..2 {
                    let sum = a + b + carry;
                    assert!(Table::ByteAdd.index(&[a, b, carry, sum & mask, sum >> bits]).is_some());
                    assert!(
                        Table::ByteAdd
                            .index(&[a, b, carry, (sum + 1) & mask, sum >> bits])
                            .is_none()
                    );
                }
            }
        }
        assert!(Table::Range16.index(&[65536]).is_none());
        assert!(Table::ByteAdd.index(&[256, 0, 0, 0, 1]).is_none());
    }
    #[test]
    fn domains_and_row_model_are_fixed() {
        assert_eq!(Table::Range16.rows(), 65_536);
        assert_eq!(Table::ByteLogic.rows(), 65_536);
        assert_eq!(Table::ByteAdd.rows(), 131_072);
        assert_eq!(Census::NATIVE.after_swap_rule_lookups(), 96_930);
        assert_eq!(Census::NATIVE.all_nonhash_lookup_lower_bound(), 106 * 16_384);
    }
    #[test]
    fn tampered_multiplicity_is_rejected() {
        let mut expected = Multiplicities::new(Table::ByteAdd);
        expected.add(0x0102);
        let mut tampered = expected.clone();
        tampered.counts[0x0102] ^= 1;
        assert!(!tampered.same_multiset(&expected));
    }
}
