//! Application-independent byte tables for the L3b word-table experiment.
//!
//! This module defines the relation and sparse integer counters only. Host
//! membership checks are not a lookup proof, and these APIs do not accept proofs.
use std::collections::BTreeMap;

/// Exact fixed domains, in concatenation order. No modulus/application tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u64)]
pub enum Table {
    Logic8 = 1,
    Add8 = 2,
    Mul8 = 3,
}
pub const TABLES: [Table; 3] = [Table::Logic8, Table::Add8, Table::Mul8];
pub const TOTAL_ROWS: usize = 1 << 18;
/// Tag plus five coordinates. Unused coordinates are canonical zeroes.
pub type Tuple = [u64; 6];
impl Table {
    pub const fn rows(self) -> usize {
        match self {
            Self::Logic8 | Self::Mul8 => 1 << 16,
            Self::Add8 => 1 << 17,
        }
    }
    pub const fn offset(self) -> usize {
        match self {
            Self::Logic8 => 0,
            Self::Add8 => 1 << 16,
            Self::Mul8 => (1 << 16) + (1 << 17),
        }
    }
    /// Canonical table row; all arithmetic here is ordinary integer arithmetic.
    pub fn tuple(self, row: usize) -> Option<Tuple> {
        if row >= self.rows() {
            return None;
        }
        let a = (row & 255) as u64;
        let b = ((row >> 8) & 255) as u64;
        Some(match self {
            Self::Logic8 => [self as u64, a, b, a ^ b, a & b, 0],
            Self::Add8 => {
                let carry = (row >> 16) as u64;
                let sum = a + b + carry;
                [self as u64, a, b, carry, sum & 255, sum >> 8]
            }
            Self::Mul8 => {
                let product = a * b;
                [self as u64, a, b, product & 255, product >> 8, 0]
            }
        })
    }
    /// Host-side advice generation, not verifier enforcement.
    pub fn index(self, tuple: &Tuple) -> Option<usize> {
        if tuple[0] != self as u64 || tuple[1] >= 256 || tuple[2] >= 256 {
            return None;
        }
        let carry = if self == Self::Add8 {
            if tuple[3] >= 2 {
                return None;
            }
            tuple[3] as usize
        } else {
            0
        };
        let row = tuple[1] as usize + 256 * tuple[2] as usize + 65536 * carry;
        (self.tuple(row)?.as_ref() == tuple).then_some(row)
    }
}

/// Sparse integer counts, keyed by fixed concatenated row index. Repeated reads
/// increment an integer count; they never cancel in characteristic two.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Multiplicities(BTreeMap<usize, u64>);
impl Multiplicities {
    pub fn add(&mut self, table: Table, tuple: &Tuple) -> Option<()> {
        let row = table.offset() + table.index(tuple)?;
        let count = self.0.entry(row).or_default();
        *count = count.checked_add(1)?;
        Some(())
    }
    pub fn entries(&self) -> impl ExactSizeIterator<Item = (usize, u64)> + '_ {
        self.0.iter().map(|(&row, &count)| (row, count))
    }
    pub fn total(&self) -> Option<u64> {
        self.0.values().try_fold(0u64, |sum, count| sum.checked_add(*count))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_tables_exhaustively_match_integer_semantics() {
        assert_eq!(TABLES.iter().map(|t| t.rows()).sum::<usize>(), TOTAL_ROWS);
        for table in TABLES {
            for row in 0..table.rows() {
                let tuple = table.tuple(row).unwrap();
                assert_eq!(table.index(&tuple), Some(row));
                let [_, a, b, c, d, e] = tuple;
                match table {
                    Table::Logic8 => {
                        assert_eq!(c, a ^ b);
                        assert_eq!(d, a & b);
                        assert_eq!(e, 0);
                    }
                    Table::Add8 => assert_eq!(a + b + c, d + 256 * e),
                    Table::Mul8 => {
                        assert_eq!(a * b, c + 256 * d);
                        assert_eq!(e, 0);
                    }
                }
                for coordinate in 0..6 {
                    let mut wrong = tuple;
                    wrong[coordinate] ^= 512;
                    assert_eq!(table.index(&wrong), None);
                }
            }
            assert_eq!(table.tuple(table.rows()), None);
        }
    }

    #[test]
    fn sparse_counts_preserve_even_multiplicity_and_reject_bad_advice() {
        let mut counts = Multiplicities::default();
        let tuple = Table::Mul8.tuple(65535).unwrap();
        for _ in 0..2 {
            counts.add(Table::Mul8, &tuple).unwrap();
        }
        assert_eq!(counts.total(), Some(2));
        assert_eq!(counts.entries().collect::<Vec<_>>(), vec![(TOTAL_ROWS - 1, 2)]);
        let previous = counts.clone();
        let mut wrong = tuple;
        wrong[3] ^= 1;
        assert_eq!(counts.add(Table::Mul8, &wrong), None);
        assert_eq!(counts, previous);
    }
}
