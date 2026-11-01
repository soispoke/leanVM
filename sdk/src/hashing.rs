//! Keccak-256 word templates and streams. All VM permutations use the Keccak instruction.
use crate::Keccak256;
use core::ops::Range;
mod plain {
    pub trait Plain: Copy {}
    impl Plain for u8 {}
    impl Plain for u16 {}
    impl Plain for u32 {}
    impl Plain for u64 {}
    impl<T: Plain, const N: usize> Plain for [T; N] {}
}
use plain::Plain;
pub struct Template<const W: usize> {
    words: [u64; W],
}
impl<const W: usize> Template<W> {
    pub const fn new(words: [u64; W]) -> Self {
        Self { words }
    }
    pub fn set<const N: usize>(&mut self, at: usize, words: [u64; N]) {
        self.words[at..at + N].copy_from_slice(&words);
    }
    pub fn write<T: Plain>(&mut self, at: usize, value: T) {
        assert!(
            at.is_multiple_of(align_of::<T>()) && size_of::<T>() <= 8 * W && at <= 8 * W - size_of::<T>(),
            "an aligned field inside the message"
        );
        // SAFETY: range and alignment checked; Plain values have no padding.
        unsafe {
            self.words.as_mut_ptr().byte_add(at).cast::<T>().write(value);
        }
    }
    pub fn digest(&mut self) -> [u64; 4] {
        let mut h = Keccak256::new();
        h.update_words(&self.words);
        h.finalize_words()
    }
    pub fn digest_prefix<const LEN: usize>(&mut self) -> [u64; 4] {
        assert!(LEN <= 8 * W);
        let mut h = Keccak256::new();
        // SAFETY: all words are initialized and the checked prefix is in bounds.
        let bytes = unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast(), LEN) };
        h.update(bytes);
        h.finalize_words()
    }
    pub fn chain<const COUNTER: usize, const VALUE: usize>(
        &mut self,
        counters: Range<u32>,
        mut value: [u64; 2],
    ) -> [u64; 2] {
        assert!(counters.start <= counters.end, "a chain of no negative length");
        for c in counters {
            self.write(COUNTER, c);
            self.write(VALUE, value);
            let d = self.digest();
            value = [d[0], d[1]];
        }
        value
    }
}
pub struct Stream<'a> {
    hasher: &'a mut Keccak256,
    pending: Option<u64>,
    written: usize,
}
impl Stream<'_> {
    pub fn write<const N: usize>(&mut self, words: [u64; N]) -> &mut Self {
        for word in words {
            if let Some(previous) = self.pending.replace(word) {
                self.hasher.update_words(&[previous]);
            }
            self.written += 8;
        }
        self
    }
    pub fn write_each<const N: usize>(&mut self, count: usize, mut array: impl FnMut(usize) -> [u64; N]) -> &mut Self {
        for i in 0..count {
            self.write(array(i));
        }
        self
    }
    fn flush(&mut self, len: usize) {
        assert!(
            len <= self.written && self.written < len + 8,
            "a length inside the message's last word"
        );
        if let Some(word) = self.pending.take() {
            self.hasher.update(&word.to_le_bytes()[..len + 8 - self.written]);
        }
    }
}
pub fn hash_with(write: impl FnOnce(&mut Stream<'_>)) -> [u64; 4] {
    let mut h = Keccak256::new();
    let mut stream = Stream {
        hasher: &mut h,
        pending: None,
        written: 0,
    };
    write(&mut stream);
    let len = stream.written;
    stream.flush(len);
    h.finalize_words()
}
pub fn hash_prefix_with<const LEN: usize>(write: impl FnOnce(&mut Stream<'_>)) -> [u64; 4] {
    let mut h = Keccak256::new();
    let mut stream = Stream {
        hasher: &mut h,
        pending: None,
        written: 0,
    };
    write(&mut stream);
    stream.flush(LEN);
    h.finalize_words()
}
#[cfg(test)]
mod tests {
    use super::*;
    use primitives::hash::{digest_words, hash};
    use primitives::test_util::Rng;

    /// The reference Keccak-256 of `bytes`, as little-endian words.
    fn reference(bytes: &[u8]) -> [u64; 4] {
        digest_words(&hash(bytes))
    }

    /// A template and the bytes its message should be, rewritten together.
    struct Mirror<const W: usize> {
        template: Template<W>,
        bytes: [u8; 64],
    }

    impl<const W: usize> Mirror<W> {
        fn new(words: [u64; W]) -> Self {
            let mut bytes = [0; 64];
            for (k, word) in words.iter().enumerate() {
                bytes[8 * k..8 * k + 8].copy_from_slice(&word.to_le_bytes());
            }
            Self {
                template: Template::new(words),
                bytes,
            }
        }

        fn put(&mut self, at: usize, le: &[u8]) {
            self.bytes[at..at + le.len()].copy_from_slice(le);
        }

        fn check(&mut self) {
            let expected = reference(&self.bytes[..8 * W]);
            assert_eq!(self.template.digest(), expected, "{W} words");
            assert_eq!(self.template.digest(), expected, "hashing leaves the message as it was");
        }
    }

    fn hashes_its_message<const W: usize>(rng: &mut Rng) {
        Mirror::<W>::new(core::array::from_fn(|_| rng.next_u64())).check();
    }

    #[test]
    fn a_template_is_the_keccak256_of_its_message() {
        // Invariant: a template of `W` words hashes as Keccak-256 of those `8W` bytes, the empty message included.
        let mut rng = Rng::new(0x7E3);
        hashes_its_message::<0>(&mut rng);
        hashes_its_message::<1>(&mut rng);
        hashes_its_message::<2>(&mut rng);
        hashes_its_message::<3>(&mut rng);
        hashes_its_message::<4>(&mut rng);
        hashes_its_message::<5>(&mut rng);
        hashes_its_message::<6>(&mut rng);
        hashes_its_message::<7>(&mut rng);
        hashes_its_message::<8>(&mut rng);
    }

    fn hashes_its_prefix<const LEN: usize>(rng: &mut Rng) {
        let mut mirror = Mirror::<7>::new(core::array::from_fn(|_| rng.next_u64()));
        // The last word keeps its first `LEN - 48` bytes.
        let last = rng.next_u64() & (u64::MAX >> (8 * (56 - LEN)));
        mirror.template.set(6, [last]);
        mirror.put(48, &last.to_le_bytes());
        assert_eq!(
            mirror.template.digest_prefix::<LEN>(),
            reference(&mirror.bytes[..LEN]),
            "{LEN} bytes"
        );
    }

    #[test]
    fn a_template_prefix_is_the_keccak256_of_those_bytes() {
        // Invariant: a message ending inside its last word, zero after it, hashes as Keccak-256 of its bytes alone.
        let mut rng = Rng::new(0x7E5);
        hashes_its_prefix::<49>(&mut rng);
        hashes_its_prefix::<52>(&mut rng);
        hashes_its_prefix::<56>(&mut rng);
    }

    /// A random offset of a `size`-byte field, aligned to its size and inside a message of `W` words.
    fn offset<const W: usize>(rng: &mut Rng, size: usize) -> usize {
        rng.next_u64() as usize % (8 * W / size) * size
    }

    fn rewrites<const W: usize>(rng: &mut Rng) {
        let mut mirror = Mirror::<W>::new(core::array::from_fn(|_| rng.next_u64()));
        mirror.check();
        for _ in 0..256 {
            let value = rng.next_u64();
            match rng.next_u64() % 7 {
                0 => {
                    let at = offset::<W>(rng, 8) / 8;
                    mirror.template.set(at, [value]);
                    mirror.put(8 * at, &value.to_le_bytes());
                }
                1 => {
                    let at = offset::<W>(rng, 8) / 8;
                    let at = at.min(W - 2);
                    mirror.template.set(at, [value, !value]);
                    mirror.put(8 * at, &value.to_le_bytes());
                    mirror.put(8 * at + 8, &(!value).to_le_bytes());
                }
                2 => {
                    let at = offset::<W>(rng, 1);
                    mirror.template.write(at, value as u8);
                    mirror.put(at, &[value as u8]);
                }
                3 => {
                    let at = offset::<W>(rng, 2);
                    mirror.template.write(at, value as u16);
                    mirror.put(at, &(value as u16).to_le_bytes());
                }
                4 => {
                    let at = offset::<W>(rng, 4);
                    mirror.template.write(at, value as u32);
                    mirror.put(at, &(value as u32).to_le_bytes());
                }
                5 => {
                    let at = offset::<W>(rng, 8);
                    mirror.template.write(at, value);
                    mirror.put(at, &value.to_le_bytes());
                }
                _ => {
                    // A digest-sized field at any word, not only at a multiple of its size.
                    let at = offset::<W>(rng, 8).min(8 * W - 16);
                    mirror.template.write(at, [value, !value]);
                    mirror.put(at, &value.to_le_bytes());
                    mirror.put(at + 8, &(!value).to_le_bytes());
                }
            }
            mirror.check();
        }
        // The last field of each width ends at the message's end, and is inside it.
        mirror.template.write(8 * W - 1, 0xA5u8);
        mirror.put(8 * W - 1, &[0xA5]);
        mirror.template.write(8 * W - 2, 0xA55Au16);
        mirror.put(8 * W - 2, &0xA55Au16.to_le_bytes());
        mirror.template.write(8 * W - 4, 0xA55A_5AA5u32);
        mirror.put(8 * W - 4, &0xA55A_5AA5u32.to_le_bytes());
        mirror.check();
    }

    #[test]
    fn a_rewritten_template_is_the_keccak256_of_its_new_message() {
        // Invariant: after any run of `set`s and `write`s, a template hashes the message those leave, as bytes in
        // little-endian words; hashing leaves the message as it was.
        //
        // Fixture: the chain step's shape (6 words), a whole block, and two words; a field of every width.
        let mut rng = Rng::new(0x7E4);
        rewrites::<2>(&mut rng);
        rewrites::<6>(&mut rng);
        rewrites::<8>(&mut rng);
    }

    #[test]
    #[should_panic(expected = "an aligned field inside the message")]
    fn write_rejects_a_misaligned_field() {
        Template::new([0; 6]).write(2, 0u32);
    }

    #[test]
    #[should_panic(expected = "an aligned field inside the message")]
    fn write_rejects_a_field_past_the_message_inside_the_block() {
        // Words 6 and 7 of the block are padding, not the message.
        Template::new([0; 6]).write(48, 0u32);
    }

    #[test]
    #[should_panic(expected = "an aligned field inside the message")]
    fn write_rejects_a_field_wider_than_the_message() {
        Template::new([0; 1]).write(0, [0u64; 2]);
    }

    #[test]
    #[should_panic(expected = "an aligned field inside the message")]
    fn write_rejects_an_offset_whose_end_would_wrap() {
        Template::new([0; 6]).write(usize::MAX, 0u8);
    }

    /// `chain::<COUNTER, VALUE>` over every length from 0 to 16 and a few first counters, against the reference
    /// Keccak-256 of each step's message; the template is left holding the last step's message.
    fn chains<const W: usize, const COUNTER: usize, const VALUE: usize>(rng: &mut Rng) {
        for first in [0, 1, 0x1234_5678, u32::MAX - 16] {
            for len in 0..=16 {
                let mut mirror = Mirror::<W>::new(core::array::from_fn(|_| rng.next_u64()));
                let start = [rng.next_u64(), rng.next_u64()];
                let mut value = start;
                for c in first..first + len {
                    mirror.put(COUNTER, &c.to_le_bytes());
                    mirror.put(VALUE, &value[0].to_le_bytes());
                    mirror.put(VALUE + 8, &value[1].to_le_bytes());
                    let [d0, d1, ..] = reference(&mirror.bytes[..8 * W]);
                    value = [d0, d1];
                }
                let chained = mirror.template.chain::<COUNTER, VALUE>(first..first + len, start);
                assert_eq!(
                    chained, value,
                    "counter at {COUNTER}, value at {VALUE}, {len} steps from {first}"
                );
                mirror.check();
            }
        }
    }

    #[test]
    fn a_chain_is_its_steps_hashed_in_turn() {
        // Invariant: `chain` is the fold of its steps, each writing its counter and the value, the value becoming the
        // digest's first two words; no steps return the value as given.
        //
        // Fixture: leanXMSS's and leanSPHINCS's shape (6 words, the counter in the tweak, the value after the
        // parameter), the counter after the value and in the last word, a whole block, and counters up to `u32::MAX`.
        let mut rng = Rng::new(0xC4A);
        chains::<6, 4, 32>(&mut rng);
        chains::<6, 44, 0>(&mut rng);
        chains::<4, 24, 0>(&mut rng);
        chains::<8, 0, 48>(&mut rng);
        chains::<8, 60, 8>(&mut rng);
    }

    #[test]
    #[should_panic(expected = "a chain of no negative length")]
    fn chain_rejects_a_reversed_range() {
        let (start, end) = (2, 1);
        Template::new([0; 6]).chain::<4, 32>(start..end, [0; 2]);
    }

    /// The reference Keccak-256 of up to 256 words, as little-endian bytes.
    fn reference_of_words(words: &[u64]) -> [u64; 4] {
        let mut bytes = [0; 8 * 256];
        for (k, word) in words.iter().enumerate() {
            bytes[8 * k..8 * k + 8].copy_from_slice(&word.to_le_bytes());
        }
        reference(&bytes[..8 * words.len()])
    }

    /// `hash_with` of `words`: the first `prefix` one at a time, then `N` at a time, the rest one at a time.
    fn in_pieces<const N: usize>(words: &[u64], prefix: usize) -> [u64; 4] {
        hash_with(|s| {
            let (head, rest) = words.split_at(prefix);
            for &word in head {
                s.write([word]);
            }
            let (pieces, tail) = rest.as_chunks::<N>();
            for &piece in pieces {
                s.write(piece);
            }
            for &word in tail {
                s.write([word]);
            }
        })
    }

    #[test]
    fn hash_with_is_the_keccak256_of_its_words() {
        // Invariant: whatever the pieces it is written in, `hash_with` hashes as Keccak-256 of the words' bytes.
        //
        // Fixture: every length from the empty message through one block, one block and a word, to five blocks, each
        // starting its pieces at every offset within a block, so that pieces straddle every block boundary. The stream
        // leaves the message unwritten until a word goes there, so a last block shorter than the one before still
        // holds that block's words past its end: each length that ends short of a block checks they hash as zeros.
        let mut rng = Rng::new(0x5E6);
        let words: [u64; 40] = core::array::from_fn(|_| rng.next_u64());
        for len in 0..=40 {
            let message = &words[..len];
            let expected = reference_of_words(message);
            for prefix in 0..=len.min(8) {
                let check = |digest, n| assert_eq!(digest, expected, "{len} words, {n} at a time after {prefix}");
                check(in_pieces::<1>(message, prefix), 1);
                check(in_pieces::<2>(message, prefix), 2);
                check(in_pieces::<3>(message, prefix), 3);
                check(in_pieces::<4>(message, prefix), 4);
                check(in_pieces::<8>(message, prefix), 8);
                check(in_pieces::<11>(message, prefix), 11);
            }
        }
    }

    /// `hash_prefix_with` of `LEN` random bytes, written a word at a time, against the reference of those bytes.
    fn streams_its_prefix<const LEN: usize>(rng: &mut Rng) {
        // The message's words: `LEN` random bytes, then zeros to the end of the last word.
        let mut bytes = [0u8; 8 * 40];
        bytes[..LEN].iter_mut().for_each(|b| *b = rng.next_u64() as u8);
        let words: [u64; 40] =
            core::array::from_fn(|k| u64::from_le_bytes(bytes[8 * k..8 * k + 8].try_into().unwrap()));
        let digest = hash_prefix_with::<LEN>(|s| {
            for &word in &words[..LEN.div_ceil(8)] {
                s.write([word]);
            }
        });
        assert_eq!(digest, reference(&bytes[..LEN]), "{LEN} bytes");
    }

    #[test]
    fn hash_prefix_with_is_the_keccak256_of_those_bytes() {
        // Invariant: the counter is the byte length, not the words written.
        //
        // Fixture: lengths ending at every kind of place.
        //
        //     1, 33, 63      inside the first block
        //     64             on its end: the block is the last one, compressed once
        //     65             one byte into a second block
        //     129, 265       three and five blocks, ending one byte past a block and a word
        let mut rng = Rng::new(0x9EF);
        streams_its_prefix::<1>(&mut rng);
        streams_its_prefix::<33>(&mut rng);
        streams_its_prefix::<63>(&mut rng);
        streams_its_prefix::<64>(&mut rng);
        streams_its_prefix::<65>(&mut rng);
        streams_its_prefix::<129>(&mut rng);
        streams_its_prefix::<265>(&mut rng);
    }

    /// `write_each` of `count` arrays of `N` words after `prefix` single words and before `suffix` more, against the
    /// reference of the same words; the arrays must be asked for once each, in order.
    fn writes_each<const N: usize>(words: &[u64; 256]) {
        for prefix in 0..=8 {
            for count in 0..=12 {
                for suffix in 0..=2 {
                    let len = prefix + N * count + suffix;
                    let mut next = 0;
                    let digest = hash_with(|s| {
                        for &word in &words[..prefix] {
                            s.write([word]);
                        }
                        s.write_each(count, |i| {
                            assert_eq!(i, next, "arrays asked for in order");
                            next += 1;
                            core::array::from_fn::<_, N, _>(|k| words[prefix + N * i + k])
                        });
                        for &word in &words[prefix + N * count..len] {
                            s.write([word]);
                        }
                    });
                    assert_eq!(next, count, "each array asked for once");
                    assert_eq!(
                        digest,
                        reference_of_words(&words[..len]),
                        "{count} arrays of {N} words after {prefix}, then {suffix}"
                    );
                }
            }
        }
    }

    #[test]
    fn write_each_puts_each_array_where_write_would() {
        // Invariant: `write_each(count, array)` is `write(array(i))` for `i` in order, whether it takes the block at a
        // time path (`N` divides 8 and the message is at a multiple of `N`) or the word at a time one.
        //
        // Fixture: arrays of every width dividing a block, and of 3, 5 and 16 words, which do not; empty arrays; every
        // starting offset in a block, up to 12 arrays (several blocks), then nothing or more words.
        let mut rng = Rng::new(0x5E7);
        let words = core::array::from_fn(|_| rng.next_u64());
        writes_each::<0>(&words);
        writes_each::<1>(&words);
        writes_each::<2>(&words);
        writes_each::<3>(&words);
        writes_each::<4>(&words);
        writes_each::<5>(&words);
        writes_each::<8>(&words);
        writes_each::<16>(&words);
    }
}
