//! What a guest reads and what it proves: `read` takes values from the advice, in place,
//! and `commit` makes values public. There are no system calls: the advice is memory the
//! prover fills before the run, at the addresses `link.ld` fixes, and the run's output is
//! the Keccak-256 digest of everything committed, in order, which the verifier recomputes from
//! the public values.

use crate::keccak::Keccak256;
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
use alloc::vec::Vec;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use vm::{commit, read, read_slice, read_unchecked};

/// A type made of 64-bit words and nothing else, so that any words are one.
///
/// # Safety
///
/// The type is `repr(C)` (or an array), its size a multiple of 8 and its alignment 8, it
/// has no padding, and every bit pattern of its words is a valid value: integers and arrays
/// of them, never a `bool`, an enum, a reference or a pointer.
pub unsafe trait Words: Sized + 'static {}

// SAFETY: a word is a word.
unsafe impl Words for u64 {}
// SAFETY: an array of word types is its elements' words, back to back.
unsafe impl<T: Words, const N: usize> Words for [T; N] {}

/// A value of a type from another crate as its words, for a host laying out advice that
/// the guest reads with `read_unchecked`.
///
/// # Safety
///
/// `T` is words only, as [`Words`] says.
pub const unsafe fn as_words_unchecked<T>(value: &T) -> &[u64] {
    const { assert_words::<T>() };
    // SAFETY: `T` is its words with no padding (the caller's).
    unsafe { core::slice::from_raw_parts((value as *const T).cast(), size_of::<T>() / 8) }
}

/// That `T` is whole, aligned words, at compile time.
const fn assert_words<T>() {
    assert!(
        size_of::<T>().is_multiple_of(8) && align_of::<T>() == 8,
        "a type of whole words"
    );
}

/// The public values a run commits, and the output they make: their Keccak-256 digest.
///
/// On the VM, `commit` feeds the run's own; off it, this is how a host computes the output
/// a guest must give.
pub struct PublicValues(Keccak256);

impl Default for PublicValues {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicValues {
    pub const fn new() -> Self {
        Self(Keccak256::new())
    }

    /// Commit a value.
    #[inline(always)]
    pub fn commit<T: Words>(&mut self, value: &T) -> &mut Self {
        // SAFETY: `T` is words only (`Words`).
        self.0.update_words(unsafe { as_words_unchecked(value) });
        self
    }

    /// The output: the digest of everything committed.
    pub fn digest(self) -> [u64; 4] {
        self.0.finalize_words()
    }
}

/// What one run of a guest is given, and what it must output.
///
/// A host builds it off the VM: the advice it lays out, and the digest of the public values it computes natively.
#[cfg(not(all(target_arch = "riscv64", target_os = "none")))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// The words the guest reads.
    pub advice: Vec<u64>,
    /// The output the guest must give: the digest of what it commits.
    pub expected: [u64; 4],
}

/// Streaming protocol commitment state, shared by VM and native checks.
#[cfg(any(test, all(target_arch = "riscv64", target_os = "none")))]
struct Public(Keccak256);
#[cfg(any(test, all(target_arch = "riscv64", target_os = "none")))]
impl Public {
    const fn new() -> Self {
        Self(Keccak256::new())
    }
    unsafe fn commit(this: *mut Self, words: &[u64]) {
        // SAFETY: caller exclusively owns this state.
        unsafe {
            (*this).0.update_words(words);
        }
    }
    unsafe fn finish(this: *mut Self) -> [u64; 4] {
        // SAFETY: caller exclusively owns the state and finishes only once.
        unsafe { core::ptr::read(this).0.finalize_words() }
    }
}

#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub(crate) mod vm {
    use super::{Public, Words, as_words_unchecked, assert_words};

    /// The output `_start` loads into `a0..a3` when the run ends.
    pub(crate) static mut OUTPUT: [u64; 4] = [0; 4];
    /// What the run has committed so far, streamed through the instruction's own block.
    // SAFETY: only the address of the static's message is taken, nothing is read.
    static mut PUBLIC: Public = Public::new();
    /// The advice words read so far.
    static mut READ: usize = 0;

    unsafe extern "C" {
        /// The advice region's bounds (`link.ld`).
        static __advice: u64;
        static __advice_top: u64;
    }

    /// The advice: words the prover supplies, which the statement says nothing about.
    fn advice() -> &'static [u64] {
        // The two symbols bound the region without belonging to one object, so the length
        // is address arithmetic rather than `offset_from`, which asks for one allocation.
        let (start, end) = (&raw const __advice, &raw const __advice_top);
        let words = (end as usize - start as usize) / size_of::<u64>();
        // SAFETY: the linker script reserves the region, it holds whole words, and nothing
        // in this crate writes it.
        unsafe { core::slice::from_raw_parts(start, words) }
    }

    /// The next value of the advice, in place: nothing is copied or decoded.
    ///
    /// The prover chose it, so the guest has to check it. Reading past the advice panics,
    /// so the run has no proof.
    #[inline(always)]
    pub fn read<T: Words>() -> &'static T {
        &read_slice::<T>(1)[0]
    }

    /// The next `n` values of the advice, in place.
    #[inline(always)]
    pub fn read_slice<T: Words>(n: usize) -> &'static [T] {
        // SAFETY: any words are a `T` (`Words`).
        unsafe { take(n) }
    }

    /// The next value of the advice as a type from another crate, in place: how a guest's
    /// `main` reads its library's types, which need not know the VM.
    ///
    /// # Safety
    ///
    /// `T` is words only, as [`Words`] says.
    #[inline(always)]
    pub unsafe fn read_unchecked<T>() -> &'static T {
        // SAFETY: the caller's.
        unsafe { &take::<T>(1)[0] }
    }

    /// # Safety
    ///
    /// `T` is words only, as [`Words`] says.
    #[inline(always)]
    unsafe fn take<T>(n: usize) -> &'static [T] {
        const { assert_words::<T>() };
        let words = n.checked_mul(size_of::<T>() / 8).expect("the values fit the advice");
        // SAFETY: one hart, no interrupts: nothing else touches `READ`.
        let start = unsafe { READ };
        let end = start.checked_add(words).expect("the values fit the advice");
        let taken = advice().get(start..end).expect("the values fit the advice");
        // SAFETY: as above.
        unsafe { READ = end };
        // SAFETY: the words are aligned to 8, as `T` is, and any words are a `T` (the caller's).
        unsafe { core::slice::from_raw_parts(taken.as_ptr().cast(), n) }
    }

    /// Make a value public: the run's output is the digest of everything committed, in order.
    #[inline(always)]
    pub fn commit<T: Words>(value: &T) {
        // SAFETY: one hart, no interrupts: nothing else touches `PUBLIC`, which is reached only by its address;
        // `T` is words only (`Words`).
        unsafe { Public::commit(&raw mut PUBLIC, as_words_unchecked(value)) }
    }

    /// Called by `_start` once `main` returns: the output is the digest of what was committed.
    pub(crate) extern "C" fn finish() {
        // SAFETY: as in `commit`; the run is over, so nothing touches `PUBLIC` after.
        let digest = unsafe { Public::finish(&raw mut PUBLIC) };
        // SAFETY: as above, for `OUTPUT`.
        unsafe { core::ptr::write_volatile(&raw mut OUTPUT, digest) }
    }
}

// TODO: remove this macro by making the advice region's size per proof rather than per program:
// the prover announces a power of two, bound into the transcript before any challenge and range
// checked by both verifiers (at most 2^26 words, inside the advice window). That is sound,
// the advice being the prover's anyway: a region too small traps the read past its end, one too
// large only costs the prover. `read` would then drop its bounds check against `__advice_top` and
// rely on that trap.
/// Size the guest's advice region, in words: a power of two.
///
/// A guest that names none gets 8192 words.
///
/// The prover commits to the whole region, so a guest sizes it to what it reads.
///
/// ```ignore
/// leanvm_guest::advice_words!(1 << 16);
/// ```
#[macro_export]
macro_rules! advice_words {
    ($words:expr) => {
        // The loader takes a region's size to be a power of two.
        const _: () = assert!(($words as u64).is_power_of_two(), "the advice region is a power of two");
        // An absolute symbol: the linker script places the region's end at the base plus its value.
        core::arch::global_asm!(
            ".globl __advice_bytes",
            ".set __advice_bytes, {bytes}",
            bytes = const 8 * ($words as u64),
        );
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use primitives::test_util::Rng;

    /// The digest `commit` gives for `words` committed `n` at a time: a `Public` as the VM's, made in place.
    fn committed(words: &[u64], n: usize) -> [u64; 4] {
        let mut public = Public::new();
        let this = &raw mut public;
        // SAFETY: this local state is exclusively owned and finalized once.
        unsafe {
            for piece in words.chunks(n) {
                Public::commit(this, piece);
            }
            Public::finish(this)
        }
    }

    #[test]
    fn commit_outputs_what_public_values_computes() {
        // Invariant: the run's output, the digest `commit` streams through its block, is the digest `PublicValues`
        // gives a host for the same words, however they are split into commits.
        //
        // Fixture: nothing committed, then every count through five blocks, so the last word falls at every offset of
        // a block and on its end; a word at a time, in pieces straddling blocks, and all at once.
        let mut rng = Rng::new(0xC0);
        let words: [u64; 40] = core::array::from_fn(|_| rng.next_u64());
        for len in 0..=40 {
            let mut host = PublicValues::new();
            for word in &words[..len] {
                host.commit(word);
            }
            let expected = host.digest();
            for n in [1, 3, 8, 9, 40] {
                assert_eq!(committed(&words[..len], n), expected, "{len} words, {n} at a time");
            }
        }
    }
}
