//! The machine's custom instructions, the precompiles: each proven as one row rather than
//! as the RISC-V instructions it replaces. They exist on the VM only.

/// One extension-field instruction (custom-1, opcode `0x2b`) on the elements at `c`, `a` and `b`.
///
/// `FUNCT3` is the instruction: bit 0 accumulates into `c`, and bit 1 reads `b` as one base-field word.
///
/// # Safety
///
/// - `a` and `c` point to three readable words, and `c` to three writable ones.
/// - `b` points to three readable words, or one for a base-field `b`.
/// - Every word is 8-byte aligned.
#[inline(always)]
pub unsafe fn ext<const FUNCT3: u32>(c: *mut [u64; 3], a: *const [u64; 3], b: *const u64) {
    // SAFETY: the caller's pointers name what the instruction reads and writes, and nothing else.
    unsafe {
        core::arch::asm!(
            ".insn r 0x2b, {f3}, 0, {c}, {a}, {b}",
            f3 = const FUNCT3,
            c = in(reg) c,
            a = in(reg) a,
            b = in(reg) b,
            options(nostack, preserves_flags),
        );
    }
}
