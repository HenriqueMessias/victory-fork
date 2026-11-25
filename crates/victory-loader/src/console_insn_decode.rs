//! Instructions the console's CPU (Zen 2) has and a PC's may lack – a title raises
//! STATUS_ILLEGAL_INSTRUCTION on them on an Intel CPU before Ice Lake / Alder Lake (CLWB,
//! SHA) or on any Intel CPU (CLZERO, RDPRU, MONITORX / MWAITX and SSE4a's EXTRQ / INSERTQ,
//! which are AMD's). The exception handler (`eh`) emulates the ones decoded here and steps over
//! them.

/// A console-only instruction at the faulting address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleOnly {
    /// `clwb m8`: write a cache line back – nothing to do, the PC's memory is coherent
    Clwb,
    /// `clzero`: zero the 64-byte cache line at rAX
    Clzero,
    /// `clzero` loop: `clzero; add rax, 0x40; cmp rax, <reg>; jb -12` – zero `[rax..reg)`
    ClzeroLoop { end_reg: u8 },
    /// `rdpru`: ecx = 0 MPERF / 1 APERF → edx:eax (a counter)
    Rdpru,
    /// `monitorx` / `mwaitx`: a wait the emulation skips
    Monitorx,
    Mwaitx,
    /// `rdpid r64`: TSC_AUX (the processor number) into the register (CONTEXT order: rax, rcx,
    /// rdx, rbx, rsp, rbp, rsi, rdi, r8..r15)
    Rdpid(u8),
    /// SSE4a `extrq xmm, imm8 (length), imm8 (index)` / `extrq xmm1, xmm2` (`src` Some: the
    /// length and index in xmm2's bits 5:0 and 13:8): a bit field of the low quadword, moved
    /// down and zero-extended (the high quadword zeroed). Registers are XMM numbers 0..15.
    Extrq { dst: u8, src: Option<u8>, len: u8, idx: u8 },
    /// SSE4a `insertq xmm1, xmm2, imm8 (length), imm8 (index)` / `insertq xmm1, xmm2` (`reg`:
    /// the length and index in xmm2's bits 69:64 and 77:72): the low bits of xmm2 put into a
    /// bit field of xmm1's low quadword.
    Insertq { dst: u8, src: u8, reg: bool, len: u8, idx: u8 },
    /// `ud2`: the title's own trap (not emulated)
    Ud2,
}

/// A field length of SSE4a's six bits: 0 is 64.
fn field_len(len: u8) -> u32 {
    match len & 63 {
        0 => 64,
        n => n as u32,
    }
}

/// EXTRQ on a low quadword: `len` bits from bit `idx`, zero-extended (a field past bit 63 is
/// undefined on the console; here it is what a shift gives).
pub fn extrq(v: u64, len: u8, idx: u8) -> u64 {
    let (len, idx) = (field_len(len), (idx & 63) as u32);
    let field = v.checked_shr(idx).unwrap_or(0);
    if len >= 64 {
        field
    } else {
        field & ((1u64 << len) - 1)
    }
}

/// INSERTQ on a low quadword: the low `len` bits of `src` put at bit `idx` of `dst`.
pub fn insertq(dst: u64, src: u64, len: u8, idx: u8) -> u64 {
    let (len, idx) = (field_len(len), (idx & 63) as u32);
    let ones = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
    let mask = ones.checked_shl(idx).unwrap_or(0);
    (dst & !mask) | ((src & ones).checked_shl(idx).unwrap_or(0) & mask)
}

/// The length of a ModRM-encoded operand (ModRM, SIB and displacement) at `b[0]`, None when the
/// bytes run out.
fn modrm_len(b: &[u8]) -> Option<usize> {
    let modrm = *b.first()?;
    let (md, rm) = (modrm >> 6, modrm & 7);
    if md == 3 {
        return Some(1);
    }
    let mut len = 1;
    let mut base = rm;
    if rm == 4 {
        base = *b.get(1)? & 7;
        len += 1;
    }
    len += match md {
        0 if base == 5 => 4, // disp32 (rip-relative, or a SIB without a base)
        0 => 0,
        1 => 1,
        _ => 4,
    };
    (b.len() >= len).then_some(len)
}

/// The console-only instruction at the start of `code` and its length.
pub fn decode(code: &[u8]) -> Option<(ConsoleOnly, usize)> {
    let mut i = 0;
    // `rep`: the last of F2 / F3, which decides between them (and over 66) for SSE4a
    let (mut p66, mut pf3, mut rep, mut rex) = (false, false, 0u8, 0u8);
    while let Some(&b) = code.get(i) {
        match b {
            0x66 => p66 = true,
            0xF2 => rep = 0xF2,
            0xF3 => {
                pf3 = true;
                rep = 0xF3;
            }
            0x2E | 0x3E | 0x26 | 0x36 | 0x64 | 0x65 | 0x67 => {}
            // REX counts only right before the opcode: one before a legacy prefix is ignored
            0x40..=0x4F => {
                rex = b;
                i += 1;
                continue;
            }
            _ => break,
        }
        rex = 0;
        i += 1;
    }
    if *code.get(i)? != 0x0F {
        return None;
    }
    match (*code.get(i + 1)?, code.get(i + 2).copied()) {
        (0x01, Some(0xFC)) => {
            // clzero (0F 01 FC); add rax, 0x40 (48 83 C0 40); cmp rax, <reg> ([48|4C] 39 modrm, rax
            // in r/m); jb -12 (72 F4)
            // (not after an 0x67: that CLZERO is at EAX, and the jb goes back to the 0F, past the
            // prefix – it is stepped alone, the loop is taken from the next one)
            if code.len() >= i + 12
                && !code[..i].contains(&0x67)
                && code[i + 3..i + 7] == [0x48, 0x83, 0xC0, 0x40]
                && (code[i + 7] == 0x48 || code[i + 7] == 0x4C)
                && code[i + 8] == 0x39
                && code[i + 9] & 0xC7 == 0xC0
                && code[i + 10..i + 12] == [0x72, 0xF4]
            {
                let rex_r = code[i + 7] == 0x4C;
                let modrm = code[i + 9];
                let reg_idx = ((modrm >> 3) & 7) | if rex_r { 8 } else { 0 };
                Some((ConsoleOnly::ClzeroLoop { end_reg: reg_idx }, i + 12))
            } else {
                Some((ConsoleOnly::Clzero, i + 3))
            }
        }
        (0x01, Some(0xFD)) => Some((ConsoleOnly::Rdpru, i + 3)),
        (0x01, Some(0xFA)) => Some((ConsoleOnly::Monitorx, i + 3)),
        (0x01, Some(0xFB)) => Some((ConsoleOnly::Mwaitx, i + 3)),
        (0x0B, _) => Some((ConsoleOnly::Ud2, i + 2)),
        // SSE4a: register operands only (ModRM mod 3); REX.R extends reg, REX.B rm
        // (the last of F2 / F3 decides: F2 INSERTQ, F3 #UD; neither with 66: EXTRQ)
        (0x78 | 0x79, Some(m)) if (rep == 0xF2 || (rep == 0 && p66)) && m >> 6 == 3 => {
            let reg = ((m >> 3) & 7) | (rex & 4) << 1;
            let rm = (m & 7) | (rex & 1) << 3;
            let imm = |k: usize| code.get(i + 3 + k).copied();
            match (code[i + 1], rep == 0xF2) {
                // extrq xmm(rm), imm8, imm8 – the ModRM reg field is /0
                (0x78, false) if (m >> 3) & 7 == 0 => Some((ConsoleOnly::Extrq { dst: rm, src: None, len: imm(0)?, idx: imm(1)? }, i + 5)),
                (0x79, false) => Some((ConsoleOnly::Extrq { dst: reg, src: Some(rm), len: 0, idx: 0 }, i + 3)),
                (0x78, true) => Some((ConsoleOnly::Insertq { dst: reg, src: rm, reg: false, len: imm(0)?, idx: imm(1)? }, i + 5)),
                (0x79, true) => Some((ConsoleOnly::Insertq { dst: reg, src: rm, reg: true, len: 0, idx: 0 }, i + 3)),
                _ => None,
            }
        }
        // 66 0F AE /6 with a memory operand (without 66 it is xsaveopt)
        (0xAE, Some(m)) if p66 && (m >> 3) & 7 == 6 && m >> 6 != 3 => Some((ConsoleOnly::Clwb, i + 2 + modrm_len(&code[i + 2..])?)),
        // F3 0F C7 /7 with a register operand
        (0xC7, Some(m)) if pf3 && (m >> 3) & 7 == 7 && m >> 6 == 3 => Some((ConsoleOnly::Rdpid((m & 7) | (rex & 1) << 3), i + 3)),
        _ => None,
    }
}

/// The second opcode byte of `clwb` (`66 0F AE /6`) and of the NOP it is made by changing that
/// byte alone (`66 0F 1F /6`, the same operand, so the same length). A write of one byte is
/// seen whole or not at all, wherever the instruction lies: another processor fetches the one
/// instruction or the other. With NOPs written over its 4 and more bytes another processor
/// could fetch some of them: after a `90` in place of the `66` the rest is `xsaveopt`, which
/// stores the processor's state where the `clwb` pointed (265 bytes changed on a Haswell).
pub const CLWB_OPCODE: u8 = 0xAE;
pub const NOP_OPCODE: u8 = 0x1F;

/// Where the second opcode byte of the instruction at the start of `code` is, if it is a
/// `clwb` or the NOP made of one (no prefix is an `0F`).
pub fn clwb_opcode(code: &[u8]) -> Option<usize> {
    let at = code.iter().position(|&b| b == 0x0F)? + 1;
    matches!(code.get(at), Some(&CLWB_OPCODE | &NOP_OPCODE)).then_some(at)
}

/// The length of the NOP made of a `clwb` at the start of `code`: what a thread finds that
/// faulted on the `clwb` just before another one changed it.
pub fn clwb_made_nop(code: &[u8]) -> Option<usize> {
    let at = clwb_opcode(code).filter(|&at| code[at] == NOP_OPCODE)?;
    // As long as any instruction; no heap, in an exception handler.
    let mut was = [0u8; 16];
    let n = code.len().min(was.len());
    was[..n].copy_from_slice(&code[..n]);
    *was.get_mut(at)? = CLWB_OPCODE;
    match decode(&was[..n]) {
        Some((ConsoleOnly::Clwb, len)) => Some(len),
        _ => None,
    }
}

/// The passes of a `clzero` loop from `start` ([`ConsoleOnly::ClzeroLoop`]): its test comes
/// last, so there is one whatever `end` is.
pub fn clzero_passes(start: u64, end: u64) -> u64 {
    end.saturating_sub(start).div_ceil(64).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every form of `clwb` is told from the NOP made of it, whose length is the same; no
    /// other instruction passes for one.
    #[test]
    fn a_clwb_and_the_nop_made_of_it() {
        let forms: [&[u8]; 7] = [
            &[0x66, 0x0F, 0xAE, 0x30],
            &[0x66, 0x0F, 0xAE, 0x71, 0x40],
            &[0x66, 0x0F, 0xAE, 0x74, 0x24, 0x08],
            &[0x66, 0x0F, 0xAE, 0x35, 1, 2, 3, 4],
            &[0x66, 0x41, 0x0F, 0xAE, 0x30],
            &[0x66, 0x67, 0x0F, 0xAE, 0x30],
            // a displacement with both opcode bytes in it
            &[0x66, 0x0F, 0xAE, 0xB0, 0x0F, 0xAE, 0x0F, 0x1F],
        ];
        for form in forms {
            // What follows it is of no account.
            let mut code = [form, &[0x0F, 0xAE, 0x30, 0x66, 0xCC]].concat();
            assert_eq!(decode(&code), Some((ConsoleOnly::Clwb, form.len())));
            assert_eq!(clwb_made_nop(&code), None);
            let at = clwb_opcode(&code).unwrap();
            code[at] = NOP_OPCODE;
            assert_eq!(decode(&code), None, "{code:02x?}");
            assert_eq!(clwb_made_nop(&code), Some(form.len()), "{code:02x?}");
            assert_eq!(clwb_opcode(&code), Some(at));
        }
        // a compiler's NOP (/0), one without 66, NOPs, a cut-off one, clflushopt, nothing
        let others: [&[u8]; 6] =
            [&[0x66, 0x0F, 0x1F, 0x00], &[0x0F, 0x1F, 0x30], &[0x90; 4], &[0x66, 0x0F, 0x1F], &[0x66, 0x0F, 0xAE, 0x38], &[]];
        for other in others {
            assert_eq!(clwb_made_nop(other), None, "{other:02x?}");
        }
    }

    /// Against the loop's own instructions, pass by pass.
    #[test]
    fn clzero_loops_pass_as_often_as_the_instructions() {
        for start in [0u64, 5, 64, 4096] {
            for end in [0u64, 1, 5, 63, 64, 65, 69, 128, 4096, 4097, 4160, 10_000] {
                let (mut rax, mut passes) = (start, 0);
                loop {
                    passes += 1;
                    rax += 64;
                    if rax >= end {
                        break;
                    }
                }
                assert_eq!(clzero_passes(start, end), passes, "{start}..{end}");
            }
        }
        assert_eq!(clzero_passes(0, 6 << 30), (6 << 30) / 64);
        assert_eq!(clzero_passes(u64::MAX, 0), 1);
        assert_eq!(clzero_passes(0, u64::MAX), 1 << 58);
    }

    /// A loop whose `cmp` is not of `rax` (a register or memory in its place) is taken one
    /// `clzero` at a time.
    #[test]
    fn a_loop_that_compares_something_else_is_not_taken_whole() {
        for modrm in [0xD1, 0x10, 0x50] {
            let code = [0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40, 0x48, 0x39, modrm, 0x72, 0xF4];
            assert_eq!(decode(&code), Some((ConsoleOnly::Clzero, 3)), "{modrm:#x}");
        }
    }

    /// EXTRQ / INSERTQ as AMD's manual gives them: a length of 0 is 64.
    #[test]
    fn sse4a_bit_fields() {
        assert_eq!(extrq(0x1234_5678_9ABC_DEF0, 8, 16), 0xBC);
        assert_eq!(extrq(0x1234_5678_9ABC_DEF0, 0, 0), 0x1234_5678_9ABC_DEF0);
        assert_eq!(extrq(0x8000_0000_0000_0000, 1, 63), 1);
        assert_eq!(insertq(0xFFFF_FFFF_FFFF_FFFF, 0xAB, 8, 8), 0xFFFF_FFFF_FFFF_ABFF);
        assert_eq!(insertq(0, 0x1FF, 4, 60), 0xF000_0000_0000_0000);
        assert_eq!(insertq(0x1111, 0xDEAD_BEEF_0000_0000, 0, 0), 0xDEAD_BEEF_0000_0000);
        for (v, len, idx) in [(0x0123_4567_89AB_CDEFu64, 12u8, 20u8), (u64::MAX, 63, 1), (0x55, 3, 0)] {
            assert_eq!(extrq(insertq(0, v, len, idx), len, idx), extrq(v, len, 0));
        }
    }

    #[test]
    fn decodes_the_console_only_instructions() {
        assert_eq!(decode(&[0x0F, 0x01, 0xFC]), Some((ConsoleOnly::Clzero, 3)));
        // clzero loop against r10 (4C 39 D0 = cmp rax, r10)
        assert_eq!(
            decode(&[0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40, 0x4C, 0x39, 0xD0, 0x72, 0xF4]),
            Some((ConsoleOnly::ClzeroLoop { end_reg: 10 }, 12))
        );
        // clzero loop against rdx (48 39 D0 = cmp rax, rdx)
        assert_eq!(
            decode(&[0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40, 0x48, 0x39, 0xD0, 0x72, 0xF4]),
            Some((ConsoleOnly::ClzeroLoop { end_reg: 2 }, 12))
        );
        // the same loop after an address-size prefix: that one CLZERO alone
        assert_eq!(decode(&[0x67, 0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40, 0x48, 0x39, 0xD0, 0x72, 0xF4]), Some((ConsoleOnly::Clzero, 4)));
        assert_eq!(decode(&[0x0F, 0x01, 0xFD]), Some((ConsoleOnly::Rdpru, 3)));
        assert_eq!(decode(&[0x0F, 0x01, 0xFA]), Some((ConsoleOnly::Monitorx, 3)));
        assert_eq!(decode(&[0x0F, 0x01, 0xFB]), Some((ConsoleOnly::Mwaitx, 3)));
        assert_eq!(decode(&[0x0F, 0x0B]), Some((ConsoleOnly::Ud2, 2)));
        // clwb [rax]; clwb [rcx+0x40]; clwb [rsp+8]; clwb [rip+disp32]; clwb [r8]
        assert_eq!(decode(&[0x66, 0x0F, 0xAE, 0x30]), Some((ConsoleOnly::Clwb, 4)));
        assert_eq!(decode(&[0x66, 0x0F, 0xAE, 0x71, 0x40]), Some((ConsoleOnly::Clwb, 5)));
        assert_eq!(decode(&[0x66, 0x0F, 0xAE, 0x74, 0x24, 0x08]), Some((ConsoleOnly::Clwb, 6)));
        assert_eq!(decode(&[0x66, 0x0F, 0xAE, 0x35, 1, 2, 3, 4]), Some((ConsoleOnly::Clwb, 8)));
        assert_eq!(decode(&[0x66, 0x41, 0x0F, 0xAE, 0x30]), Some((ConsoleOnly::Clwb, 5)));
        // rdpid rax; rdpid r9
        assert_eq!(decode(&[0xF3, 0x0F, 0xC7, 0xF8]), Some((ConsoleOnly::Rdpid(0), 4)));
        assert_eq!(decode(&[0xF3, 0x41, 0x0F, 0xC7, 0xF9]), Some((ConsoleOnly::Rdpid(9), 5)));
        // not console-only: clflushopt (/7), xsaveopt (no 66), a plain mov, truncated bytes
        // SSE4a, as a retail game has it (#216: insertq xmm0, xmm1 with length / index bytes)
        assert_eq!(decode(&[0xF2, 0x0F, 0x78, 0xC1, 0x08, 0x10]), Some((ConsoleOnly::Insertq { dst: 0, src: 1, reg: false, len: 8, idx: 16 }, 6)));
        assert_eq!(decode(&[0xF2, 0x45, 0x0F, 0x79, 0xC1]), Some((ConsoleOnly::Insertq { dst: 8, src: 9, reg: true, len: 0, idx: 0 }, 5)));
        assert_eq!(decode(&[0x66, 0x0F, 0x78, 0xC2, 0x04, 0x08]), Some((ConsoleOnly::Extrq { dst: 2, src: None, len: 4, idx: 8 }, 6)));
        assert_eq!(decode(&[0x66, 0x0F, 0x79, 0xCA]), Some((ConsoleOnly::Extrq { dst: 1, src: Some(2), len: 0, idx: 0 }, 4)));
        assert_eq!(decode(&[0xF2, 0x0F, 0x78, 0xC1, 0x08]), None, "an immediate missing");
        assert_eq!(decode(&[0x0F, 0x78, 0xC1, 0x08, 0x10]), None, "VMREAD without a prefix is not SSE4a");
        // prefixes as a Zen 5 runs them (Kalmarv on #209): the last of F2 / F3 decides, 66 next
        // to them does not; 0x67 and a REX before a legacy prefix are ignored
        let insertq = Some((ConsoleOnly::Insertq { dst: 0, src: 1, reg: false, len: 16, idx: 16 }, 7));
        for code in [[0x66, 0xF2, 0x0F, 0x78, 0xC1, 0x10, 0x10], [0xF2, 0x66, 0x0F, 0x78, 0xC1, 0x10, 0x10], [0xF3, 0xF2, 0x0F, 0x78, 0xC1, 0x10, 0x10], [0x67, 0xF2, 0x0F, 0x78, 0xC1, 0x10, 0x10], [0x41, 0xF2, 0x0F, 0x78, 0xC1, 0x10, 0x10]] {
            assert_eq!(decode(&code), insertq, "{code:02x?}");
        }
        for code in [[0xF2, 0xF3, 0x0F, 0x78, 0xC1, 0x10, 0x10], [0xF3, 0x66, 0x0F, 0x78, 0xC1, 0x10, 0x10], [0x66, 0xF3, 0x0F, 0x78, 0xC0, 0x10, 0x10]] {
            assert_eq!(decode(&code), None, "#UD on the CPU: {code:02x?}");
        }
        assert_eq!(decode(&[0x67, 0x0F, 0x01, 0xFC]), Some((ConsoleOnly::Clzero, 4)));
        assert_eq!(decode(&[0x66, 0x0F, 0xAE, 0x38]), None);
        assert_eq!(decode(&[0x0F, 0xAE, 0x30]), None);
        assert_eq!(decode(&[0x48, 0x8B, 0x01]), None);
        assert_eq!(decode(&[0x66, 0x0F, 0xAE, 0x74, 0x24]), None);
        assert_eq!(decode(&[0x0F]), None);
    }
}
