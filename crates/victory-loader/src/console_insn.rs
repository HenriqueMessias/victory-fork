//! Instructions the console's CPU (Zen 2) has and an Intel PC's lacks, emulated: the title's
//! code raises STATUS_ILLEGAL_INSTRUCTION on them (the title zeroes memory with a `clzero` loop at
//! its first frames), and the vectored handler steps over them here.
//!
//! Ported from XCL (github.com/ivall/xcl, GPL-2.0-only): `insn.rs` (decoder, as
//! `console_insn_decode.rs`) and `eh.rs` `emulate_console_only`. Changed here: how a `clwb` is
//! patched ([`patch_clwb`]) and what a `clzero` loop leaves behind ([`clzero_loop`]).

#[path = "console_insn_decode.rs"]
mod decode;

use decode::ConsoleOnly;
use std::cell::Cell;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering::Relaxed, Ordering::SeqCst};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;

const CONTINUE_EXECUTION: i32 = -1;

/// Whether what Windows said about memory is remembered per thread (the regions it found
/// writable, the code bytes it found readable) and not asked again at every emulated
/// instruction. A query walks the pages of the region it answers for: asked from outside, it
/// took 2-9 ms in the title's heaps of 0.6-2.2 GB and 89 ms in its 6.2 GB page pool (run 30),
/// and the title zeroes blocks of them with `clzero` loops all through a frame: six of its
/// threads spent 25-78 % of their time inside that query (runs 29 and 30), about 27 s of
/// processor time in Windows per 9 s frame. On by default; `VICTORY_CLZERO_ASK=1` asks every
/// time, as before.
fn remembers() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("VICTORY_CLZERO_ASK").is_none_or(|v| v != "1"))
}

/// Answers a remembered region gives before Windows is asked about it again: one freed or
/// protected meanwhile is forgotten then.
const ANSWERS: u32 = 4096;

thread_local! {
    /// The regions Windows last said are committed and writable (start, end), newest first,
    /// and the answers they gave since they were emptied.
    static WRITABLE: Cell<([(usize, usize); 4], u32)> = const { Cell::new(([(0, 0); 4], 0)) };
    /// Faulting addresses and the code bytes found readable there, newest first.
    static CODE: Cell<[(usize, usize); 8]> = const { Cell::new([(0, 0); 8]) };
}

/// Instructions emulated, the times Windows was asked about memory for them, and the bytes
/// `clzero` loops zeroed, since the start.
static EMULATED: AtomicU64 = AtomicU64::new(0);
static ASKED: AtomicU64 = AtomicU64::new(0);
static ZEROED: AtomicU64 = AtomicU64::new(0);

fn readable(va: usize, bytes: usize) -> bool {
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery};
    // SAFETY: plain data filled in by the query.
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out pointer of the right size.
    let found = unsafe { VirtualQuery(va as *const _, &mut m, size_of_val(&m)) } != 0;
    ASKED.fetch_add(1, Relaxed);
    found && m.State == MEM_COMMIT && m.Protect & (PAGE_NOACCESS | PAGE_GUARD) == 0 && m.BaseAddress as usize + m.RegionSize >= va + bytes
}

fn writable(va: usize, bytes: usize) -> bool {
    writable_to(va, va + bytes) == Some(va + bytes)
}

/// Where the committed, writable memory that `va` lies in ends, at most `end`; None if `va`
/// is not in such memory. A region found is remembered ([`remembers`]).
/// shortcut: a remembered region that was freed or protected since is written all the same
/// for up to [`ANSWERS`] answers: the write then faults inside the handler, which the guard
/// on view memory opens as it does any write, and which is a crash otherwise (as the
/// unchecked single-line emulation behind this one already is).
fn writable_to(va: usize, end: usize) -> Option<usize> {
    use windows_sys::Win32::System::Memory::{MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, VirtualQuery};
    let remember = remembers();
    if remember {
        let (regions, answers) = WRITABLE.with(Cell::get);
        if let Some(&(_, to)) = regions.iter().find(|&&(from, to)| from <= va && va < to) {
            let next = if answers >= ANSWERS { ([(0, 0); 4], 0) } else { (regions, answers + 1) };
            WRITABLE.with(|w| w.set(next));
            return Some(to.min(end));
        }
    }
    // SAFETY: plain data filled in by the query.
    let mut m: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out pointer of the right size.
    let found = unsafe { VirtualQuery(va as *const _, &mut m, size_of_val(&m)) } != 0;
    ASKED.fetch_add(1, Relaxed);
    if !found || m.State != MEM_COMMIT || m.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE) == 0 {
        return None;
    }
    let (from, to) = (m.BaseAddress as usize, m.BaseAddress as usize + m.RegionSize);
    if remember {
        WRITABLE.with(|w| {
            let (mut regions, answers) = w.get();
            regions.rotate_right(1);
            regions[0] = (from, to);
            w.set((regions, answers));
        });
    }
    Some(to.min(end))
}

/// Makes the `clwb` whose second opcode byte is at `at` a NOP ([`decode::NOP_OPCODE`]): there is
/// nothing to write back on the PC, and no exception next time. Other threads may be running
/// the instruction, so that byte alone is written. One thread patches at a time: two of them
/// changing one page's protection left it writable, or took the write away from under the
/// other (a fault inside the handler). A thread that finds another one at it leaves the
/// instruction for its next time.
///
/// # Safety
/// `at` is inside mapped code.
unsafe fn patch_clwb(at: usize) {
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    static PATCHING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let Ok(_one) = PATCHING.try_lock() else { return };
    let mut old = 0u32;
    // SAFETY: one byte of code, made writable for the patch and restored; only patches write
    // code while the title runs, one at a time.
    unsafe {
        let opcode = AtomicU8::from_ptr(at as *mut u8);
        if opcode.load(SeqCst) == decode::CLWB_OPCODE && VirtualProtect(at as *const _, 1, PAGE_EXECUTE_READWRITE, &mut old) != 0 {
            opcode.store(decode::NOP_OPCODE, SeqCst);
            VirtualProtect(at as *const _, 1, old, &mut old);
            FlushInstructionCache(GetCurrentProcess(), at as *const _, 1);
        }
    }
}

/// The whole `clzero; add rax,40h; cmp rax,end; jb` loop at once, as its instructions leave
/// memory, `rax` and the flags: whole lines, however `rax` lies in its own, and the first
/// without a test. False if it is not over: at the first line that cannot be written (`rax`
/// is then there, and the real one faults there too).
///
/// Region by region: a block may lie across several (the title's pages are mapped one view
/// each), and one answer for all of it was a refusal, after which every 64-byte line took an
/// exception of its own.
///
/// # Safety
/// As [`emulate`], for a `ClzeroLoop` at `ctx.Rip`.
unsafe fn clzero_loop(ctx: &mut CONTEXT, end_reg: u8) -> bool {
    let start = ctx.Rax;
    let first = start & !63;
    let end = *crate::crash::gpr(ctx, end_reg);
    let passes = decode::clzero_passes(start, end);
    // Past the end of the address space nothing is writable.
    let stop = passes.saturating_mul(64).saturating_add(first) & !63;
    let mut at = first as usize;
    while at < stop as usize {
        let Some(to) = writable_to(at, stop as usize) else { break };
        // SAFETY: committed and writable from `at` to `to`.
        unsafe { std::ptr::write_bytes(at as *mut u8, 0, to - at) };
        at = to;
    }
    let zeroed = at as u64 - first;
    ZEROED.fetch_add(zeroed, Relaxed);
    // Regions and lines end on lines: whole passes.
    ctx.Rax = start.wrapping_add(zeroed);
    if zeroed / 64 < passes {
        return false;
    }
    // (`cmp rax, rax` compares what the loop left there.)
    let end = *crate::crash::gpr(ctx, end_reg);
    ctx.EFlags = ctx.EFlags & !crate::crash::CMP_FLAGS | crate::crash::cmp_flags(ctx.Rax, end);
    true
}

/// An illegal instruction at `ctx.Rip`: a console-only one is emulated and stepped over
/// (`CONTINUE_EXECUTION`); anything else returns 0 (the crash report and the title's handlers
/// see it).
///
/// # Safety
/// `ctx` is the faulting thread's context, from the exception being dispatched.
pub(crate) unsafe fn emulate(ctx: &mut CONTEXT) -> i32 {
    let rip = ctx.Rip as usize;
    // The same few instructions fault again and again: their bytes are asked about once.
    let known = if remembers() { CODE.with(Cell::get) } else { [(0, 0); 8] };
    let n = match known.iter().find(|&&(at, n)| at == rip && n > 0) {
        Some(&(_, n)) => n,
        None => {
            if !readable(rip, 1) {
                return 0;
            }
            let n = (1..=16).rev().find(|&n| readable(rip, n)).unwrap_or(0);
            if remembers() {
                let mut known = known;
                known.rotate_right(1);
                known[0] = (rip, n);
                CODE.with(|c| c.set(known));
            }
            n
        }
    };
    // A copy: another thread may be patching the instruction.
    let mut code = [0u8; 16];
    for (i, b) in code[..n].iter_mut().enumerate() {
        // SAFETY: `n` bytes at `rip` are readable.
        *b = unsafe { (rip as *const u8).add(i).read_volatile() };
    }
    let code = &code[..n];
    let Some((what, len)) = decode::decode(code) else {
        // A `clwb` another thread made a NOP since this one faulted on it.
        let Some(len) = decode::clwb_made_nop(code) else { return 0 };
        ctx.Rip += len as u64;
        return CONTINUE_EXECUTION;
    };
    static SEEN: std::sync::Mutex<Vec<std::mem::Discriminant<ConsoleOnly>>> = std::sync::Mutex::new(Vec::new());
    if let Ok(mut seen) = SEEN.lock()
        && !seen.contains(&std::mem::discriminant(&what))
    {
        seen.push(std::mem::discriminant(&what));
        if what != ConsoleOnly::Ud2 {
            tracing::warn!(instruction = ?what, at = format_args!("{rip:#x}"), "a console CPU instruction this CPU lacks: emulated (logged once)");
        }
    }
    match what {
        ConsoleOnly::Ud2 => return 0,
        ConsoleOnly::Clwb => {
            if let Some(at) = decode::clwb_opcode(code) {
                // SAFETY: inside the instruction that faulted.
                unsafe { patch_clwb(rip + at) };
            }
        }
        ConsoleOnly::Monitorx => {}
        ConsoleOnly::Mwaitx => std::hint::spin_loop(),
        ConsoleOnly::Clzero => {
            // with an address-size prefix (0x67) the line is at EAX, zero-extended
            let a32 = code[..len - 3].contains(&0x67);
            let line = (if a32 { ctx.Rax & 0xFFFF_FFFF } else { ctx.Rax } as usize) & !63;
            if !writable(line, 64) {
                return 0; // the real instruction faults there too
            }
            // SAFETY: the 64-byte line is committed and writable.
            unsafe { std::ptr::write_bytes(line as *mut u8, 0, 64) };
        }
        ConsoleOnly::ClzeroLoop { end_reg } => {
            let start = ctx.Rax;
            // SAFETY: the loop at `rip`.
            if !unsafe { clzero_loop(ctx, end_reg) } {
                if ctx.Rax == start {
                    return 0;
                }
                // The loop goes on at the line that is not writable (the same instruction
                // again).
                return CONTINUE_EXECUTION;
            }
        }
        ConsoleOnly::Rdpru => {
            let mut v = 0i64;
            // SAFETY: a valid out pointer.
            unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut v) };
            let v = if ctx.Rcx as u32 <= 1 { v as u64 } else { 0 };
            ctx.Rax = v & 0xFFFF_FFFF;
            ctx.Rdx = v >> 32;
        }
        ConsoleOnly::Rdpid(r) => {
            // SAFETY: no preconditions.
            let cpu = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessorNumber() } as u64;
            let regs: [&mut u64; 16] = [
                &mut ctx.Rax, &mut ctx.Rcx, &mut ctx.Rdx, &mut ctx.Rbx, &mut ctx.Rsp, &mut ctx.Rbp, &mut ctx.Rsi, &mut ctx.Rdi, &mut ctx.R8, &mut ctx.R9, &mut ctx.R10, &mut ctx.R11, &mut ctx.R12, &mut ctx.R13,
                &mut ctx.R14, &mut ctx.R15,
            ];
            *regs[r as usize & 15] = cpu;
        }
        // the low quadword changes; the high one is zeroed, as a Zen 5 does
        ConsoleOnly::Extrq { dst, src, len, idx } => {
            // SAFETY: the context's XMM registers (CONTEXT_FLOATING_POINT is captured for exceptions).
            let x = unsafe { &mut ctx.Anonymous.FltSave.XmmRegisters };
            let (len, idx) = match src {
                Some(s) => {
                    let c = x[s as usize & 15].Low;
                    (c as u8, (c >> 8) as u8)
                }
                None => (len, idx),
            };
            let d = &mut x[dst as usize & 15];
            d.Low = decode::extrq(d.Low, len, idx);
            d.High = 0;
        }
        ConsoleOnly::Insertq { dst, src, reg, len, idx } => {
            // SAFETY: as above.
            let x = unsafe { &mut ctx.Anonymous.FltSave.XmmRegisters };
            let s = x[src as usize & 15];
            let (len, idx) = if reg { (s.High as u8, (s.High >> 8) as u8) } else { (len, idx) };
            let d = &mut x[dst as usize & 15];
            d.Low = decode::insertq(d.Low, s.Low, len, idx);
            d.High = 0;
        }
    }
    ctx.Rip += len as u64;
    // How often this runs at all (each one is an exception: a trip into Windows and back).
    let emulated = EMULATED.fetch_add(1, Relaxed) + 1;
    if emulated >= 1 << 16 && emulated.is_power_of_two() {
        tracing::info!(
            emulated,
            asked = ASKED.load(Relaxed),
            zeroed_mb = ZEROED.load(Relaxed) >> 20,
            "console CPU instructions emulated so far, the times Windows was asked about memory for them, and what clzero loops zeroed"
        );
    }
    CONTINUE_EXECUTION
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_READWRITE, VirtualAlloc,
        VirtualFree, VirtualProtect, VirtualQuery,
    };

    /// Fresh pages; freed at the end.
    struct Pages(usize, usize);
    impl Pages {
        fn new(len: usize) -> Pages {
            // SAFETY: a fresh allocation.
            let at = unsafe { VirtualAlloc(std::ptr::null(), len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) };
            assert!(!at.is_null());
            Pages(at as usize, len)
        }
        fn bytes(&mut self) -> &mut [u8] {
            // SAFETY: ours, committed.
            unsafe { std::slice::from_raw_parts_mut(self.0 as *mut u8, self.1) }
        }
        fn protect(&self, at: usize, len: usize, protect: u32) {
            let mut old = 0;
            // SAFETY: our pages.
            assert_ne!(unsafe { VirtualProtect((self.0 + at) as *const _, len, protect, &mut old) }, 0);
        }
        fn protection(&self) -> u32 {
            // SAFETY: plain data filled in by the query.
            unsafe {
                let mut m: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
                assert_ne!(VirtualQuery(self.0 as *const _, &mut m, size_of_val(&m)), 0);
                m.Protect
            }
        }
    }
    impl Drop for Pages {
        fn drop(&mut self) {
            // SAFETY: allocated in `new`.
            unsafe { VirtualFree(self.0 as *mut _, 0, MEM_RELEASE) };
        }
    }

    fn at(rip: usize) -> CONTEXT {
        // SAFETY: a zeroed context is valid.
        let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
        ctx.Rip = rip as u64;
        ctx
    }

    /// Threads that fault on one `clwb` at once, some after another has patched it: all go on
    /// behind it, the instruction becomes one NOP, and its page keeps its protection.
    #[test]
    fn threads_that_meet_at_a_clwb_all_go_on() {
        // [r9+0x40], over a cache line's end in its page.
        const CLWB: [u8; 6] = [0x66, 0x41, 0x0F, 0xAE, 0x71, 0x40];
        const AT: usize = 64 - 3;
        for _ in 0..200 {
            let mut code = Pages::new(0x1000);
            code.bytes().fill(0xCC);
            code.bytes()[AT..AT + CLWB.len()].copy_from_slice(&CLWB);
            code.protect(0, 0x1000, PAGE_EXECUTE_READ);
            let rip = code.0 + AT;
            let gate = std::sync::Barrier::new(8);
            std::thread::scope(|s| {
                for _ in 0..8 {
                    s.spawn(|| {
                        gate.wait();
                        for _ in 0..4 {
                            let mut ctx = at(rip);
                            // SAFETY: the context of a fault at our code.
                            assert_eq!(unsafe { emulate(&mut ctx) }, CONTINUE_EXECUTION);
                            assert_eq!(ctx.Rip as usize, rip + CLWB.len());
                        }
                    });
                }
            });
            assert_eq!(code.protection(), PAGE_EXECUTE_READ);
            let mut nop = CLWB;
            nop[3] = decode::NOP_OPCODE;
            assert_eq!(&code.bytes()[AT..AT + nop.len()], &nop);
        }
    }

    /// On a thread of its own, which remembers no memory of other tests ([`WRITABLE`]).
    fn on_a_thread(test: impl FnOnce() + Send) {
        std::thread::scope(|s| s.spawn(test).join().unwrap());
    }

    /// `clzero; add rax,40h; cmp rax,rdx; jb` run from the fault on.
    const LOOP: [u8; 12] = [0x0F, 0x01, 0xFC, 0x48, 0x83, 0xC0, 0x40, 0x48, 0x39, 0xD0, 0x72, 0xF4];

    fn run_loop(start: usize, end: usize) -> (i32, CONTEXT, usize) {
        let code = LOOP;
        let rip = code.as_ptr() as usize;
        let mut ctx = at(rip);
        ctx.Rax = start as u64;
        ctx.Rdx = end as u64;
        ctx.EFlags = 0x202;
        // SAFETY: the context of a fault at `code`; the loop's memory is the caller's.
        let r = unsafe { emulate(&mut ctx) };
        let moved = ctx.Rip as usize - rip;
        (r, ctx, moved)
    }

    /// Memory, `rax` and the flags are as the loop's own instructions leave them, also for a
    /// `rax` inside a line, an end inside one, and an end at or before the start.
    #[test]
    fn clzero_loops_leave_what_the_instructions_leave() {
        on_a_thread(|| {
            for (start, end) in [(0, 0x1000), (64, 65), (5, 200), (0x100, 0x100), (0x100, 0x40), (0x47, 0x80), (0x47, 0x88)] {
                let mut data = Pages::new(0x3000);
                data.bytes().fill(0xEE);
                let base = data.0 + 0x1000;
                let (r, ctx, moved) = run_loop(base + start, base + end);
                assert_eq!((r, moved), (CONTINUE_EXECUTION, LOOP.len()), "{start:#x}..{end:#x}");
                let (mut rax, mut expected) = (start, vec![0xEE; 0x3000]);
                loop {
                    let line = 0x1000 + (rax & !63);
                    expected[line..line + 64].fill(0);
                    rax += 64;
                    if rax >= end {
                        break;
                    }
                }
                assert!(data.bytes() == &expected[..], "{start:#x}..{end:#x}");
                assert_eq!(ctx.Rax as usize, base + rax);
                let flags = crate::crash::cmp_flags((base + rax) as u64, (base + end) as u64);
                assert_eq!(ctx.EFlags, 0x202 & !crate::crash::CMP_FLAGS | flags);
                assert_eq!(ctx.EFlags & 1, 0, "jb is not taken");
            }
        });
    }

    /// The loop stops at a line it cannot write, with `rax` there and the loop to go on; at
    /// the first line it is not emulated at all.
    #[test]
    fn a_clzero_loop_stops_at_memory_it_cannot_write() {
        on_a_thread(|| {
            let mut data = Pages::new(0x3000);
            data.bytes().fill(0xEE);
            data.protect(0x1000, 0x1000, PAGE_READONLY);
            let (r, ctx, moved) = run_loop(data.0 + 0x800 + 5, data.0 + 0x2800);
            assert_eq!((r, moved), (CONTINUE_EXECUTION, 0));
            assert_eq!(ctx.Rax as usize, data.0 + 0x1000 + 5);
            assert!(data.bytes()[0x800..0x1000].iter().all(|&b| b == 0));
            assert!(data.bytes()[0x1000..].iter().all(|&b| b == 0xEE));
            let (r, ctx, moved) = run_loop(data.0 + 0x1000, data.0 + 0x2800);
            assert_eq!((r, moved, ctx.Rax as usize), (0, 0, data.0 + 0x1000));
            // An end that is no address: what can be written is, and no more.
            let (r, ctx, _) = run_loop(data.0 + 0x2000, usize::MAX);
            assert_eq!(r, CONTINUE_EXECUTION);
            assert_eq!(ctx.Rax as usize, data.0 + 0x3000, "the rest of its 64 KiB is free");
            assert!(data.bytes()[0x2000..].iter().all(|&b| b == 0));
        });
    }
}
