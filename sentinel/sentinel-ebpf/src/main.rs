#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
};
use sentinel_common::OpenEvent;

/// PID allowlist -- only PIDs present in this map generate events.
/// User-space writes the target PID here before the agent starts.
#[map]
static TARGET_PID: HashMap<u32, u8> = HashMap::with_max_entries(16, 0);

/// Zero-copy perf ring for shipping OpenEvent structs to user-space.
#[map]
static EVENTS: PerfEventArray<OpenEvent> = PerfEventArray::new(0);

/// Filename pointer lives at byte-offset 24 in the `syscalls/sys_enter_openat`
/// tracepoint record on x86_64 (after the 8-byte common header, 8-byte
/// __syscall_nr + pad, and 8-byte dfd field).
const FILENAME_OFFSET: usize = 24;

#[tracepoint]
pub fn sentinel(ctx: TracePointContext) -> u32 {
    match try_sentinel(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_sentinel(ctx: &TracePointContext) -> Result<u32, i64> {
    // ── Zero-overhead PID filter (must be first to avoid cache misses) ──
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;

    // SAFETY: HashMap::get performs a bounded map lookup keyed on a
    // stack-local u32. The verifier guarantees the pointer is valid or NULL.
    if unsafe { TARGET_PID.get(&pid) }.is_none() {
        return Ok(0);
    }

    // ── Initialize event to all-zero to prevent kernel stack leakage ──
    let mut event = OpenEvent::zeroed();
    event.pid = pid;

    // ── Read the user-space filename string ──
    // SAFETY: ctx.read_at reads from the tracepoint record at a compile-time
    // constant offset verified against the sys_enter_openat format.
    let filename_ptr: u64 = unsafe { ctx.read_at(FILENAME_OFFSET)? };

    // SAFETY: bpf_probe_read_user_str_bytes copies at most
    // MAX_FILENAME_LEN bytes from the user-space pointer into our
    // stack-allocated buffer. The helper is NULL-safe and returns an
    // error on fault rather than panicking.
    if let Ok(name) = unsafe {
        bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut event.filename)
    } {
        event.filename_len = name.len() as u32;
    }

    // ── Ship event to user-space via perf ring (zero-copy) ──
    // SAFETY: PerfEventArray::output calls bpf_perf_event_output with
    // BPF_F_CURRENT_CPU. The event is repr(C) and fully initialized.
    EVENTS.output(ctx, &event, 0);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
