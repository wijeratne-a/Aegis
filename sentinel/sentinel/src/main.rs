use std::{fs::OpenOptions, io::Write, mem};

use anyhow::Context as _;
use aya::{
    maps::{HashMap, perf::AsyncPerfEventArray},
    programs::TracePoint,
    util::online_cpus,
};
use bytes::BytesMut;
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use serde::Serialize;
use sentinel_common::OpenEvent;
use tokio::signal;

#[derive(Parser)]
#[command(name = "sentinel", about = "Aegis PoT kernel trace daemon")]
struct Args {
    /// PID of the agent process to monitor
    #[arg(long)]
    pid: u32,
}

#[derive(Serialize)]
struct TraceEvent<'a> {
    pid: u32,
    filename: &'a str,
    timestamp_ns: u128,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit is a well-defined POSIX call; we pass a valid rlimit struct.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sentinel"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => warn!("failed to initialize eBPF logger: {e}"),
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // ── PID Lock: write the target PID into the eBPF map before attaching ──
    let mut target_pid: HashMap<_, u32, u8> =
        HashMap::try_from(ebpf.map_mut("TARGET_PID").context("TARGET_PID map not found")?)?;
    target_pid.insert(args.pid, 1, 0)?;
    log::info!("locked TARGET_PID map to pid {}", args.pid);

    let program: &mut TracePoint = ebpf.program_mut("sentinel").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_openat")?;
    log::info!("tracepoint attached, monitoring pid {}", args.pid);

    // ── Async perf event polling ──
    let perf_map = ebpf.take_map("EVENTS").context("EVENTS map not found")?;
    let mut perf_array = AsyncPerfEventArray::try_from(perf_map)?;

    let cpus = online_cpus().map_err(|(_, e)| e)?;
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("trace.log")
        .context("failed to open trace.log")?;

    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let mut log_file = log_file.try_clone()?;

        tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(mem::size_of::<OpenEvent>() + 64))
                .collect::<Vec<_>>();

            let mut json_buf: Vec<u8> = Vec::with_capacity(512);

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let raw = &buffers[i];
                    if raw.len() < mem::size_of::<OpenEvent>() {
                        continue;
                    }
                    // SAFETY: OpenEvent is repr(C), fully initialized by the eBPF
                    // program, and we verified the buffer length above.
                    let event: &OpenEvent =
                        unsafe { &*(raw.as_ptr() as *const OpenEvent) };

                    let name_len = (event.filename_len as usize).min(event.filename.len());
                    let filename = core::str::from_utf8(&event.filename[..name_len])
                        .unwrap_or("<invalid utf8>");

                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();

                    let trace = TraceEvent {
                        pid: event.pid,
                        filename,
                        timestamp_ns: ts,
                    };

                    json_buf.clear();
                    serde_json::to_writer(&mut json_buf, &trace).unwrap();
                    json_buf.push(b'\n');
                    let _ = log_file.write_all(&json_buf);
                }
            }
        });
    }

    println!("Sentinel running. Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
