//! Profiler support for JIT code, off by default.
//!
//! `WASMFUZZ_PERFMAP=map` (or `1`) appends `/tmp/perf-<pid>.map` lines for each
//! compiled function. `WASMFUZZ_PERFMAP=jitdump` writes a jitdump file
//! (`$WASMFUZZ_JITDUMP_DIR/jit-<pid>.dump`, default cwd) for
//! `perf record -k mono` + `perf inject --jit`; this keeps code bytes and copes
//! with address reuse across worker respawns. `both` enables both.
//!
//! `WASMFUZZ_JIT_DUMP=<sub>[,<sub>...]` writes the CLIF before and after
//! optimization plus the VCode disassembly of each function whose symbol
//! contains one of the substrings to `$WASMFUZZ_JIT_DUMP_DIR` (default cwd),
//! as `<kind>-<symbol>.{pre.clif,opt.clif,vcode}`; `*` matches everything.

use std::{
    fs::File,
    io::Write,
    sync::{Mutex, OnceLock},
};

#[derive(Clone, Copy, Default)]
struct Mode {
    map: bool,
    jitdump: bool,
}

fn mode() -> Mode {
    static MODE: OnceLock<Mode> = OnceLock::new();
    *MODE.get_or_init(|| match std::env::var("WASMFUZZ_PERFMAP").as_deref() {
        Ok("1" | "map") => Mode {
            map: true,
            jitdump: false,
        },
        Ok("jitdump") => Mode {
            map: false,
            jitdump: true,
        },
        Ok("both") => Mode {
            map: true,
            jitdump: true,
        },
        _ => Mode::default(),
    })
}

pub(crate) fn enabled() -> bool {
    let m = mode();
    m.map || m.jitdump
}

/// Drops rustc's `[0123456789abcdef]` crate disambiguators from a symbol.
pub(crate) fn short_name(name: &str) -> String {
    let b = name.as_bytes();
    let mut out = String::with_capacity(name.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'['
            && i + 17 < b.len()
            && b[i + 17] == b']'
            && b[i + 1..i + 17].iter().all(u8::is_ascii_hexdigit)
        {
            i += 18;
            continue;
        }
        let ch = name[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

pub(crate) struct CodeRegion {
    pub ptr: *const u8,
    pub size: usize,
    pub name: String,
}

struct JitDump {
    file: File,
    code_index: u64,
}

fn timestamp() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn jitdump() -> &'static Mutex<Option<JitDump>> {
    static JD: OnceLock<Mutex<Option<JitDump>>> = OnceLock::new();
    JD.get_or_init(|| {
        let dir = std::env::var("WASMFUZZ_JITDUMP_DIR").unwrap_or_else(|_| ".".into());
        let pid = std::process::id();
        let path = format!("{dir}/jit-{pid}.dump");
        let res = (|| -> std::io::Result<JitDump> {
            let mut file = File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)?;
            // perf finds the dump through this executable mmap of its first page.
            let page = rustix::param::page_size();
            unsafe {
                use std::os::fd::AsRawFd;
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    page,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE,
                    file.as_raw_fd(),
                    0,
                );
                if p == libc::MAP_FAILED {
                    return Err(std::io::Error::last_os_error());
                }
            }
            let mut hdr = Vec::with_capacity(40);
            hdr.extend_from_slice(&0x4A69_5444u32.to_le_bytes()); // magic "JiTD"
            hdr.extend_from_slice(&1u32.to_le_bytes()); // version
            hdr.extend_from_slice(&40u32.to_le_bytes()); // header size
            hdr.extend_from_slice(&62u32.to_le_bytes()); // EM_X86_64
            hdr.extend_from_slice(&0u32.to_le_bytes());
            hdr.extend_from_slice(&pid.to_le_bytes());
            hdr.extend_from_slice(&timestamp().to_le_bytes());
            hdr.extend_from_slice(&0u64.to_le_bytes()); // flags
            file.write_all(&hdr)?;
            Ok(JitDump {
                file,
                code_index: 0,
            })
        })();
        match res {
            Ok(jd) => {
                eprintln!("[perfmap] writing jitdump to {path}");
                Mutex::new(Some(jd))
            }
            Err(err) => {
                eprintln!("[perfmap] failed to create jitdump {path}: {err}");
                Mutex::new(None)
            }
        }
    })
}

/// Record finalized code regions. `regions` must point at live, finalized code.
pub(crate) fn record(regions: &[CodeRegion]) {
    let m = mode();
    if m.map {
        let mut buf = String::new();
        for r in regions {
            use std::fmt::Write;
            let name = r.name.replace('\n', " ");
            let _ = writeln!(buf, "{:x} {:x} {}", r.ptr as usize, r.size, name);
        }
        let path = format!("/tmp/perf-{}.map", std::process::id());
        if let Ok(mut f) = File::options().create(true).append(true).open(&path) {
            let _ = f.write_all(buf.as_bytes());
        }
    }
    if m.jitdump {
        let mut guard = jitdump().lock().unwrap();
        let Some(jd) = guard.as_mut() else { return };
        let pid = std::process::id();
        let tid = unsafe { libc::gettid() } as u32;
        let mut buf = Vec::new();
        for r in regions {
            let name = r.name.replace('\0', " ");
            let total = 16 + 40 + name.len() + 1 + r.size;
            buf.extend_from_slice(&0u32.to_le_bytes()); // JIT_CODE_LOAD
            buf.extend_from_slice(&(total as u32).to_le_bytes());
            buf.extend_from_slice(&timestamp().to_le_bytes());
            buf.extend_from_slice(&pid.to_le_bytes());
            buf.extend_from_slice(&tid.to_le_bytes());
            buf.extend_from_slice(&(r.ptr as u64).to_le_bytes()); // vma
            buf.extend_from_slice(&(r.ptr as u64).to_le_bytes()); // code_addr
            buf.extend_from_slice(&(r.size as u64).to_le_bytes());
            buf.extend_from_slice(&jd.code_index.to_le_bytes());
            jd.code_index += 1;
            buf.extend_from_slice(name.as_bytes());
            buf.push(0);
            // Safety: caller guarantees the region is finalized, readable code.
            buf.extend_from_slice(unsafe { std::slice::from_raw_parts(r.ptr, r.size) });
        }
        let _ = jd.file.write_all(&buf);
    }
}

/// Path prefix for dumping this function's IR, if `WASMFUZZ_JIT_DUMP` selects it.
pub(crate) fn dump_target(symbol: &str, kind: super::CompilationKind) -> Option<String> {
    static SEL: OnceLock<Option<(Vec<String>, String)>> = OnceLock::new();
    let (subs, dir) = SEL
        .get_or_init(|| {
            let subs = std::env::var("WASMFUZZ_JIT_DUMP").ok()?;
            let dir = std::env::var("WASMFUZZ_JIT_DUMP_DIR").unwrap_or_else(|_| ".".into());
            Some((subs.split(',').map(str::to_owned).collect(), dir))
        })
        .as_ref()?;
    if !subs.iter().any(|s| s == "*" || symbol.contains(s.as_str())) {
        return None;
    }
    let mut name: String = symbol
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    name.truncate(120);
    Some(format!("{dir}/{kind:?}-{name}"))
}
