use std::{
    cell::{Cell, RefCell},
    sync::Once,
};

#[expect(non_camel_case_types)]
mod setjmp {
    use std::ffi::c_int;

    pub type __jmp_buf = [::std::os::raw::c_long; 8usize];

    #[repr(C)]
    pub struct __sigset_t {
        pub __val: [::std::os::raw::c_ulong; 16usize],
    }

    #[repr(C)]
    pub struct __jmp_buf_tag {
        pub __jmpbuf: __jmp_buf,
        pub __mask_was_saved: ::std::os::raw::c_int,
        pub __saved_mask: __sigset_t,
    }

    pub type jmp_buf = [__jmp_buf_tag; 1usize];
    // pub type sigjmp_buf = [__jmp_buf_tag; 1usize];

    unsafe extern "C" {
        #[link_name = "_setjmp"]
        pub fn setjmp(env: *mut jmp_buf) -> c_int;
        // #[link_name = "__sigsetjmp"]
        // pub fn sigsetjmp(env: *mut sigjmp_buf, savesigs: c_int) -> c_int;
        #[link_name = "longjmp"]
        pub fn longjmp(env: *mut jmp_buf, val: c_int) -> !;
        // #[link_name = "siglongjmp"]
        // pub fn siglongjmp(env: *mut sigjmp_buf, val: c_int) -> !;
    }
}
use setjmp::*;

type HandlerFn = unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void);
unsafe extern "C" fn trap_handler(
    signum: libc::c_int,
    siginfo: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    unsafe {
        let context = &*(context as *const libc::ucontext_t);
        let (pc, _fp) = ucontext_get_pc_and_fp(context);
        let faulting_addr = match signum {
            libc::SIGSEGV | libc::SIGBUS => Some((*siginfo).si_addr() as usize),
            _ => None,
        };
        raise_trapinfo(TrapInfo {
            reason: None,
            pc: pc as usize,
            faulting_addr,
        })
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn ucontext_get_pc_and_fp(cx: &libc::ucontext_t) -> (*const u8, usize) {
    (
        cx.uc_mcontext.gregs[libc::REG_RIP as usize] as *const u8,
        cx.uc_mcontext.gregs[libc::REG_RBP as usize] as usize,
    )
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn ucontext_get_pc_and_fp(cx: &libc::ucontext_t) -> (*const u8, usize) {
    (
        cx.uc_mcontext.pc as *const u8,
        cx.uc_mcontext.regs[29] as usize,
    )
}

fn setup_handlers(trap_handler: HandlerFn) {
    // Allow handling OOB with signals on all architectures
    setup_handler(libc::SIGSEGV, trap_handler);

    // Handle `unreachable` instructions which execute `ud2` right now
    setup_handler(libc::SIGILL, trap_handler);

    // x86 and s390x use SIGFPE to report division by zero
    if cfg!(target_arch = "x86_64") || cfg!(target_arch = "s390x") {
        setup_handler(libc::SIGFPE, trap_handler);
    }

    // Sometimes we need to handle SIGBUS too:
    // - On Darwin, guard page accesses are raised as SIGBUS.
    if cfg!(target_os = "macos") || cfg!(target_os = "freebsd") {
        setup_handler(libc::SIGBUS, trap_handler);
    }
}

// Xref: wasmtime's runtime/vm/unix/signal.rs
fn setup_handler(signal: libc::c_int, trap_handler: HandlerFn) {
    let mut handler: libc::sigaction = unsafe { std::mem::zeroed() };
    // The flags here are relatively careful, and they are...
    //
    // SA_SIGINFO gives us access to information like the program
    // counter from where the fault happened.
    //
    // SA_ONSTACK allows us to handle signals on an alternate stack,
    // so that the handler can run in response to running out of
    // stack space on the main stack. Rust installs an alternate
    // stack with sigaltstack, so we rely on that.
    //
    // SA_NODEFER allows us to reenter the signal handler if we
    // crash while handling the signal, and fall through to the
    // Breakpad handler by testing handlingSegFault.
    handler.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER | libc::SA_ONSTACK;
    handler.sa_sigaction = trap_handler as libc::size_t;
    unsafe {
        libc::sigemptyset(&mut handler.sa_mask);
        if libc::sigaction(signal, &handler, std::ptr::null_mut()) != 0 {
            panic!(
                "unable to install signal handler: {}",
                std::io::Error::last_os_error(),
            );
        }
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum TrapReason {
    MemoryOutOfBounds,
    OutOfFuel,
    OutOfMemory,
}

thread_local! {
    static JMP_BUF: RefCell<jmp_buf> = const { RefCell::new(unsafe { std::mem::zeroed() }) };
    static TRAP_INFO: Cell<Option<TrapInfo>> = const { Cell::new(None) };
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static INSTALL: Once = const { Once::new() };
}

pub(crate) unsafe fn raise_trap(trap_reason: TrapReason) -> ! {
    unsafe {
        raise_trapinfo(TrapInfo {
            reason: Some(trap_reason),
            ..Default::default()
        })
    }
}

unsafe fn raise_trapinfo(info: TrapInfo) -> ! {
    unsafe {
        TRAP_INFO.set(Some(info));
        let jmp_buf = JMP_BUF.with_borrow_mut(|x| x as *mut _);
        longjmp(jmp_buf, 1);
    }
}

#[derive(Default, Debug, PartialEq)]
pub(crate) struct TrapInfo {
    pub reason: Option<TrapReason>,
    pub pc: usize,
    pub faulting_addr: Option<usize>,
}

pub(crate) unsafe fn catch_traps<T, F: Fn() -> T>(f: F) -> Result<T, TrapInfo> {
    unsafe {
        INSTALL.with(|x| x.call_once(|| setup_handlers(trap_handler)));

        assert!(!ACTIVE.replace(true));
        let jmp_buf = JMP_BUF.with_borrow_mut(|x| x as *mut _);
        let res = match setjmp(jmp_buf) {
            0 => Ok(f()),
            1 => Err(TRAP_INFO.take().unwrap()),
            _ => unreachable!(),
        };
        assert!(ACTIVE.replace(false));
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_catch_ok() {
        let res = unsafe { catch_traps(|| 42) };
        assert_eq!(res, Ok(42));
    }

    #[test]
    fn test_catch_raised_via_call() {
        let res = unsafe { catch_traps::<(), _>(|| raise_trap(TrapReason::OutOfFuel)) };
        assert_eq!(
            res,
            Err(TrapInfo {
                reason: Some(TrapReason::OutOfFuel),
                ..Default::default()
            })
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_catch_signal() {
        #[inline(never)]
        fn trap_or_get_trap_pc(dry_run: bool) -> usize {
            let trap_loc: usize;

            unsafe {
                std::arch::asm!(
                    "cmp {0}, 0",
                    "jnz 3f",
                    "2: mov byte ptr [0xffffffffcafebabe], 0",
                    "3:",
                    "lea {1}, [rip+2b]",
                    in(reg) dry_run as usize,
                    out(reg) trap_loc,
                    options(nostack)
                );
            }

            trap_loc
        }
        let pc = trap_or_get_trap_pc(true);
        let res = unsafe { catch_traps(|| trap_or_get_trap_pc(false)) };
        assert_eq!(
            res,
            Err(TrapInfo {
                reason: None,
                pc,
                faulting_addr: Some(0xffffffffcafebabe)
            })
        );
    }
}
