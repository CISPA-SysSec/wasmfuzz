//! WIP JIT experiments on well-behaved WebAssembly fuzz targets
//!
//! See [the whitepaper](https://isotropic.org/papers/chicken.pdf) for more details.

mod cli;
pub mod cow_memory;
mod fuzzer;
mod instrumentation;
mod ir;
mod jit;
mod simple_bus;
mod util;

pub(crate) use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

#[cfg(test)]
mod tests;

#[cfg(feature = "with_mimalloc")]
mod with_mimalloc {
    #[global_allocator]
    static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;
}

// Note: This is a hard limit, the CLI has its own default.
pub(crate) const TEST_CASE_SIZE_LIMIT: usize = u16::MAX as usize; // 64kb

// Requests for new memory pages (`memory.grow`) will fail after this limit:
pub(crate) const MEMORY_PAGES_LIMIT: u32 = 1024 * 16; // ~1GB, make configurable?

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum AbortCode {
    UnreachableReached,
    Unimplemented,
}

fn main() {
    cli::main();
}
