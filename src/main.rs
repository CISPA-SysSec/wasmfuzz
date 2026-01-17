//! WIP JIT experiments on well-behaved WebAssembly fuzz targets
//!
//! See [the whitepaper](https://isotropic.org/papers/chicken.pdf) for more details.

mod cli;
mod concolic;
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

#[cfg(feature = "tracy")]
#[global_allocator]
static ALLOC: tracy_full::alloc::GlobalAllocator = tracy_full::alloc::GlobalAllocator::new();

// Note: This is a hard limit, fuzzer instances set their own limits..
pub(crate) const TEST_CASE_SIZE_LIMIT: usize = u16::MAX as usize; // 64kb

// Requests for new memory pages (`memory.grow`) will fail after this limit.
// Note that fuzzer instances set their own "soft" limits that short-circuit execution instead.
pub(crate) const MEMORY_PAGES_LIMIT: u32 = 512 * 16; // ~512MB

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum AbortCode {
    // Explicit `unreachable`
    UnreachableReached,
    // Wasm-related traps
    TableOutOfBounds,
    Unimplemented,
    // Cranelift traps
    StackOverflow,
    HeapOutOfBounds,
    IntegerOverflow,
    IntegerDivisionByZero,
    BadConversionToInteger,
}

fn main() {
    cli::main();
}
