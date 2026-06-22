use std::cell::RefCell;

use crate::{
    concolic::ConcolicContext,
    cow_memory::{CowResetMapping, ResettableMapping, RestoreDirtyLKMMapping},
    ir::ModuleSpec,
};

use super::feedback::FeedbackContext;
use super::signals::{TrapReason, raise_trap};

#[repr(C)]
pub(crate) struct VMContext {
    pub heap: *mut u8,
    pub host_ptrs: *const usize,
    pub fuel: u64,
    // ^^ Note: These fields are accessed by JITted code ^^
    pub fuel_init: u64,
    pub heap_alloc: Box<dyn ResettableMapping>,
    pub heap_pages: u32,
    pub heap_pages_snapshot: u32,
    pub heap_snapshot_is_initial: bool,
    pub heap_pages_limit_soft: u32,
    pub heap_pages_limit_hard: u32,
    // module-declared memory max in pages; grow past this returns -1.
    // independent of the fuzzer soft/hard caps. u32::MAX means no max.
    pub heap_pages_limit_module: u32,
    pub globals: Box<[u64]>,
    pub globals_snapshot: Vec<u64>,
    pub tables: Vec<Box<[usize]>>,
    // per-slot signature ids, parallel to `tables`; u32::MAX when uninitialized.
    // call_indirect checks these to reject mismatched/empty slots.
    pub table_sigs: Vec<Box<[u32]>>,
    pub debugstrs: Vec<String>,
    pub input_ptr: u32,
    pub input_size: usize,
    pub input: Vec<u8>,
    pub feedback: FeedbackContext,
    pub concolic: ConcolicContext,
    pub host_ptrs_backing: RefCell<Vec<usize>>,
    pub tainted: bool,
    pub random_get_seed: u64,
}

impl VMContext {
    pub(crate) fn new(module: &ModuleSpec) -> Box<Self> {
        let globals = module
            .globals
            .iter()
            .map(|v| v.as_bits())
            .collect::<Box<[_]>>();

        // one function table per declared table, sized to the declared minimum
        // but grown if an element segment reaches further (covers the
        // no-TableSection / imported-table cases). slots default to the
        // 0xdeadf00f sentinel so calling an uninitialized one traps.
        let mut table_sizes: Vec<usize> =
            module.func_table_sizes.iter().map(|&n| n as usize).collect();
        for (table_index, offset, funcs) in &module.func_table_inits {
            let needed = offset + funcs.len();
            let idx = *table_index as usize;
            if idx >= table_sizes.len() {
                table_sizes.resize(idx + 1, 0);
            }
            table_sizes[idx] = table_sizes[idx].max(needed);
        }
        let tables: Vec<Box<[usize]>> = table_sizes
            .into_iter()
            .map(|len| vec![0xdeadf00fusize; len].into_boxed_slice())
            .collect();

        // signature ids parallel to `tables`; ref.null slots stay u32::MAX
        let mut table_sigs: Vec<Box<[u32]>> = tables
            .iter()
            .map(|t| vec![u32::MAX; t.len()].into_boxed_slice())
            .collect();
        for (table_index, offset, funcs) in &module.func_table_inits {
            for (i, f) in funcs.iter().enumerate() {
                if *f == u32::MAX {
                    continue;
                }
                table_sigs[*table_index as usize][offset + i] =
                    module.canonical_type_id(module.func_type(*f));
            }
        }

        // 8 GiB + 1-page guard region: a wasm32 effective address is
        // addr32 (<4 GiB) + static offset (<4 GiB) + access width, so the full
        // span must be reserved for large-offset OOB accesses to fault
        let guard_mapping_size = (1usize << 33) + (1 << 16);
        let mut heap_alloc: Box<dyn ResettableMapping> = if RestoreDirtyLKMMapping::is_available() {
            Box::new(RestoreDirtyLKMMapping::new(
                module.initial_mem_pages << 16,
                guard_mapping_size,
            ))
        } else {
            Box::new(CowResetMapping::new(
                module.initial_mem_pages << 16,
                guard_mapping_size,
            ))
        };

        // Note: we write to the snapshot directly instead of taking a snapshot
        //       to avoid scanning the whole memory area
        for (data, offset) in &module.memory_initializers {
            heap_alloc.as_mut_slice()[*offset..][..data.len()].copy_from_slice(data);
            heap_alloc.snapshot_as_mut_slice()[*offset..][..data.len()].copy_from_slice(data);
        }
        heap_alloc.restore();

        Box::new(Self {
            heap: heap_alloc.as_mut_slice().as_mut_ptr(),
            heap_pages: module.initial_mem_pages as u32,
            heap_pages_limit_soft: crate::MEMORY_PAGES_LIMIT,
            heap_pages_limit_hard: crate::MEMORY_PAGES_LIMIT,
            heap_pages_limit_module: module.initial_mem_pages_max.unwrap_or(u32::MAX),
            fuel: 0,
            fuel_init: u32::MAX as u64,
            heap_pages_snapshot: module.initial_mem_pages as u32,
            heap_alloc,
            heap_snapshot_is_initial: true,
            globals_snapshot: globals.to_vec(),
            globals,
            tables,
            table_sigs,
            host_ptrs: 0xf00dcafe as *const _,
            host_ptrs_backing: RefCell::new(Vec::new()),
            debugstrs: Vec::new(),
            input_size: 0,
            input_ptr: 0,
            input: Vec::new(),
            feedback: FeedbackContext::new(),
            concolic: ConcolicContext::new(module.globals.len()),
            tainted: false,
            random_get_seed: 0xdeadbeefdeadbeef,
        })
    }

    pub(crate) fn finalize(&mut self) {
        let host_ptrs = self.host_ptrs_backing.try_borrow().unwrap();
        self.host_ptrs = host_ptrs.as_ptr();
    }

    pub(crate) fn heap(&mut self) -> &mut [u8] {
        self.heap_alloc.as_mut_slice()
    }

    pub(crate) fn snapshot(&mut self) {
        tracy_full::zone!("VMContext::snapshot");
        assert!(!self.tainted);
        self.globals_snapshot.copy_from_slice(&self.globals);
        self.heap_pages_snapshot = self.heap_pages;
        self.heap_alloc.snapshot();
        self.heap_snapshot_is_initial = false;
    }

    pub(crate) fn restore(&mut self) {
        tracy_full::zone!("VMContext::restore");
        self.globals.copy_from_slice(&self.globals_snapshot);
        self.heap_pages = self.heap_pages_snapshot;
        self.heap_alloc.restore();
        self.concolic.reset();

        // input_ptr should be fine still
        self.input_size = 0;
        self.tainted = false;
        self.random_get_seed = 0xdeadbeefdeadbeef;
    }

    /// Resets the instance
    pub(crate) fn reset(&mut self) {
        tracy_full::zone!("VMContext::reset");
        assert!(self.heap_snapshot_is_initial);

        self.input_ptr = 0;
        self.restore();
    }

    /// Resets this instance to the "initial" state
    pub(crate) fn reset_to_initial_and_snapshot(&mut self, from: &ModuleSpec) {
        // Initialize globals and snapshot
        let globals = from
            .globals
            .iter()
            .map(|v| v.as_bits())
            .collect::<Box<[_]>>();
        self.globals_snapshot.copy_from_slice(&globals);
        self.heap_pages_limit_module = from.initial_mem_pages_max.unwrap_or(u32::MAX);

        // Initialize memory and snapshot
        self.heap_alloc.resize(from.initial_mem_pages << 16);
        self.heap_alloc.as_mut_slice().fill(0);
        self.heap_alloc.snapshot_as_mut_slice().fill(0);
        for (data, offset) in &from.memory_initializers {
            self.heap_alloc.as_mut_slice()[*offset..][..data.len()].copy_from_slice(data);
            self.heap_alloc.snapshot_as_mut_slice()[*offset..][..data.len()].copy_from_slice(data);
        }
        // NB: redundant
        // self.heap_alloc.restore();

        self.heap_snapshot_is_initial = true;
        self.reset();
    }

    pub(crate) fn builtin_consume_fuel(&mut self, delta: u64) {
        if self.fuel >= delta {
            self.fuel -= delta;
        } else {
            unsafe { raise_trap(TrapReason::OutOfFuel) };
        }
    }
}
