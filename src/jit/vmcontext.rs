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
    pub globals: Box<[u64]>,
    pub globals_snapshot: Vec<u64>,
    pub tables: Vec<Box<[usize]>>,
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

        // These tables need to be backfilled with each function's code pointer
        let tables = module
            .scuffed_func_table_initializers
            .iter()
            // trapped at unknown pc 0xdeadf00f: call_indirect to
            .map(|(table, offset)| vec![0xdeadf00fusize; table.len() + *offset].into_boxed_slice())
            .collect();

        let mut heap_alloc: Box<dyn ResettableMapping> = if RestoreDirtyLKMMapping::is_available() {
            Box::new(RestoreDirtyLKMMapping::new(
                module.initial_mem_pages << 16,
                1 << 32,
            ))
        } else {
            Box::new(CowResetMapping::new(
                module.initial_mem_pages << 16,
                1 << 32,
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
            fuel: 0,
            fuel_init: u32::MAX as u64,
            heap_pages_snapshot: module.initial_mem_pages as u32,
            heap_alloc,
            heap_snapshot_is_initial: true,
            globals_snapshot: globals.to_vec(),
            globals,
            tables,
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

    pub(crate) fn reset(&mut self, from: &ModuleSpec) {
        tracy_full::zone!("VMContext::reset");
        self.input_ptr = 0;
        self.input_size = 0;
        self.heap_pages = from.initial_mem_pages as u32;
        assert!(self.heap_snapshot_is_initial);
        self.heap_alloc.restore();
        // reset globals
        for (val, initial) in self.globals.iter_mut().zip(&from.globals) {
            *val = initial.as_bits();
        }
        self.concolic.reset();
        self.tainted = false;
        self.random_get_seed = 0xdeadbeefdeadbeef;
    }

    pub(crate) fn reset_to_initial(&mut self, from: &ModuleSpec) {
        let globals = from
            .globals
            .iter()
            .map(|v| v.as_bits())
            .collect::<Box<[_]>>();
        self.globals_snapshot.copy_from_slice(&globals);

        self.heap_alloc.resize(from.initial_mem_pages << 16);
        self.heap_alloc.as_mut_slice().fill(0);
        self.heap_alloc.snapshot_as_mut_slice().fill(0);
        for (data, offset) in &from.memory_initializers {
            self.heap_alloc.as_mut_slice()[*offset..][..data.len()].copy_from_slice(data);
            self.heap_alloc.snapshot_as_mut_slice()[*offset..][..data.len()].copy_from_slice(data);
        }
        self.heap_alloc.restore();

        self.heap_snapshot_is_initial = true;
        self.reset(from);
    }

    pub(crate) fn builtin_consume_fuel(&mut self, delta: u64) {
        if self.fuel >= delta {
            self.fuel -= delta;
        } else {
            unsafe { raise_trap(TrapReason::OutOfFuel) };
        }
    }
}
