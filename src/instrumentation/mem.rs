use cranelift::codegen::ir::{self, InstBuilder, MemFlags, Type, Value, types};

use crate::ir::{Location, ModuleSpec};

use super::{
    AssociatedCoverageArray, InstrCtx, KVInstrumentationPass, feedback_lattice::ValueRange,
};

fn iter_memory(
    load: bool,
    store: bool,
    incl_float: bool,
    spec: &ModuleSpec,
) -> impl Iterator<Item = Location> + '_ {
    use crate::ir::{MemoryInstruction as MI, WFOperator};
    spec.functions.iter().flat_map(move |f| {
        f.operators.iter().enumerate().filter_map(move |(idx, op)| {
            let WFOperator::Memory(op) = op else {
                return None;
            };
            let (is_load, is_store, is_float) = match op {
                MI::I32Load(_)
                | MI::I32Load8U(_)
                | MI::I32Load8S(_)
                | MI::I32Load16U(_)
                | MI::I32Load16S(_)
                | MI::I64Load(_)
                | MI::I64Load8U(_)
                | MI::I64Load8S(_)
                | MI::I64Load16U(_)
                | MI::I64Load16S(_)
                | MI::I64Load32U(_)
                | MI::I64Load32S(_) => (true, false, false),
                MI::I32Store(_)
                | MI::I32Store8(_)
                | MI::I32Store16(_)
                | MI::I64Store(_)
                | MI::I64Store8(_)
                | MI::I64Store16(_)
                | MI::I64Store32(_) => (false, true, false),
                MI::F32Load(_) | MI::F64Load(_) => (true, false, true),
                MI::F32Store(_) | MI::F64Store(_) => (false, true, true),
                _ => return None,
            };
            if (is_load != load) || (is_store != store) || (is_float && !incl_float) {
                return None;
            }
            Some(Location {
                function: f.idx,
                index: idx as u32,
            })
        })
    })
}

pub(crate) struct MemoryOpAddressRangePass {
    coverage: AssociatedCoverageArray<Location, ValueRange>,
}

impl MemoryOpAddressRangePass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(key_filter)
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for MemoryOpAddressRangePass {
    type Key = Location;
    type Value = ValueRange;
    super::traits::impl_kv_instrumentation_pass!("memory-op-addr-range");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Location> {
        iter_memory(true, false, true, spec)
    }

    fn instrument_memory_load(
        &self,
        address: Value,
        _imm_offset: u32,
        _res: Value,
        _ty: Type,
        _opcode: ir::Opcode,
        mut ctx: InstrCtx,
    ) {
        self.coverage
            .instrument_range(&ctx.state.loc(), address, types::I32, &mut ctx, self);
    }

    fn instrument_memory_store(
        &self,
        address: Value,
        _imm_offset: u32,
        _val: Value,
        _ty: Type,
        _opcode: ir::Opcode,
        mut ctx: InstrCtx,
    ) {
        self.coverage
            .instrument_range(&ctx.state.loc(), address, types::I32, &mut ctx, self);
    }
}

pub(crate) struct MemoryLoadValRangePass {
    coverage: AssociatedCoverageArray<Location, ValueRange>,
}

impl MemoryLoadValRangePass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(key_filter)
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for MemoryLoadValRangePass {
    type Key = Location;
    type Value = ValueRange;
    super::traits::impl_kv_instrumentation_pass!("memory-load-profile");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Location> {
        iter_memory(true, false, false, spec)
    }

    fn instrument_memory_load(
        &self,
        _address: Value,
        _imm_offset: u32,
        res: Value,
        ty: Type,
        _opcode: ir::Opcode,
        mut ctx: InstrCtx,
    ) {
        self.coverage
            .instrument_range(&ctx.state.loc(), res, ty, &mut ctx, self);
    }
}

pub(crate) struct MemoryStoreValRangePass {
    coverage: AssociatedCoverageArray<Location, ValueRange>,
}

impl MemoryStoreValRangePass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(key_filter)
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for MemoryStoreValRangePass {
    type Key = Location;
    type Value = ValueRange;
    super::traits::impl_kv_instrumentation_pass!("memory-store-profile");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Location> {
        iter_memory(true, false, false, spec)
    }

    fn instrument_memory_store(
        &self,
        _address: Value,
        _imm_offset: u32,
        val: Value,
        ty: Type,
        _opcode: ir::Opcode,
        mut ctx: InstrCtx,
    ) {
        self.coverage
            .instrument_range(&ctx.state.loc(), val, ty, &mut ctx, self);
    }
}

pub(crate) struct MemoryStorePrevValRangePass {
    coverage: AssociatedCoverageArray<Location, ValueRange>,
}

impl MemoryStorePrevValRangePass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(key_filter)
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for MemoryStorePrevValRangePass {
    type Key = Location;
    type Value = ValueRange;
    super::traits::impl_kv_instrumentation_pass!("memory-store-profile");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Location> {
        iter_memory(false, true, false, spec)
    }

    fn instrument_memory_store(
        &self,
        addr32: Value,
        imm_offset: u32,
        _val: Value,
        ty: Type,
        opcode: ir::Opcode,
        mut ctx: InstrCtx,
    ) {
        if !self.coverage.has_key(&ctx.state.loc()) {
            return;
        }
        let load_opcode = match opcode {
            ir::Opcode::Store => ir::Opcode::Load,
            ir::Opcode::Istore8 => ir::Opcode::Uload8,
            ir::Opcode::Istore16 => ir::Opcode::Uload16,
            ir::Opcode::Istore32 => ir::Opcode::Uload32,
            _ => unreachable!(),
        };

        let base = ctx.state.get_heap_base(ctx.bcx);
        let addr = ctx.bcx.ins().uextend(ctx.state.ptr_ty(), addr32);
        let addr = ctx.bcx.ins().iadd(base, addr);
        let offset = ir::immediates::Offset32::new(imm_offset as i32);
        let mut flags = MemFlags::new();
        flags.set_endianness(ir::Endianness::Little);
        let (load, dfg) = ctx.bcx.ins().Load(load_opcode, ty, flags, offset, addr);
        let val = dfg.first_result(load);
        self.coverage
            .instrument_range(&ctx.state.loc(), val, ty, &mut ctx, self);
    }
}
