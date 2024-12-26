use cranelift::codegen::ir::{self, InstBuilder, MemFlags};
use cranelift::module::{DataDescription, DataId, Module};

use crate::{ir::ModuleSpec, jit::vmcontext::VMContext};

use super::{
    feedback_lattice::{Maximize, Minimize},
    AssociatedCoverageArray, Edge, FeedbackLattice, FeedbackLatticeCodegen, FuncIdx, InstrCtx,
    KVInstrumentationPass,
};

fn get_var(ctx: &mut InstrCtx) -> DataId {
    let key = "initial-fuel";
    if ctx.instance_meta::<_, Option<DataId>>(key).is_none() {
        let val = ctx
            .state
            .module
            .declare_anonymous_data(true, false)
            .unwrap();
        let mut data_desc = DataDescription::new();
        data_desc.define_zeroinit(std::mem::size_of::<u16>());
        ctx.state.module.define_data(val, &data_desc).unwrap();
        *ctx.instance_meta::<_, Option<DataId>>(key).insert(val)
    } else {
        ctx.instance_meta::<_, Option<DataId>>(key).unwrap()
    }
}

fn instrument_site<
    P: KVInstrumentationPass<Key = K, Value = V>,
    K: PartialEq + Ord + Clone,
    V: FeedbackLattice + FeedbackLatticeCodegen,
>(
    pass: &P,
    key: K,
    mut ctx: InstrCtx,
) {
    let data = get_var(&mut ctx);
    let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
    let initial_fuel_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);
    let initial_fuel = ctx
        .bcx
        .ins()
        .load(ir::types::I64, MemFlags::trusted(), initial_fuel_ptr, 0);

    let gv_vmctx = ctx.state.get_vmctx(ctx.bcx);
    let vmctx = ctx.bcx.ins().global_value(ctx.state.ptr_ty(), gv_vmctx);
    let fuel = ctx.bcx.ins().load(
        ir::types::I64,
        MemFlags::trusted(),
        vmctx,
        std::mem::offset_of!(VMContext, fuel) as i32,
    );

    let trace_length = ctx.bcx.ins().isub(initial_fuel, fuel);
    pass.coverage()
        .instrument_coverage(&key, trace_length, ctx, pass);
}

fn instrument_trampoline(mut ctx: InstrCtx) {
    let data = get_var(&mut ctx);
    let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
    let initial_fuel_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

    let gv_vmctx = ctx.state.get_vmctx(ctx.bcx);
    let vmctx = ctx.bcx.ins().global_value(ctx.state.ptr_ty(), gv_vmctx);
    let initial_fuel = ctx.bcx.ins().load(
        ir::types::I64,
        MemFlags::trusted(),
        vmctx,
        std::mem::offset_of!(VMContext, fuel) as i32,
    );
    ctx.bcx
        .ins()
        .store(MemFlags::trusted(), initial_fuel, initial_fuel_ptr, 0);
}

pub(crate) struct FunctionShortestExecutionTracePass {
    pub coverage: AssociatedCoverageArray<FuncIdx, Minimize<u64>>,
}

impl FunctionShortestExecutionTracePass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for FunctionShortestExecutionTracePass {
    type Key = FuncIdx;
    type Value = Minimize<u64>;
    super::traits::impl_kv_instrumentation_pass!("func-shortest-trace");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_funcs(spec)
    }

    fn instrument_function(&self, ctx: InstrCtx) {
        instrument_site(self, FuncIdx(ctx.state.fidx), ctx);
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(ctx)
    }
}

pub(crate) struct FunctionLongestExecutionTracePass {
    pub coverage: AssociatedCoverageArray<FuncIdx, Maximize<u64>>,
}

impl FunctionLongestExecutionTracePass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for FunctionLongestExecutionTracePass {
    type Key = FuncIdx;
    type Value = Maximize<u64>;
    super::traits::impl_kv_instrumentation_pass!("func-longest-trace");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_funcs(spec)
    }

    fn instrument_function(&self, ctx: InstrCtx) {
        instrument_site(self, FuncIdx(ctx.state.fidx), ctx);
    }

    fn instrument_function_ret(&self, ctx: InstrCtx) {
        instrument_site(self, FuncIdx(ctx.state.fidx), ctx);
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(ctx)
    }
}

pub(crate) struct EdgeShortestExecutionTracePass {
    pub coverage: AssociatedCoverageArray<Edge, Minimize<u64>>,
}

impl EdgeShortestExecutionTracePass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for EdgeShortestExecutionTracePass {
    type Key = Edge;
    type Value = Minimize<u64>;
    super::traits::impl_kv_instrumentation_pass!("edge-shortest-trace");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_edges(spec)
    }

    fn instrument_edge(&self, edge: Edge, ctx: InstrCtx) {
        instrument_site(self, edge, ctx);
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(ctx)
    }
}
