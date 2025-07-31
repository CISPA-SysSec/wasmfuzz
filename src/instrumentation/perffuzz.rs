use cranelift::codegen::ir::{self, InstBuilder, MemFlags};
use cranelift::frontend::Variable;
use cranelift::module::{DataDescription, DataId, Module};

use crate::{
    HashMap,
    ir::{Location, ModuleSpec},
};

use super::{
    AssociatedCoverageArray, Edge, FeedbackLattice, FeedbackLatticeCodegen, FuncIdx, InstrCtx,
    KVInstrumentationPass, feedback_lattice::Maximize,
};

pub(crate) struct EdgeHitsInAFunctionPass {
    coverage: AssociatedCoverageArray<Edge, Maximize<u32>>,
}

impl EdgeHitsInAFunctionPass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(|x| key_filter(&Location::from(*x)))
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for EdgeHitsInAFunctionPass {
    type Key = Edge;
    type Value = Maximize<u32>;
    super::traits::impl_kv_instrumentation_pass!("perffuzz-edges-in-function");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        let mut edges: Vec<_> = super::iter_edges(spec).collect();
        let mut func_edge_count: HashMap<u32, usize> = HashMap::default();
        for edge in &edges {
            *func_edge_count.entry(edge.function).or_default() += 1;
        }
        // Note: We filter out functions with lots of edges to work around this issue:
        // `couldn't compile function: Compilation(CodeTooLarge)`
        // It seems like something funky is going on in `cranelift-frontend`... TODO: Investigate?
        // 1000 locals in a function should not break things in the way it does currently
        edges.retain(|edge| *func_edge_count.entry(edge.function).or_default() < 500);
        edges.into_iter()
    }

    fn instrument_function(&self, mut ctx: InstrCtx) {
        let val = ctx.bcx.ins().iconst(ir::types::I32, 0);
        // let mut ctr = 0;
        for edge in self.coverage.keys.iter() {
            if edge.function == ctx.state.fidx {
                // ctr += 1;
                let var = ctx.bcx.declare_var(ir::types::I32);
                ctx.bcx.def_var(var, val);
                *ctx.instance_meta((self.shortcode(), edge)) = Some(var);
            }
        }
        // dbg!(&ctx.state.fspec()._symbol);
        // dbg!(ctx.state.fidx, ctr);
    }

    fn instrument_edge(&self, edge: Edge, mut ctx: InstrCtx) {
        if !self.coverage.has_key(&edge) {
            return;
        }

        let var = ctx
            .instance_meta::<_, Option<Variable>>((self.shortcode(), edge))
            .unwrap();
        let val = ctx.bcx.use_var(var);
        let val = ctx.bcx.ins().iadd_imm(val, 1);
        ctx.bcx.def_var(var, val);
        self.coverage.instrument_coverage(&edge, val, ctx, self);
    }
}

fn get_data<P: KVInstrumentationPass>(pass: &P, ctx: &mut InstrCtx) -> DataId {
    let key = pass.shortcode();
    if ctx.instance_meta::<_, Option<DataId>>(key).is_none() {
        let val = ctx
            .state
            .module
            .declare_anonymous_data(true, false)
            .unwrap();
        let mut data_desc = DataDescription::new();
        data_desc.define_zeroinit(pass.coverage().keys.len() * std::mem::size_of::<u32>());
        data_desc.set_align(std::mem::align_of::<u32>() as _);
        ctx.state.module.define_data(val, &data_desc).unwrap();
        *ctx.instance_meta::<_, Option<DataId>>(key).insert(val)
    } else {
        ctx.instance_meta::<_, Option<DataId>>(key).unwrap()
    }
}

fn instrument_trampoline<P: KVInstrumentationPass>(pass: &P, mut ctx: InstrCtx) {
    let data = get_data(pass, &mut ctx);

    let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
    let buffer = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

    let size = pass.coverage().keys.len() * std::mem::size_of::<u32>();
    ctx.bcx.emit_small_memset(
        ctx.state.module.target_config(),
        buffer,
        0,
        size as u64,
        std::mem::align_of::<u32>() as _,
        MemFlags::trusted(),
    );
}

fn instrument_hitcounter<K, V, P>(pass: &P, key: K, mut ctx: InstrCtx)
where
    K: Clone + Ord,
    V: FeedbackLattice + FeedbackLatticeCodegen + Clone,
    P: KVInstrumentationPass<Key = K, Value = V>,
{
    if !pass.coverage().has_key(&key) {
        return;
    }

    let data = get_data(pass, &mut ctx);
    let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
    let buffer = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);
    let index = pass.coverage().keys.binary_search(&key).unwrap();
    let offset = index * std::mem::size_of::<u32>();

    let val = ctx
        .bcx
        .ins()
        .load(ir::types::I32, MemFlags::trusted(), buffer, offset as i32);
    let val = ctx.bcx.ins().iadd_imm(val, 1);
    ctx.bcx
        .ins()
        .store(MemFlags::trusted(), val, buffer, offset as i32);
    pass.coverage().instrument_coverage(&key, val, ctx, pass);
}

pub(crate) struct PerffuzzFunctionPass {
    pub coverage: AssociatedCoverageArray<FuncIdx, Maximize<u32>>,
}

impl PerffuzzFunctionPass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(|x| key_filter(&Location::from(*x)))
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for PerffuzzFunctionPass {
    type Key = FuncIdx;
    type Value = Maximize<u32>;
    super::traits::impl_kv_instrumentation_pass!("perffuzz-function");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_funcs(spec)
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(self, ctx)
    }

    fn instrument_function(&self, ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);
        instrument_hitcounter(self, key, ctx)
    }
}

pub(crate) struct PerffuzzBBPass {
    pub coverage: AssociatedCoverageArray<Location, Maximize<u32>>,
}

impl PerffuzzBBPass {
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

impl KVInstrumentationPass for PerffuzzBBPass {
    type Key = Location;
    type Value = Maximize<u32>;
    super::traits::impl_kv_instrumentation_pass!("perffuzz-bbs");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_bbs(spec)
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(self, ctx)
    }

    fn instrument_basic_block(&self, ctx: InstrCtx) {
        let key = ctx.state.loc();
        instrument_hitcounter(self, key, ctx)
    }
}

pub(crate) struct PerffuzzEdgePass {
    coverage: AssociatedCoverageArray<Edge, Maximize<u32>>,
}

impl PerffuzzEdgePass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(|x| key_filter(&Location::from(*x)))
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for PerffuzzEdgePass {
    type Key = Edge;
    type Value = Maximize<u32>;
    super::traits::impl_kv_instrumentation_pass!("perffuzz-edges");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_edges(spec)
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(self, ctx)
    }

    fn instrument_edge(&self, key: Edge, ctx: InstrCtx) {
        instrument_hitcounter(self, key, ctx)
    }
}

pub(crate) struct FunctionRecursionDepthPass {
    pub coverage: AssociatedCoverageArray<FuncIdx, Maximize<u32>>,
}

impl FunctionRecursionDepthPass {
    pub(crate) fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(
                &Self::generate_keys(spec)
                    .filter(|x| key_filter(&Location::from(*x)))
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

impl KVInstrumentationPass for FunctionRecursionDepthPass {
    type Key = FuncIdx;
    type Value = Maximize<u32>;
    super::traits::impl_kv_instrumentation_pass!("func-rec-depth");

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_funcs(spec)
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(self, ctx)
    }

    fn instrument_function(&self, mut ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);

        if !self.coverage.has_key(&key) {
            return;
        }

        let data = get_data(self, &mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let buffer = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);
        let index = self.coverage.keys.binary_search(&key).unwrap();
        let offset = index * std::mem::size_of::<u32>();

        let val = ctx
            .bcx
            .ins()
            .load(ir::types::I32, MemFlags::trusted(), buffer, offset as i32);
        let val = ctx.bcx.ins().iadd_imm(val, 1);
        ctx.bcx
            .ins()
            .store(MemFlags::trusted(), val, buffer, offset as i32);
        self.coverage.instrument_coverage(&key, val, ctx, self);
    }

    fn instrument_function_ret(&self, mut ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);

        if !self.coverage.has_key(&key) {
            return;
        }

        let data = get_data(self, &mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let buffer = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);
        let index = self.coverage.keys.binary_search(&key).unwrap();
        let offset = index * std::mem::size_of::<u32>();

        let val = ctx
            .bcx
            .ins()
            .load(ir::types::I32, MemFlags::trusted(), buffer, offset as i32);
        let val = ctx.bcx.ins().iadd_imm(val, -1);
        ctx.bcx
            .ins()
            .store(MemFlags::trusted(), val, buffer, offset as i32);
    }
}
