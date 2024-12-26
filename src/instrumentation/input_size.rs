use cranelift::codegen::ir::{self, InstBuilder, MemFlags};
use cranelift::module::{DataDescription, DataId, Module};

use crate::{ir::ModuleSpec, jit::vmcontext::VMContext};

use super::{
    feedback_lattice::Minimize, AssociatedCoverageArray, FuncIdx, InstrCtx, KVInstrumentationPass,
};

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
pub(crate) enum InputComplexityMetric {
    Size,
    ByteDiversity,
    DeBruijn,
}

/// Tracks the smallest input that reaches each function.
pub(crate) struct InputSizePass {
    pub metric: InputComplexityMetric,
    pub coverage: AssociatedCoverageArray<FuncIdx, Minimize<u16>>,
}

impl InputSizePass {
    pub(crate) fn new(metric: InputComplexityMetric, spec: &ModuleSpec) -> Self {
        Self {
            metric,
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for InputSizePass {
    type Key = FuncIdx;
    type Value = Minimize<u16>;
    super::traits::impl_kv_instrumentation_pass!();

    fn shortcode(&self) -> &'static str {
        match self.metric {
            InputComplexityMetric::Size => "input-size",
            InputComplexityMetric::ByteDiversity => "input-size-diversity",
            InputComplexityMetric::DeBruijn => "input-size-debruijn",
        }
    }

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_funcs(spec)
    }

    fn instrument_function(&self, mut ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);
        let data = self.get_cost_var(&mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let cost_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);
        let cost = ctx
            .bcx
            .ins()
            .load(ir::types::I16, MemFlags::trusted(), cost_ptr, 0);
        self.coverage.instrument_coverage(&key, cost, ctx, self);
    }

    fn instrument_trampoline(&self, mut ctx: InstrCtx) {
        let data = self.get_cost_var(&mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let cost_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);
        let zero = ctx.bcx.ins().iconst(ir::types::I16, 0);
        ctx.bcx.ins().store(MemFlags::trusted(), zero, cost_ptr, 0);
    }

    fn instrument_fuzz_trampoline(
        &self,
        inp_ptr: ir::Value,
        inp_size: ir::Value,
        mut ctx: InstrCtx,
    ) {
        let data = self.get_cost_var(&mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let cost_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

        let size_fn = match self.metric {
            InputComplexityMetric::Size => compute_metric_size,
            InputComplexityMetric::ByteDiversity => compute_metric_byte_diversity,
            InputComplexityMetric::DeBruijn => compute_metric_debrujin,
        };

        let [cost_val] = ctx.state.host_call(
            ctx.bcx,
            size_fn as unsafe extern "C" fn(_, _, _) -> u16,
            &[inp_ptr, inp_size],
        );
        ctx.bcx
            .ins()
            .store(MemFlags::trusted(), cost_val, cost_ptr, 0);

        unsafe extern "C" fn compute_metric_size(
            _inp_ptr: u32,
            inp_size: u32,
            _vmctx: *mut VMContext,
        ) -> u16 {
            inp_size as _
        }

        unsafe extern "C" fn compute_metric_byte_diversity(
            inp_ptr: u32,
            inp_size: u32,
            vmctx: *mut VMContext,
        ) -> u16 {
            let vmctx = &mut *vmctx;
            let buf = &vmctx.heap()[inp_ptr as usize..][..inp_size as usize];
            assert_eq!(buf.len(), inp_size as usize);
            let mut count = [0u8; 256];
            for el in buf {
                count[*el as usize] = count[*el as usize].saturating_add(1);
            }
            let mut res = 0;
            for el in count {
                if el > 0 && el < 8 {
                    res += 1 << (el as usize - 1);
                } else if el >= 8 {
                    res += (el as usize) << 7;
                }
            }
            res.try_into().unwrap_or(u16::MAX)
        }

        unsafe extern "C" fn compute_metric_debrujin(
            inp_ptr: u32,
            inp_size: u32,
            vmctx: *mut VMContext,
        ) -> u16 {
            let vmctx = &mut *vmctx;
            let buf = &vmctx.heap()[inp_ptr as usize..][..inp_size as usize];
            assert_eq!(buf.len(), inp_size as usize);

            // i.e. +1 size for every byte that doesn't match cyclic()
            // b"aaaabaaacaaa"[...]
            let mut res = 0;
            for (i, el) in buf.chunks(4).enumerate() {
                let mut i_ = i;
                for &c in el {
                    let expected_char = b'a' + (i_ % 26) as u8;
                    res += (c != expected_char) as usize;
                    if i_ != 0 {
                        i_ /= 26
                    };
                }
            }
            res.try_into().unwrap_or(u16::MAX)
        }
    }
}

impl InputSizePass {
    fn get_cost_var(&self, ctx: &mut InstrCtx) -> DataId {
        let key = ("input-size", self.metric);
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
}
