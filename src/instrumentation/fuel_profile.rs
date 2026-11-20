//! Fuel attribution passes for `fuel-profile`: inclusive fuel per call site and per function.
//!
//! Both read `vmctx.fuel` around a region (a call, or a function body) and add the difference
//! to a per-key u64 accumulator; the accumulator is reported through a `Maximize<u64>` entry, so
//! the saved value after a run is the run's sum. Bulk-memory and WASI fuel is charged to
//! `vmctx.fuel` by the builtins, so it is included in whatever region it happens in.

use cranelift::codegen::ir::{self, InstBuilder, MemFlagsData};
use cranelift::module::{DataDescription, DataId, Module};
use cranelift::prelude::IntCC;

use crate::{
    ir::{ControlInstruction, Location, ModuleSpec, WFOperator},
    jit::vmcontext::VMContext,
};

use super::{
    AssociatedCoverageArray, FuncIdx, InstrCtx, KVInstrumentationPass, feedback_lattice::Maximize,
};

/// Zero-initialised u64 array of `len` entries, one per pass and `tag`; zeroed again in the
/// trampoline before every run.
fn get_buf(ctx: &mut InstrCtx, shortcode: &'static str, tag: &'static str, len: usize) -> DataId {
    let key = (shortcode, tag);
    if let Some(id) = *ctx.instance_meta::<_, Option<DataId>>(key) {
        return id;
    }
    let id = ctx
        .state
        .module
        .declare_anonymous_data(true, false)
        .unwrap();
    let mut desc = DataDescription::new();
    desc.define_zeroinit(len.max(1) * 8);
    desc.set_align(8);
    ctx.state.module.define_data(id, &desc).unwrap();
    *ctx.instance_meta::<_, Option<DataId>>(key) = Some(id);
    id
}

fn buf_ptr(ctx: &mut InstrCtx, id: DataId) -> ir::Value {
    let gv = ctx.state.module.declare_data_in_func(id, ctx.bcx.func);
    ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv)
}

fn zero_buf(ctx: &mut InstrCtx, shortcode: &'static str, tag: &'static str, len: usize) {
    let id = get_buf(ctx, shortcode, tag, len);
    let ptr = buf_ptr(ctx, id);
    ctx.bcx.emit_small_memset(
        ctx.state.module.target_config(),
        ptr,
        0,
        (len.max(1) * 8) as u64,
        8,
        MemFlagsData::trusted(),
    );
}

fn load_fuel(ctx: &mut InstrCtx) -> ir::Value {
    let vmctx = ctx.state.get_vmctx(ctx.bcx);
    ctx.bcx.ins().load(
        ir::types::I64,
        MemFlagsData::trusted(),
        vmctx,
        std::mem::offset_of!(VMContext, fuel) as i32,
    )
}

/// acc[index] += delta; returns the new sum.
fn accumulate(ctx: &mut InstrCtx, buf: ir::Value, index: usize, delta: ir::Value) -> ir::Value {
    let off = (index * 8) as i32;
    let prev = ctx
        .bcx
        .ins()
        .load(ir::types::I64, MemFlagsData::trusted(), buf, off);
    let sum = ctx.bcx.ins().iadd(prev, delta);
    ctx.bcx
        .ins()
        .store(MemFlagsData::trusted(), sum, buf, off);
    sum
}

pub(crate) fn iter_call_sites(spec: &ModuleSpec) -> impl Iterator<Item = Location> + '_ {
    spec.functions.iter().flat_map(|f| {
        f.operators
            .iter()
            .enumerate()
            .filter_map(move |(idx, op)| match op {
                WFOperator::Control(
                    ControlInstruction::Call { .. } | ControlInstruction::CallIndirect { .. },
                ) => Some(Location {
                    function: f.idx,
                    index: idx as u32,
                }),
                _ => None,
            })
    })
}

/// Fuel spent inside each call (callee and everything below it), per call site.
pub(crate) struct CallSiteFuelPass {
    pub coverage: AssociatedCoverageArray<Location, Maximize<u64>>,
}

impl CallSiteFuelPass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&iter_call_sites(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for CallSiteFuelPass {
    type Key = Location;
    type Value = Maximize<u64>;
    super::traits::impl_kv_instrumentation_pass!("fuel-callsite");

    fn instrument_trampoline(&self, mut ctx: InstrCtx) {
        zero_buf(&mut ctx, self.shortcode(), "acc", self.coverage.keys.len());
    }

    fn instrument_call(
        &self,
        _target: Option<FuncIdx>,
        _params: &[ir::Value],
        _tys: &[ir::Type],
        mut ctx: InstrCtx,
    ) {
        let before = load_fuel(&mut ctx);
        *ctx.instance_meta::<_, Option<ir::Value>>((self.shortcode(), "before")) = Some(before);
    }

    fn instrument_call_return(
        &self,
        _target: Option<FuncIdx>,
        _returns: &[ir::Value],
        _tys: &[ir::Type],
        mut ctx: InstrCtx,
    ) {
        let key = ctx.state.loc();
        let Some(before) = ctx
            .instance_meta::<_, Option<ir::Value>>((self.shortcode(), "before"))
            .take()
        else {
            return;
        };
        let Ok(index) = self.coverage.keys.binary_search(&key) else {
            return;
        };
        let after = load_fuel(&mut ctx);
        let delta = ctx.bcx.ins().isub(before, after);
        let id = get_buf(&mut ctx, self.shortcode(), "acc", self.coverage.keys.len());
        let buf = buf_ptr(&mut ctx, id);
        let sum = accumulate(&mut ctx, buf, index, delta);
        self.coverage.instrument_coverage(&key, sum, ctx, self);
    }
}

/// Fuel spent between function entry and return, per function. `inclusive` counts only the
/// outermost activation of a recursive function (so the value is the fuel spent with the
/// function on the stack); the raw variant sums every activation, which makes
/// `raw(f) - sum(call sites in f)` the fuel charged in f's own frames.
pub(crate) struct FunctionFuelPass {
    pub coverage: AssociatedCoverageArray<FuncIdx, Maximize<u64>>,
    pub inclusive: bool,
}

impl FunctionFuelPass {
    pub(crate) fn new(spec: &ModuleSpec, inclusive: bool) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&super::iter_funcs(spec).collect::<Vec<_>>()),
            inclusive,
        }
    }
}

impl KVInstrumentationPass for FunctionFuelPass {
    type Key = FuncIdx;
    type Value = Maximize<u64>;

    fn shortcode(&self) -> &'static str {
        if self.inclusive {
            "fuel-func-incl"
        } else {
            "fuel-func-raw"
        }
    }
    super::traits::impl_kv_instrumentation_pass!();

    fn instrument_trampoline(&self, mut ctx: InstrCtx) {
        let n = self.coverage.keys.len();
        zero_buf(&mut ctx, self.shortcode(), "acc", n);
        if self.inclusive {
            zero_buf(&mut ctx, self.shortcode(), "depth", n);
        }
    }

    fn instrument_function(&self, mut ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);
        let Ok(index) = self.coverage.keys.binary_search(&key) else {
            return;
        };
        let entry = load_fuel(&mut ctx);
        *ctx.instance_meta::<_, Option<ir::Value>>((self.shortcode(), "entry")) = Some(entry);
        if self.inclusive {
            let id = get_buf(&mut ctx, self.shortcode(), "depth", self.coverage.keys.len());
            let buf = buf_ptr(&mut ctx, id);
            let one = ctx.bcx.ins().iconst(ir::types::I64, 1);
            accumulate(&mut ctx, buf, index, one);
        }
    }

    fn instrument_function_ret(&self, mut ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);
        let Ok(index) = self.coverage.keys.binary_search(&key) else {
            return;
        };
        let Some(entry) = *ctx.instance_meta::<_, Option<ir::Value>>((self.shortcode(), "entry"))
        else {
            return;
        };
        let now = load_fuel(&mut ctx);
        let mut delta = ctx.bcx.ins().isub(entry, now);
        if self.inclusive {
            let id = get_buf(&mut ctx, self.shortcode(), "depth", self.coverage.keys.len());
            let buf = buf_ptr(&mut ctx, id);
            let minus_one = ctx.bcx.ins().iconst(ir::types::I64, -1);
            let depth = accumulate(&mut ctx, buf, index, minus_one);
            // count only when the outermost activation returns (depth back at 0)
            let outer = ctx.bcx.ins().icmp_imm_u(IntCC::Equal, depth, 0);
            let zero = ctx.bcx.ins().iconst(ir::types::I64, 0);
            delta = ctx.bcx.ins().select(outer, delta, zero);
        }
        let id = get_buf(&mut ctx, self.shortcode(), "acc", self.coverage.keys.len());
        let buf = buf_ptr(&mut ctx, id);
        let sum = accumulate(&mut ctx, buf, index, delta);
        self.coverage.instrument_coverage(&key, sum, ctx, self);
    }
}
