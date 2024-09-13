use cranelift::codegen::ir::{self, condcodes::IntCC, InstBuilder, MemFlags, Type, Value};
use cranelift::frontend::FunctionBuilder;

use crate::ir::{Location, ModuleSpec};

use super::{feedback_lattice::Minimize, AssociatedCoverageArray, InstrCtx, KVInstrumentationPass};

pub(crate) enum CmpCovKind {
    Hamming,
    AbsDist,
}

pub(crate) struct CmpCoveragePass {
    kind: CmpCovKind,
    coverage: AssociatedCoverageArray<Location, Minimize<u8>>,
}

impl CmpCoveragePass {
    pub(crate) fn new(kind: CmpCovKind, spec: &ModuleSpec) -> Self {
        Self {
            kind,
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }

    fn calculate_hamming_distance(
        &self,
        value_ty: Type,
        mut value_a: Value,
        mut value_b: Value,
        bcx: &mut FunctionBuilder,
    ) -> Value {
        use ir::types::*;
        if value_ty == F32 {
            // value_ty = I32;
            value_a = bcx.ins().bitcast(I32, MemFlags::new(), value_a);
            value_b = bcx.ins().bitcast(I32, MemFlags::new(), value_b);
        } else if value_ty == F64 {
            // value_ty = I64;
            value_a = bcx.ins().bitcast(I64, MemFlags::new(), value_a);
            value_b = bcx.ins().bitcast(I64, MemFlags::new(), value_b);
        }
        let dist = bcx.ins().bxor(value_a, value_b);
        let dist = bcx.ins().popcnt(dist);
        bcx.ins().ireduce(I8, dist)
    }

    fn calculate_absdist_distance(
        &self,
        value_ty: Type,
        value_a: Value,
        value_b: Value,
        bcx: &mut FunctionBuilder,
    ) -> ir::Value {
        use ir::types::*;
        match value_ty {
            F32 => {
                let diff = bcx.ins().fsub(value_a, value_b);
                // IEEE 754 binary32 layout:
                // 1 sign 8 exponent 23 fraction
                // extract exponent:
                let val = bcx.ins().bitcast(I32, MemFlags::new(), diff);
                let val = bcx.ins().ishl_imm(val, 1);
                let val = bcx.ins().ushr_imm(val, 24);
                bcx.ins().ireduce(I8, val)
            }
            F64 => {
                let diff = bcx.ins().fsub(value_a, value_b);
                // IEEE 754 binary64 layout:
                // 1 sign 11 exponent 52 fraction
                // extract exponent:
                let val = bcx.ins().bitcast(I64, MemFlags::new(), diff);
                let val = bcx.ins().ishl_imm(val, 1);
                let val = bcx.ins().ushr_imm(val, 53);
                let u8_max = bcx.ins().iconst(I64, 255);
                let val = bcx.ins().smin(val, u8_max);
                bcx.ins().ireduce(I8, val)
            }
            I32 | I64 => {
                // Note: is this correct?
                let smaller = bcx.ins().smin(value_a, value_b);
                let bigger = bcx.ins().smax(value_a, value_b);
                let dist = bcx.ins().isub(bigger, smaller);

                let val = bcx.ins().clz(dist);

                let val = if true {
                    // progress:
                    // 0-128: 128-distance
                    // 128-192: 128+clz(distance)

                    let thresh = 255 - value_ty.bits() as i64;
                    let v_thresh = bcx.ins().iconst(value_ty, thresh);
                    let is_small = bcx.ins().icmp(IntCC::UnsignedLessThan, dist, v_thresh);

                    let x = bcx.ins().irsub_imm(dist, thresh);
                    let y = bcx.ins().iadd_imm(dist, thresh);

                    bcx.ins().select(is_small, x, y)
                } else {
                    val
                };

                bcx.ins().ireduce(I8, val)
            }
            _ => unreachable!(),
        }
    }
}

impl KVInstrumentationPass for CmpCoveragePass {
    type Key = Location;
    type Value = Minimize<u8>;

    fn shortcode(&self) -> &'static str {
        match self.kind {
            CmpCovKind::Hamming => "cmpcov-hamming",
            CmpCovKind::AbsDist => "cmpcov-absdist",
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }

    fn coverage_mut(&mut self) -> &mut AssociatedCoverageArray<Self::Key, Self::Value> {
        &mut self.coverage
    }

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        super::iter_cmp_instrs(spec)
    }

    fn instrument_cmp(&self, value_ty: Type, value_a: Value, value_b: Value, ctx: InstrCtx) {
        if !self.coverage.has_key(&ctx.state.loc()) {
            return;
        }
        let dist_fn = match self.kind {
            CmpCovKind::Hamming => Self::calculate_hamming_distance,
            CmpCovKind::AbsDist => Self::calculate_absdist_distance,
        };
        let dist = dist_fn(self, value_ty, value_a, value_b, ctx.bcx);
        self.coverage
            .instrument_coverage(&ctx.state.loc(), dist, ctx, self);
    }
}
