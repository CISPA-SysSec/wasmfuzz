use std::any::Any;

use cranelift::codegen::ir::{self, Type, Value};

use crate::ir::{Location, ModuleSpec};

use super::{
    code_coverage::CoverageBitset, path_hash::HashBitset, AssociatedCoverageArray, CovSnapshot,
    Edge, ErasedInstrumentationPassHelper, FeedbackLattice, FuncIdx, InstrCtx,
};

macro_rules! _def {
    (empty $func_name:ident(&self $(, $param:ident:$param_ty:ty)*)) => {
        fn $func_name(&self $(, $param: $param_ty)*, _ctx: InstrCtx) {
            let _ = ($($param,)*);
        }
    };
    (no_body $func_name:ident(&self $(, $param:ident:$param_ty:ty)*)) => {
        fn $func_name(&self $(, $param: $param_ty)*, ctx: InstrCtx);
    };
    (dispatch $func_name:ident(&self $(, $param:ident:$param_ty:ty)*)) => {
        fn $func_name(&self $(, $param: $param_ty)*, ctx: InstrCtx) {
            if ctx.state.dead(ctx.bcx) {
                return;
            }
            match self {
                ErasedInstrumentationPassHelper::KV(x) => x.$func_name($($param,)* ctx),
                ErasedInstrumentationPassHelper::CodeCov(x) => x.$func_name($($param,)* ctx),
                ErasedInstrumentationPassHelper::HashBitset(x) => x.$func_name($($param,)* ctx),
                ErasedInstrumentationPassHelper::Erased(x) => x.$func_name($($param,)* ctx),
            }
        }
    }
}
macro_rules! instrumentation_hook_fn_defs {
    ($t:tt) => {
        _def!($t instrument_function(&self));
        _def!($t instrument_basic_block(&self));
        _def!($t instrument_edge(&self, edge: Edge));

        _def!($t instrument_trampoline(&self));
        _def!($t instrument_fuzz_trampoline(&self, inp_ptr: ir::Value, inp_size: ir::Value));
        _def!($t instrument_trampoline_ret(&self));

        _def!($t instrument_function_ret(&self));
        _def!($t instrument_cmp(&self, ty: Type, lhs: Value, rhs: Value));
        _def!($t instrument_memory_load(&self, address: Value, imm_offset: u32, res: Value, ty: Type, opcode: ir::Opcode));
        _def!($t instrument_memory_store(&self, address: Value, imm_offset: u32, val: Value, ty: Type, opcode: ir::Opcode));
        _def!($t instrument_call(&self, target: Option<FuncIdx>, params: &[Value], tys: &[Type]));
        _def!($t instrument_call_return(&self, target: Option<FuncIdx>, returns: &[Value], tys: &[Type]));
        _def!($t instrument_global_set(&self, index: u32, val: Value, ty: Type));
    };
}

macro_rules! impl_kv_instrumentation_pass {
    () => {
        fn as_any(&self) -> &dyn std::any::Any {
            self as &dyn std::any::Any
        }
        fn coverage(&self) -> &AssociatedCoverageArray<Self::Key, Self::Value> {
            &self.coverage
        }
        fn coverage_mut(&mut self) -> &mut AssociatedCoverageArray<Self::Key, Self::Value> {
            &mut self.coverage
        }
    };
    ($shortcode:literal) => {
        fn shortcode(&self) -> &'static str {
            $shortcode
        }
        crate::instrumentation::traits::impl_kv_instrumentation_pass!();
    };
}
pub(crate) use impl_kv_instrumentation_pass;

pub(crate) trait KVInstrumentationPass {
    type Key: Into<Location> + Ord + Clone; // = Location
    type Value: FeedbackLattice + 'static;

    /// Returns a short string (<12 chars) that describes this specific pass
    fn shortcode(&self) -> &'static str;

    fn as_any(&self) -> &dyn Any;
    fn coverage(&self) -> &AssociatedCoverageArray<Self::Key, Self::Value>;
    fn coverage_mut(&mut self) -> &mut AssociatedCoverageArray<Self::Key, Self::Value>;

    fn generate_keys(_modspec: &ModuleSpec) -> impl Iterator<Item = Self::Key>
    where
        Self: Sized,
    {
        std::iter::empty()
    }

    fn update_and_scan_coverage(&mut self) -> bool {
        self.coverage_mut().update_and_scan()
    }
    fn reset_coverage(&mut self) {
        self.coverage_mut().reset()
    }
    fn reset_coverage_keep_saved(&mut self) {
        self.coverage_mut().reset_keep_saved()
    }
    fn snapshot_coverage(&self) -> CovSnapshot {
        self.coverage().snapshot()
    }

    instrumentation_hook_fn_defs!(empty);
}

pub(crate) trait CodeCovInstrumentationPass {
    type Key: Into<Location> + Ord + Clone; // = Location

    instrumentation_hook_fn_defs!(empty);

    fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self
    where
        Self: Sized;

    /// Returns a short string (<12 chars) that describes this specific pass
    fn shortcode(&self) -> &'static str;
    fn coverage(&self) -> &CoverageBitset<Self::Key>;
    fn coverage_mut(&mut self) -> &mut CoverageBitset<Self::Key>;
    fn count_saved(&self) -> usize {
        self.coverage().iter_covered_keys().count()
    }

    fn update_and_scan_coverage(&mut self) -> bool {
        self.coverage_mut().update_and_scan()
    }
    fn reset_coverage(&mut self) {
        self.coverage_mut().reset()
    }
    fn reset_coverage_keep_saved(&mut self) {
        self.coverage_mut().reset_keep_saved()
    }
    fn snapshot_coverage(&self) -> CovSnapshot {
        CovSnapshot::BitBox(self.coverage().entries.clone())
    }

    fn as_any(&self) -> &dyn Any;
}

pub(crate) trait HashBitsetInstrumentationPass {
    type Key: Into<Location> + Ord + Clone; // = Location

    instrumentation_hook_fn_defs!(empty);

    /// Returns a short string (<12 chars) that describes this specific pass
    fn shortcode(&self) -> &'static str;
    fn coverage(&self) -> &HashBitset;
    fn coverage_mut(&mut self) -> &mut HashBitset;

    fn update_and_scan_coverage(&mut self) -> bool {
        self.coverage_mut().update_and_scan()
    }
    fn reset_coverage(&mut self) {
        self.coverage_mut().reset()
    }
    fn reset_coverage_keep_saved(&mut self) {
        self.coverage_mut().reset_keep_saved()
    }
    fn snapshot_coverage(&self) -> CovSnapshot {
        CovSnapshot::BitBox(self.coverage().entries.clone())
    }

    fn as_any(&self) -> &dyn Any;
}

pub trait ErasedInstrumentationPass {
    instrumentation_hook_fn_defs!(no_body);

    fn update_and_scan_coverage(&mut self) -> bool;
    fn reset_coverage(&mut self);
    fn reset_coverage_keep_saved(&mut self);
    fn snapshot_coverage(&self) -> CovSnapshot;
    fn shortcode(&self) -> &'static str;
    fn as_any(&self) -> &dyn Any;
}

macro_rules! dispatch {
    ($func_name:ident(&self $(, $param:ident:$param_ty:ty)*) -> $ret:ty) => {
        fn $func_name(&self $(, $param: $param_ty)*) -> $ret {
            match self {
                ErasedInstrumentationPassHelper::KV(x) => x.$func_name($($param,)*),
                ErasedInstrumentationPassHelper::CodeCov(x) => x.$func_name($($param,)*),
                ErasedInstrumentationPassHelper::HashBitset(x) => x.$func_name($($param,)*),
                ErasedInstrumentationPassHelper::Erased(x) => x.$func_name($($param,)*),
            }
        }
    };
    ($func_name:ident(&mut self $(, $param:ident:$param_ty:ty)*) -> $ret:ty) => {
        fn $func_name(&mut self $(, $param: $param_ty)*) -> $ret {
            match self {
                ErasedInstrumentationPassHelper::KV(x) => x.$func_name($($param,)*),
                ErasedInstrumentationPassHelper::CodeCov(x) => x.$func_name($($param,)*),
                ErasedInstrumentationPassHelper::HashBitset(x) => x.$func_name($($param,)*),
                ErasedInstrumentationPassHelper::Erased(x) => x.$func_name($($param,)*),
            }
        }
    };
}

impl<K: Ord + Into<Location> + Clone + 'static, V: FeedbackLattice + 'static>
    ErasedInstrumentationPass for ErasedInstrumentationPassHelper<K, V>
{
    instrumentation_hook_fn_defs!(dispatch);
    dispatch!(update_and_scan_coverage(&mut self) -> bool);
    dispatch!(reset_coverage(&mut self) -> ());
    dispatch!(reset_coverage_keep_saved(&mut self) -> ());
    dispatch!(snapshot_coverage(&self) -> CovSnapshot);
    dispatch!(shortcode(&self) -> &'static str);
    dispatch!(as_any(&self) -> &dyn Any);
}
