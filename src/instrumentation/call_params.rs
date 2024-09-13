use cranelift::codegen::ir::{Type, Value};

use crate::ir::{Location, ModuleSpec};

use super::{
    feedback_lattice::{ValueRange, ValueSet},
    AssociatedCoverageArray, FuncIdx, InstrCtx, KVInstrumentationPass,
};

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub(crate) struct CallArgument {
    location: Location,
    index: usize,
    is_return: bool,
}
impl From<CallArgument> for Location {
    fn from(value: CallArgument) -> Self {
        value.location
    }
}

pub(crate) struct CallParamsRangePass {
    coverage: AssociatedCoverageArray<CallArgument, ValueRange>,
}

impl CallParamsRangePass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for CallParamsRangePass {
    type Key = CallArgument;
    type Value = ValueRange;

    fn shortcode(&self) -> &'static str {
        "call-params-range"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }

    fn coverage_mut(&mut self) -> &mut AssociatedCoverageArray<Self::Key, Self::Value> {
        &mut self.coverage
    }

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        use crate::ir::{ControlInstruction, WFOperator};
        spec.functions.iter().flat_map(|f| {
            f.operators
                .iter()
                .enumerate()
                .filter_map(|(idx, op)| match op {
                    WFOperator::Control(ControlInstruction::Call { function_ty, .. })
                    | WFOperator::Control(ControlInstruction::CallIndirect {
                        function_ty, ..
                    }) => {
                        let loc = Location {
                            function: f.idx,
                            index: idx as u32,
                        };
                        Some((loc, function_ty))
                    }
                    _ => None,
                })
                .flat_map(move |(location, ty)| {
                    let params = ty
                        .params()
                        .iter()
                        .enumerate()
                        .map(move |(index, _)| Self::Key {
                            location,
                            index,
                            is_return: false,
                        });
                    let returns =
                        ty.results()
                            .iter()
                            .enumerate()
                            .map(move |(index, _)| Self::Key {
                                location,
                                index,
                                is_return: true,
                            });
                    params.chain(returns)
                })
        })
    }

    fn instrument_call(
        &self,
        _target: Option<FuncIdx>,
        params: &[Value],
        tys: &[Type],
        mut ctx: InstrCtx,
    ) {
        let location = ctx.state.loc();
        for (index, (&param, &ty)) in params.iter().zip(tys.iter()).enumerate() {
            let key = CallArgument {
                index,
                location,
                is_return: false,
            };
            if self.coverage.has_key(&key) {
                self.coverage
                    .instrument_range(&key, param, ty, &mut ctx, self);
            }
        }
    }
    fn instrument_call_return(
        &self,
        _target: Option<FuncIdx>,
        returns: &[Value],
        tys: &[Type],
        mut ctx: InstrCtx,
    ) {
        let location = ctx.state.loc();
        for (index, (&ret, &ty)) in returns.iter().zip(tys.iter()).enumerate() {
            let key = CallArgument {
                index,
                location,
                is_return: true,
            };
            if self.coverage.has_key(&key) {
                self.coverage
                    .instrument_range(&key, ret, ty, &mut ctx, self);
            }
        }
    }
}

pub(crate) struct CallParamsSetPass {
    coverage: AssociatedCoverageArray<CallArgument, ValueSet<8>>,
}

impl CallParamsSetPass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for CallParamsSetPass {
    type Key = CallArgument;
    type Value = ValueSet<8>;

    fn shortcode(&self) -> &'static str {
        "call-params-set"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }

    fn coverage_mut(&mut self) -> &mut AssociatedCoverageArray<Self::Key, Self::Value> {
        &mut self.coverage
    }

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        CallParamsRangePass::generate_keys(spec)
    }

    fn instrument_call(
        &self,
        _target: Option<FuncIdx>,
        params: &[Value],
        tys: &[Type],
        mut ctx: InstrCtx,
    ) {
        let location = ctx.state.loc();
        for (index, (&param, &ty)) in params.iter().zip(tys.iter()).enumerate() {
            let key = CallArgument {
                index,
                location,
                is_return: false,
            };
            if self.coverage.has_key(&key) {
                self.coverage
                    .instrument_set(&key, param, ty, &mut ctx, self);
            }
        }
    }
    fn instrument_call_return(
        &self,
        _target: Option<FuncIdx>,
        returns: &[Value],
        tys: &[Type],
        mut ctx: InstrCtx,
    ) {
        let location = ctx.state.loc();
        for (index, (&ret, &ty)) in returns.iter().zip(tys.iter()).enumerate() {
            let key = CallArgument {
                index,
                location,
                is_return: true,
            };
            if self.coverage.has_key(&key) {
                self.coverage.instrument_set(&key, ret, ty, &mut ctx, self);
            }
        }
    }
}

pub(crate) struct GlobalsRangePass {
    coverage: AssociatedCoverageArray<Location, ValueRange>,
}

impl GlobalsRangePass {
    pub(crate) fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: AssociatedCoverageArray::new(&Self::generate_keys(spec).collect::<Vec<_>>()),
        }
    }
}

impl KVInstrumentationPass for GlobalsRangePass {
    type Key = Location;
    type Value = ValueRange;

    fn shortcode(&self) -> &'static str {
        "globals-range"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }

    fn coverage_mut(&mut self) -> &mut AssociatedCoverageArray<Self::Key, Self::Value> {
        &mut self.coverage
    }

    fn generate_keys(spec: &ModuleSpec) -> impl Iterator<Item = Self::Key> {
        use crate::ir::{VariableInstruction, WFOperator};
        spec.functions.iter().flat_map(|f| {
            f.operators
                .iter()
                .enumerate()
                .filter_map(|(idx, op)| match op {
                    WFOperator::Variable(VariableInstruction::GlobalSet(_index)) => {
                        let loc = Location {
                            function: f.idx,
                            index: idx as u32,
                        };
                        Some(loc)
                    }
                    _ => None,
                })
        })
    }

    fn instrument_global_set(&self, _index: u32, value: Value, ty: Type, mut ctx: InstrCtx) {
        self.coverage
            .instrument_range(&ctx.state.loc(), value, ty, &mut ctx, self);
    }
}
