use crate::{ir::ModuleSpec, HashMap, HashSet};
use std::sync::Arc;

use crate::concolic::MemoryAccessKind;

use super::smtlib_helpers::BitVecExt;
use super::{BinaryOp, ConcolicEvent, SolverBackendError, SymVal, SymValRef, Symvals, UnaryOp};

use smtlib::Logic;
use smtlib::{
    prelude::*,
    terms::{Const, Dynamic},
    BitVec, Bool, SatResult,
};

#[derive(Clone, Debug)]
enum Value<'ctx> {
    Bool(Bool<'ctx>),
    BV8(BitVec<'ctx, 8>),
    BV32(BitVec<'ctx, 32>),
    BV64(BitVec<'ctx, 64>),
}
impl<'ctx> Value<'ctx> {
    fn as_bv32(&self) -> BitVec<'ctx, 32> {
        match self {
            Value::BV32(bv) => *bv,
            _ => panic!("expected BV32, got {self:?}"),
        }
    }

    fn into_dynamic(&self) -> Dynamic<'ctx> {
        match self {
            Value::Bool(b) => b.into_dynamic(),
            Value::BV8(bv) => bv.into_dynamic(),
            Value::BV32(bv) => bv.into_dynamic(),
            Value::BV64(bv) => bv.into_dynamic(),
        }
    }
}

impl<'ctx> From<Value<'ctx>> for Dynamic<'ctx> {
    fn from(val: Value<'ctx>) -> Self {
        val.into_dynamic()
    }
}

impl<'ctx> From<Dynamic<'ctx>> for Value<'ctx> {
    fn from(val: Dynamic<'ctx>) -> Self {
        if Bool::is_sort(val.sort()) {
            Value::Bool(Bool::from_dynamic(val))
        } else if BitVec::<8>::is_sort(val.sort()) {
            Value::BV8(BitVec::<8>::from_dynamic(val))
        } else if BitVec::<32>::is_sort(val.sort()) {
            Value::BV32(BitVec::<32>::from_dynamic(val))
        } else if BitVec::<64>::is_sort(val.sort()) {
            Value::BV64(BitVec::<64>::from_dynamic(val))
        } else {
            unreachable!()
        }
    }
}

impl<'ctx> From<Bool<'ctx>> for Value<'ctx> {
    fn from(val: Bool<'ctx>) -> Self {
        Value::Bool(val)
    }
}

impl<'ctx> From<BitVec<'ctx, 8>> for Value<'ctx> {
    fn from(val: BitVec<'ctx, 8>) -> Self {
        Value::BV8(val)
    }
}

impl<'ctx> From<BitVec<'ctx, 32>> for Value<'ctx> {
    fn from(val: BitVec<'ctx, 32>) -> Self {
        Value::BV32(val)
    }
}

impl<'ctx> From<BitVec<'ctx, 64>> for Value<'ctx> {
    fn from(val: BitVec<'ctx, 64>) -> Self {
        Value::BV64(val)
    }
}

pub(crate) struct SolverInstance<'ctx> {
    storage: &'ctx smtlib::Storage,
    solver: smtlib::Solver<'ctx, Box<dyn smtlib::backend::Backend>>,
    vals: HashMap<SymValRef, Value<'ctx>>,
    vals_err: HashMap<SymValRef, SolverBackendError>,
    seen: HashSet<SymValRef>,
    inp_vals: HashMap<u16, Const<'ctx, BitVec<'ctx, 8>>>,
    spec: Option<Arc<ModuleSpec>>,
    prop_counter: usize,
}

struct Logger;
impl smtlib::Logger for Logger {
    fn exec(&self, cmd: smtlib::lowlevel::ast::Command) {
        eprintln!("{cmd}");
    }

    fn response(&self, cmd: smtlib::lowlevel::ast::Command, res: &str) {
        eprintln!("{cmd}: {res}");
    }
}

impl<'ctx> SolverInstance<'ctx> {
    pub(crate) fn new(
        spec: Option<Arc<ModuleSpec>>,
        storage: &'ctx smtlib::Storage,
        mut solver: smtlib::Solver<'ctx, Box<dyn smtlib::backend::Backend>>,
    ) -> Self {
        let debug = std::env::var("CONCOLICDEBUG").as_deref().unwrap_or("0") == "1";
        if debug {
            solver.set_logger(Logger);
        }
        // solver.set_logic(Logic::QF_ABV).unwrap();
        solver.set_logic(Logic::QF_BV).unwrap();
        if let Err(err) = solver.set_timeout(1500) {
            eprintln!("[WARN] failed to set solver timeout: {err:?}");
        }
        SolverInstance {
            storage,
            solver,
            vals: HashMap::default(),
            vals_err: HashMap::default(),
            seen: HashSet::default(),
            inp_vals: HashMap::default(),
            spec,
            prop_counter: 0,
        }
    }

    fn get_inp_bv(&mut self, i: u16) -> Const<'ctx, BitVec<'ctx, 8>> {
        *self.inp_vals
            .entry(i)
            .or_insert_with(|| {
                let symbol = format!("inp-{i}");
                BitVec::new_const(self.storage, &symbol)
            })
    }

    fn new_prop(&mut self) -> Const<'ctx, Bool<'ctx>> {
        let name = self
            .storage
            .alloc_str(&format!("prop-{}", self.prop_counter));
        self.prop_counter += 1;
        Bool::new_const(self.storage, name)
    }

    fn get_symval(
        &mut self,
        symref: SymValRef,
        context: &Symvals,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        if let Some(el) = self.vals.get(&symref) {
            return Ok(el.clone());
        }
        if let Some(err) = self.vals_err.get(&symref) {
            return Err(err.clone());
        }
        // let sym = context.fetch(symref);
        // eprintln!("get_symval new {:?} ({:?})", symref, &sym);
        if cfg!(feature = "concolic_debug_verify") && !self.seen.insert(symref) {
            // dbg!(symref, context.fetch(symref));
            panic!("cyclic symvalref: {symref:?}");
        }
        let res = self.get_symval_(symref, context);
        match &res {
            Ok(res) => {
                self.vals.insert(symref, res.clone());
            }
            Err(res) => {
                self.vals_err.insert(symref, res.clone());
            }
        }
        res
    }

    fn get_symval_(
        &mut self,
        symref: SymValRef,
        context: &Symvals,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        let sym = context.fetch(symref);
        Ok(match sym {
            SymVal::Concrete => unreachable!(),
            SymVal::Load { .. } => todo!(),
            SymVal::InputByte(index) => Value::BV8(self.get_inp_bv(index).into()),
            SymVal::ConstI8(v) => BitVec::<8>::new(self.storage, v as i64).into(),
            SymVal::ConstI32(v) => BitVec::<32>::new(self.storage, v as i64).into(),
            SymVal::ConstI64(v) => BitVec::<64>::new(self.storage, v as i64).into(),
            SymVal::ConstF32(_) | SymVal::ConstF64(_) => {
                return Err(SolverBackendError::UnsupportedFloatingpointOperation)
            }
            SymVal::Unary(op, bv) => {
                let val = self.get_symval(bv, context)?;
                self.build_unary(op, val)?
            }
            SymVal::Binary(op, a, b) => {
                let a = self.get_symval(a, context)?;
                let b = self.get_symval(b, context)?;
                self.build_binary(op, a, b)?
            }
            SymVal::Select { condition, a, b } => {
                let cond = self.get_symval(condition, context)?;
                let a = self.get_symval(a, context)?;
                let b = self.get_symval(b, context)?;
                let cond = match cond {
                    Value::Bool(v) => v,
                    Value::BV8(v) => v._neq(0),
                    Value::BV32(v) => v._neq(0),
                    Value::BV64(v) => v._neq(0),
                };
                cond.ite(a.into_dynamic(), b.into_dynamic()).into()
            }
            SymVal::ExtractByte {
                kind: _,
                val,
                byte_index,
            } => {
                let val = self.get_symval(val, context)?;
                let (i, j) = (byte_index * 8 + 7, byte_index * 8);
                let val: BitVec<'ctx, 8> = match val {
                    Value::BV32(bv) => bv.extract_(i, j),
                    Value::BV64(bv) => bv.extract_(i, j),
                    _ => unreachable!(),
                };
                val.into()
            }
            SymVal::CombineBytes { kind, vals } => {
                assert_eq!(vals.len(), kind.access_width_bytes());
                let bytes = vals
                    .iter()
                    .map(|v| {
                        self.get_symval(*v, context).map(|v| match v {
                            Value::BV8(v) => v,
                            _ => unreachable!(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                fn combine_16<'ctx>(bytes: &[BitVec<'ctx, 8>]) -> BitVec<'ctx, 16> {
                    bytes[1].concat_::<8, 16>(bytes[0])
                }

                fn combine_32<'ctx>(bytes: &[BitVec<'ctx, 8>]) -> BitVec<'ctx, 32> {
                    combine_16(&bytes[2..]).concat_::<16, 32>(combine_16(&bytes[0..2]))
                }

                fn combine_64<'ctx>(bytes: &[BitVec<'ctx, 8>]) -> BitVec<'ctx, 64> {
                    combine_32(&bytes[4..]).concat_::<32, 64>(combine_32(&bytes[0..4]))
                }

                match kind {
                    MemoryAccessKind::I32 => combine_32(&bytes).into(),
                    MemoryAccessKind::I32AsS8 => bytes[0].sext::<24, 32>().into(),
                    MemoryAccessKind::I32AsU8 => bytes[0].uext::<24, 32>().into(),
                    MemoryAccessKind::I32AsS16 => combine_16(&bytes).sext::<16, 32>().into(),
                    MemoryAccessKind::I32AsU16 => combine_16(&bytes).uext::<16, 32>().into(),
                    MemoryAccessKind::I64 => combine_64(&bytes).into(),
                    MemoryAccessKind::I64AsS8 => bytes[0].sext::<56, 64>().into(),
                    MemoryAccessKind::I64AsU8 => bytes[0].uext::<56, 64>().into(),
                    MemoryAccessKind::I64AsS16 => combine_16(&bytes).sext::<16, 64>().into(),
                    MemoryAccessKind::I64AsU16 => combine_16(&bytes).uext::<16, 64>().into(),
                    MemoryAccessKind::I64AsS32 => combine_32(&bytes).sext::<32, 64>().into(),
                    MemoryAccessKind::I64AsU32 => combine_32(&bytes).uext::<32, 64>().into(),
                    MemoryAccessKind::F32 | MemoryAccessKind::F64 => {
                        return Err(SolverBackendError::UnsupportedFloatingpointOperation)
                    }
                }
                // zero-width bvs are not allowed :(
                // let mut res: Option<BitVec<'ctx, 8>> = None;
                // for byte in vals {
                //     let byte = self.get_symval(byte, context)?.bv();
                //     res = Some(match res {
                //         Some(res) => byte.concat(&res),
                //         None => byte,
                //     });
                // }
                // let res = res.unwrap();
                // if matches!(kind, MemoryAccessKind::F32) {
                //     res.to_fp32().into()
                // } else if matches!(kind, MemoryAccessKind::F64) {
                //     res.to_fp64().into()
                // } else if kind.value_width_bytes() != kind.access_width_bytes() {
                //     let extend_by =
                //         (kind.value_width_bytes() * 8 - kind.access_width_bytes() * 8) as u64;
                //     if kind.sign_extend() {
                //         res.sext(extend_by).into()
                //     } else {
                //         res.uext(extend_by).into()
                //     }
                // } else {
                //     assert_eq!(res.get_width(), kind.value_width_bytes() as u64 * 8);
                //     res.into()
                // }
            }
        })
    }

    fn build_unary(
        &self,
        op: UnaryOp,
        val: Value<'ctx>,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        match op {
            UnaryOp::Clz
            | UnaryOp::Ctz
            | UnaryOp::Popcnt
            | UnaryOp::Eqz
            | UnaryOp::I32Extend8S
            | UnaryOp::I32Extend16S
            | UnaryOp::I32WrapI64
            | UnaryOp::I64Extend8S
            | UnaryOp::I64Extend16S
            | UnaryOp::I64Extend32S
            | UnaryOp::I64ExtendI32S
            | UnaryOp::I64ExtendI32U => self.build_unary_bv(op, val),
            UnaryOp::I32TruncF32S
            | UnaryOp::I32TruncF32U
            | UnaryOp::I32TruncF64S
            | UnaryOp::I32TruncF64U
            | UnaryOp::I64TruncF32S
            | UnaryOp::I64TruncF32U
            | UnaryOp::I64TruncF64S
            | UnaryOp::I64TruncF64U
            | UnaryOp::I32TruncSatF32S
            | UnaryOp::I32TruncSatF32U
            | UnaryOp::I32TruncSatF64S
            | UnaryOp::I32TruncSatF64U
            | UnaryOp::I64TruncSatF32S
            | UnaryOp::I64TruncSatF32U
            | UnaryOp::I64TruncSatF64S
            | UnaryOp::I64TruncSatF64U
            | UnaryOp::F32DemoteF64
            | UnaryOp::F64PromoteF32
            | UnaryOp::F32ConvertI32S
            | UnaryOp::F32ConvertI32U
            | UnaryOp::F32ConvertI64S
            | UnaryOp::F32ConvertI64U
            | UnaryOp::F64ConvertI32S
            | UnaryOp::F64ConvertI32U
            | UnaryOp::F64ConvertI64S
            | UnaryOp::F64ConvertI64U
            | UnaryOp::I32ReinterpretF32
            | UnaryOp::I64ReinterpretF64
            | UnaryOp::F32ReinterpretI32
            | UnaryOp::F64ReinterpretI64
            | UnaryOp::FAbs
            | UnaryOp::FNeg
            | UnaryOp::FSqrt
            | UnaryOp::FCeil
            | UnaryOp::FFloor
            | UnaryOp::FTrunc
            | UnaryOp::FNearest => self.build_unary_fp(op, val),
        }
    }

    fn build_unary_bv(
        &self,
        op: UnaryOp,
        val: Value<'ctx>,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        Ok(match (&op, &val) {
            (UnaryOp::Clz, Value::BV32(val)) => val.clz().into(),
            (UnaryOp::Clz, Value::BV64(val)) => val.clz().into(),
            (UnaryOp::Ctz, Value::BV32(val)) => val.ctz().into(),
            (UnaryOp::Ctz, Value::BV64(val)) => val.ctz().into(),
            (UnaryOp::Popcnt, Value::BV32(val)) => val.popcnt().into(),
            (UnaryOp::Popcnt, Value::BV64(val)) => val.popcnt().into(),
            (UnaryOp::Eqz, Value::BV32(val)) => BitVec::<32>::from_bool(val._eq(0)).into(),
            (UnaryOp::Eqz, Value::BV64(val)) => BitVec::<64>::from_bool(val._eq(0)).into(),
            (UnaryOp::I32Extend8S, Value::BV32(val)) => {
                val.extract_::<8>(7, 0).sext::<24, 32>().into()
            }
            (UnaryOp::I32Extend16S, Value::BV32(val)) => {
                val.extract_::<16>(15, 0).sext::<16, 32>().into()
            }
            (UnaryOp::I32WrapI64, Value::BV64(val)) => val.extract_::<32>(31, 0).into(),
            (UnaryOp::I64Extend8S, Value::BV64(val)) => {
                val.extract_::<8>(7, 0).sext::<56, 64>().into()
            }
            (UnaryOp::I64Extend16S, Value::BV64(val)) => {
                val.extract_::<16>(15, 0).sext::<48, 64>().into()
            }
            (UnaryOp::I64Extend32S, Value::BV64(val)) => {
                val.extract_::<32>(31, 0).sext::<32, 64>().into()
            }
            (UnaryOp::I64ExtendI32S, Value::BV32(val)) => val.sext::<32, 64>().into(),
            (UnaryOp::I64ExtendI32U, Value::BV32(val)) => val.uext::<32, 64>().into(),
            _ => unreachable!("unsupported unary op: {:?} bv: {:?}", op, val),
        })
    }

    fn build_unary_fp(
        &self,
        _op: UnaryOp,
        _val: Value<'ctx>,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        Err(SolverBackendError::UnsupportedFloatingpointOperation)
    }

    fn build_binary(
        &self,
        op: BinaryOp,
        a: Value<'ctx>,
        b: Value<'ctx>,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        match op {
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::DivS
            | BinaryOp::DivU
            | BinaryOp::RemS
            | BinaryOp::RemU
            | BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Xor
            | BinaryOp::Shl
            | BinaryOp::ShrS
            | BinaryOp::ShrU
            | BinaryOp::Rotl
            | BinaryOp::Rotr => match (a, b) {
                (Value::BV32(a), Value::BV32(b)) => self.build_binary_bv(op, a, b).map(Into::into),
                (Value::BV64(a), Value::BV64(b)) => self.build_binary_bv(op, a, b).map(Into::into),
                _ => unreachable!(),
            },
            BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::LtU
            | BinaryOp::LtS
            | BinaryOp::GtU
            | BinaryOp::GtS
            | BinaryOp::LeU
            | BinaryOp::LeS
            | BinaryOp::GeU
            | BinaryOp::GeS => match (a, b) {
                (Value::BV32(a), Value::BV32(b)) => {
                    self.build_binary_bv_eq(op, a, b).map(Into::into)
                }
                (Value::BV64(a), Value::BV64(b)) => {
                    self.build_binary_bv_eq(op, a, b).map(Into::into)
                }
                _ => unreachable!(),
            },
            BinaryOp::FEq
            | BinaryOp::FNe
            | BinaryOp::FLt
            | BinaryOp::FGt
            | BinaryOp::FLe
            | BinaryOp::FGe
            | BinaryOp::FAdd
            | BinaryOp::FSub
            | BinaryOp::FMul
            | BinaryOp::FDiv
            | BinaryOp::FMin
            | BinaryOp::FMax
            | BinaryOp::FCopysign => self.build_binary_fp(op, a, b),
        }
    }

    fn build_binary_bv<const N: usize>(
        &self,
        op: BinaryOp,
        a: BitVec<'ctx, N>,
        b: BitVec<'ctx, N>,
    ) -> Result<BitVec<'ctx, N>, SolverBackendError> {
        let shift_amount = || b.bvand(BitVec::<N>::new(self.storage, N as i64 - 1));
        Ok(match op {
            BinaryOp::Add => a.bvadd(b),
            BinaryOp::Sub => a.bvadd(b.bvneg()),
            BinaryOp::Mul => a.bvmul(b),
            BinaryOp::DivS => a.bvsdiv(b),
            BinaryOp::DivU => a.bvudiv(b),
            BinaryOp::RemS => a.bvsrem(b),
            BinaryOp::RemU => a.bvurem(b),
            BinaryOp::And => a.bvand(b),
            BinaryOp::Or => a.bvor(b),
            BinaryOp::Xor => a.bvxor(b),
            BinaryOp::Shl => a.bvshl(shift_amount()),
            BinaryOp::ShrS => a.bvashr(shift_amount()),
            BinaryOp::ShrU => a.bvlshr(shift_amount()),
            BinaryOp::Rotl => a.rol(shift_amount()),
            BinaryOp::Rotr => a.ror(shift_amount()),
            _ => unreachable!(),
        })
    }

    fn build_binary_bv_eq<const N: usize>(
        &self,
        op: BinaryOp,
        a: BitVec<'ctx, N>,
        b: BitVec<'ctx, N>,
    ) -> Result<BitVec<'ctx, 32>, SolverBackendError> {
        Ok(match op {
            BinaryOp::Eq => BitVec::<32>::from_bool(a._eq(b)),
            BinaryOp::Ne => BitVec::<32>::from_bool(a._neq(b)),
            BinaryOp::LtU => BitVec::<32>::from_bool(a.bvult(b)),
            BinaryOp::LtS => BitVec::<32>::from_bool(a.bvslt(b)),
            BinaryOp::GtU => BitVec::<32>::from_bool(a.bvugt(b)),
            BinaryOp::GtS => BitVec::<32>::from_bool(a.bvsgt(b)),
            BinaryOp::LeU => BitVec::<32>::from_bool(a.bvule(b)),
            BinaryOp::LeS => BitVec::<32>::from_bool(a.bvsle(b)),
            BinaryOp::GeU => BitVec::<32>::from_bool(a.bvuge(b)),
            BinaryOp::GeS => BitVec::<32>::from_bool(a.bvsge(b)),
            _ => unreachable!(),
        })
    }

    fn build_binary_fp(
        &self,
        _op: BinaryOp,
        _a: Value<'ctx>,
        _b: Value<'ctx>,
    ) -> Result<Value<'ctx>, SolverBackendError> {
        Err(SolverBackendError::UnsupportedFloatingpointOperation)
    }

    fn event_as_constraint(
        &mut self,
        event: &ConcolicEvent,
        context: &Symvals,
    ) -> Result<Bool<'ctx>, SolverBackendError> {
        Ok(match event {
            ConcolicEvent::PathConstraint {
                condition, taken, ..
            } => {
                let cond = self.get_symval(*condition, context)?;
                match (cond, *taken) {
                    (Value::BV32(cond), true) => cond._neq(0),
                    (Value::BV32(cond), false) => cond._eq(0),
                    (Value::BV64(cond), true) => cond._neq(0),
                    (Value::BV64(cond), false) => cond._eq(0),
                    _ => unreachable!(),
                }
            }
            ConcolicEvent::MemoryConstraint { address, sym, .. } => self
                .get_symval(*sym, context)?
                .as_bv32()
                ._eq(*address as i64),
            ConcolicEvent::TryAlternative { .. } => todo!(),
            ConcolicEvent::TrySolveMemcmp { pairs, .. } => {
                let _true = Bool::new(self.storage, true);
                pairs
                    .iter()
                    .map(|(a, b)| {
                        let a: Dynamic<'_> = self.get_symval(*a, context)?.into();
                        let b: Dynamic<'_> = self.get_symval(*b, context)?.into();
                        Ok(a._eq(b))
                    })
                    .try_fold(_true, |a, b| Ok(a & b?))?
            }
            ConcolicEvent::TrySolveStrcmplike {
                symvals,
                reference,
                ignorecase,
                ..
            } => {
                let _true = Bool::new(self.storage, true);
                let symvals = symvals
                    .iter()
                    .map(|v| {
                        self.get_symval(*v, context).map(|v| match v {
                            Value::BV8(v) => v,
                            _ => unreachable!(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                symvals
                    .iter()
                    .zip(reference)
                    .try_fold(_true, |acc, (sym, &ref_)| {
                        let res = if *ignorecase
                            && (ref_.is_ascii_lowercase() || ref_.is_ascii_uppercase())
                        {
                            sym._eq(ref_ as i64) | sym._eq((ref_ ^ 0x20) as i64)
                        } else {
                            sym._eq(ref_ as i64)
                        };
                        Ok(acc & res)
                    })?
            }
        })
    }

    pub(crate) fn try_negate(
        &mut self,
        event: &ConcolicEvent,
        context: &Symvals,
    ) -> Result<bool, SolverBackendError> {
        let start = std::time::Instant::now();
        let prop = self.new_prop();
        let constraint = self.event_as_constraint(event, context)?;
        // TODO(refactor): move to event_as_constraint?
        let constraint = match event {
            ConcolicEvent::TryAlternative { .. }
            | ConcolicEvent::TrySolveMemcmp { .. }
            | ConcolicEvent::TrySolveStrcmplike { .. } => !constraint,
            _ => constraint,
        };
        println!("solving for negated condition   ...");
        self.solver.assert(prop.implies(!constraint)).unwrap();
        let res = self
            .solver
            .check_sat_assuming(self.storage.alloc_slice(&[(prop, true)]))
            .map_err(|_| SolverBackendError::UnspecifiedError)?;
        println!(
            "solving for negated condition   ... done: {:?} ({:?})",
            res,
            start.elapsed()
        );
        if start.elapsed().as_secs_f32() > 1.0 {
            if let Some(spec) = self.spec.as_ref() {
                println!("slow solve @ {:?}", spec.format_location(event.location()));
            }
            println!("{event:?}");
        }
        Ok(res == SatResult::Sat)
    }

    pub(crate) fn apply_model(&mut self, input: &mut [u8]) {
        let model = self.solver.get_model().unwrap();
        for (i, bv) in &self.inp_vals {
            if let Some(solution) = model.eval(*bv) {
                let solution: i64 = solution.try_into().unwrap();
                input[*i as usize] = solution as u8;
                eprintln!("apply_model[{}] = {:#x}", *i as usize, input[*i as usize]);
            } else {
                eprintln!("apply_model[{}] = unknown", *i as usize);
            }
        }
    }

    pub(crate) fn provide_hint(&mut self, input: &[u8], mask: &bitvec::slice::BitSlice) {
        let prop = self.new_prop();
        for i in mask.iter_ones() {
            let hint = input[i];
            let bv = self.get_inp_bv(i as u16);
            self.solver
                .assert(prop.implies(bv._eq(hint as i64)))
                .unwrap();
        }
        self.solver
            .check_sat_assuming(self.storage.alloc_slice(&[(prop, true)]))
            .unwrap();
    }

    pub(crate) fn assert(
        &mut self,
        event: &ConcolicEvent,
        input: &[u8],
        context: &Symvals,
        try_solve: bool,
    ) -> Result<(), SolverBackendError> {
        match event {
            ConcolicEvent::TryAlternative { .. }
            | ConcolicEvent::TrySolveMemcmp { .. }
            | ConcolicEvent::TrySolveStrcmplike { .. } => return Ok(()),
            _ => {}
        }
        let hint_prop = self.new_prop();

        let start = std::time::Instant::now();
        let constraint = self.event_as_constraint(event, context)?;
        self.solver.assert(constraint).unwrap();

        let mut res = SatResult::Unknown;

        if try_solve {
            println!("solving with asserted condition ...");
            res = self
                .solver
                .check_sat()
                .map_err(|_| SolverBackendError::UnspecifiedError)?;
            println!(
                "solving with asserted condition ... done: {:?} ({:?})",
                res,
                start.elapsed()
            );
            if start.elapsed().as_secs_f32() > 0.5 {
                println!("\n^ slow!");
            }
        } else if cfg!(not(feature = "concolic_debug_verify")) {
            return Ok(());
        }

        if res == SatResult::Unknown {
            // help the solver out with the original assignment as assumptions
            for (i, bv) in &self.inp_vals {
                let hint = input[*i as usize];
                self.solver
                    .assert(hint_prop.implies(bv._eq(hint as i64)))
                    .unwrap();
            }
            if try_solve {
                println!("solving with assert and hints   ...");
            }
            res = self
                .solver
                .check_sat_assuming(self.storage.alloc_slice(&[(hint_prop, true)]))
                .map_err(|_| SolverBackendError::UnspecifiedError)?;
            if try_solve {
                println!(
                    "solving with assert and hints   ... done: {:?} ({:?})",
                    res,
                    start.elapsed()
                );
            }
        }

        if res != SatResult::Sat {
            println!();
            println!("{event:?}");
            std::fs::write("/tmp/inp.bin", input).unwrap();
        }
        assert_eq!(res, SatResult::Sat);

        Ok(())
    }

    pub(crate) fn eval_as_u64_with_input(
        &mut self,
        val: SymValRef,
        input: &[u8],
        context: &Symvals,
    ) -> Result<Option<u64>, SolverBackendError> {
        let prop = self.new_prop();
        let tmp_const_name = self
            .storage
            .alloc_str(&format!("tmp_const_{}", self.prop_counter));
        let tmp_const = BitVec::new_const(self.storage, tmp_const_name);
        let bv = self.get_symval(val, context)?;
        self.solver
            .assert(tmp_const._eq(match bv {
                // Value::Bool(bool) => todo!(),
                // Value::BV8(bit_vec) => todo!(),
                Value::BV32(v) => v.uext::<32, 64>(),
                Value::BV64(v) => v,
                _ => todo!(),
            }))
            .unwrap();

        for (i, bv) in &self.inp_vals {
            let hint = input[*i as usize];
            self.solver
                .assert(prop.implies(bv._eq(hint as i64)))
                .unwrap();
        }
        let res = self
            .solver
            .check_sat()
            .map_err(|_| SolverBackendError::UnspecifiedError)?;
        assert_eq!(res, SatResult::Sat);

        let res = self
            .solver
            .check_sat_assuming(self.storage.alloc_slice(&[(prop, true)]))
            .unwrap();
        assert_eq!(res, SatResult::Sat);

        let model = self.solver.get_model().unwrap();
        let res: Option<i64> = model.eval(tmp_const).map(|v| v.try_into().unwrap());
        Ok(res.map(|v| v as u64))
    }
}
