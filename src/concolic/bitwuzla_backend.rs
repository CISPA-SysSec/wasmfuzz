// TODO(concolic): concretization policies in style of https://github.com/trailofbits/manticore/blob/master/manticore/core/state.py#L387

use crate::{HashMap, HashSet, ir::ModuleSpec};
use std::{rc::Rc, sync::Arc, time::Duration};

use bitvec::slice::BitSlice;
use bitwuzla::{BV, Bool, Btor, FP, RoundingMode, SolverResult};

use crate::concolic::MemoryAccessKind;

use super::{BinaryOp, ConcolicEvent, SolverBackendError, SymVal, SymValRef, Symvals, UnaryOp};

type BV_ = BV<Rc<Btor>>;
type Bool_ = Bool<Rc<Btor>>;
type FP_ = FP<Rc<Btor>>;

#[derive(Debug, Clone)]
enum BitwuzlaVal {
    BV(BV<Rc<Btor>>),
    FP(FP<Rc<Btor>>),
}

impl BitwuzlaVal {
    fn is_bv(&self) -> bool {
        matches!(self, BitwuzlaVal::BV(_))
    }

    fn bv(self) -> BV<Rc<Btor>> {
        match self {
            BitwuzlaVal::BV(v) => v,
            BitwuzlaVal::FP(_) => unreachable!(),
        }
    }

    fn fp(self) -> FP<Rc<Btor>> {
        match self {
            BitwuzlaVal::BV(_) => unreachable!(),
            BitwuzlaVal::FP(v) => v,
        }
    }
}

impl From<BV<Rc<Btor>>> for BitwuzlaVal {
    fn from(v: BV<Rc<Btor>>) -> Self {
        Self::BV(v)
    }
}

impl From<FP<Rc<Btor>>> for BitwuzlaVal {
    fn from(v: FP<Rc<Btor>>) -> Self {
        Self::FP(v)
    }
}

pub(crate) struct SolverInstance {
    btor: Rc<Btor>,
    vals: HashMap<SymValRef, BitwuzlaVal>,
    vals_err: HashMap<SymValRef, SolverBackendError>,
    seen: HashSet<SymValRef>,
    inp_vals: HashMap<u16, BV_>,
    spec: Option<Arc<ModuleSpec>>,
}

impl SolverInstance {
    pub(crate) fn new(spec: Option<Arc<ModuleSpec>>) -> Self {
        // TODO: solver instance for specific trace
        let btor = Btor::builder()
            .with_model_gen()
            .solver_timeout(Some(Duration::from_secs(2)))
            .build();
        let btor = Rc::new(btor);
        SolverInstance {
            btor,
            vals: HashMap::default(),
            vals_err: HashMap::default(),
            seen: HashSet::default(),
            inp_vals: HashMap::default(),
            spec,
        }
    }

    fn get_inp_bv(&mut self, i: u16) -> BV_ {
        self.inp_vals
            .entry(i)
            .or_insert_with(|| {
                let symbol = format!("inp-{}", i);
                BV::new(self.btor.clone(), 8, Some(&symbol))
            })
            .clone()
    }

    fn get_symval(
        &mut self,
        symref: SymValRef,
        context: &Symvals,
    ) -> Result<BitwuzlaVal, SolverBackendError> {
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
            panic!("cyclic symvalref: {:?}", symref);
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
    ) -> Result<BitwuzlaVal, SolverBackendError> {
        let sym = context.fetch(symref);
        Ok(match sym {
            SymVal::Concrete => unreachable!(),
            SymVal::Load { .. } => todo!(),
            SymVal::InputByte(index) => self.get_inp_bv(index).into(),
            SymVal::ConstI8(v) => BV::from_u32(self.btor.clone(), v as u32, 8).into(),
            SymVal::ConstI32(v) => BV::from_u32(self.btor.clone(), v, 32).into(),
            SymVal::ConstI64(v) => BV::from_u64(self.btor.clone(), v, 64).into(),
            SymVal::ConstF32(v) => FP::from_f32(self.btor.clone(), *v).into(),
            SymVal::ConstF64(v) => FP::from_f64(self.btor.clone(), *v).into(),
            SymVal::Unary(op, bv) => {
                let bv = self.get_symval(bv, context)?;
                self.build_unary(op, bv)?
            }
            SymVal::Binary(op, a, b) => {
                let a = self.get_symval(a, context)?;
                let b = self.get_symval(b, context)?;
                self.build_binary(op, a, b)?
            }
            SymVal::Select { condition, a, b } => {
                let cond = self.get_symval(condition, context)?.bv();
                let a = self.get_symval(a, context)?;
                let b = self.get_symval(b, context)?;
                let zero = BV::from_u32(self.btor.clone(), 0, 32);
                let cond = cond._ne(&zero);
                if a.is_bv() {
                    cond.cond_bv(&a.bv(), &b.bv()).into()
                } else {
                    cond.cond_fp(&a.fp(), &b.fp()).into()
                }
            }
            SymVal::ExtractByte {
                kind: _,
                val,
                byte_index,
            } => {
                let byte_index = byte_index as u64;
                let val = self.get_symval(val, context)?;
                val.bv().slice(byte_index * 8 + 7, byte_index * 8).into()
            }
            SymVal::CombineBytes { kind, vals } => {
                assert_eq!(vals.len(), kind.access_width_bytes());
                // zero-width bvs are not allowed :(
                let mut res: Option<BV_> = None;
                for byte in vals {
                    let byte = self.get_symval(byte, context)?.bv();
                    res = Some(match res {
                        Some(res) => byte.concat(&res),
                        None => byte,
                    });
                }
                let res = res.unwrap();
                if matches!(kind, MemoryAccessKind::F32) {
                    res.to_fp32().into()
                } else if matches!(kind, MemoryAccessKind::F64) {
                    res.to_fp64().into()
                } else if kind.value_width_bytes() != kind.access_width_bytes() {
                    let extend_by =
                        (kind.value_width_bytes() * 8 - kind.access_width_bytes() * 8) as u64;
                    if kind.sign_extend() {
                        res.sext(extend_by).into()
                    } else {
                        res.uext(extend_by).into()
                    }
                } else {
                    assert_eq!(res.get_width(), kind.value_width_bytes() as u64 * 8);
                    res.into()
                }
            }
        })
    }

    fn build_unary(
        &self,
        op: UnaryOp,
        val: BitwuzlaVal,
    ) -> Result<BitwuzlaVal, SolverBackendError> {
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
            | UnaryOp::I64ExtendI32U => self.build_unary_bv(op, val.bv()).map(Into::into),
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

    fn build_unary_bv(&self, op: UnaryOp, val: BV_) -> Result<BV_, SolverBackendError> {
        let width = val.get_width();
        Ok(match op {
            UnaryOp::Clz | UnaryOp::Ctz => {
                let zero = BV::zero(self.btor.clone(), width);
                let one = BV::one(self.btor.clone(), width);
                let mut cnt = BV::zero(self.btor.clone(), width);
                let mut seen = Bool::from_bool(self.btor.clone(), false);
                for i in 0..width {
                    let i = if matches!(op, UnaryOp::Clz) {
                        width - i - 1
                    } else {
                        i
                    };
                    seen = seen.or(&val.slice(i, i).to_bool());
                    cnt = cnt.add(&seen.cond_bv(&zero, &one));
                }
                cnt
            }
            UnaryOp::Popcnt => {
                let mut cnt = BV::from_u32(self.btor.clone(), 0, width);
                for i in 0..width {
                    let bit = val.slice(i, i);
                    cnt = cnt.add(&bit.uext(width - 1));
                }
                cnt
            }
            UnaryOp::Eqz => val._eq(&BV::from_u32(self.btor.clone(), 0, width)).uext(31),
            UnaryOp::I32Extend8S => val.slice(7, 0).sext(24),
            UnaryOp::I32Extend16S => val.slice(15, 0).sext(16),
            UnaryOp::I32WrapI64 => val.slice(31, 0),
            UnaryOp::I64Extend8S => val.slice(7, 0).sext(56),
            UnaryOp::I64Extend16S => val.slice(15, 0).sext(48),
            UnaryOp::I64Extend32S => val.slice(31, 0).sext(32),
            UnaryOp::I64ExtendI32S => val.sext(32),
            UnaryOp::I64ExtendI32U => val.uext(32),
            _ => unreachable!(),
        })
    }

    fn build_unary_fp(
        &self,
        op: UnaryOp,
        val: BitwuzlaVal,
    ) -> Result<BitwuzlaVal, SolverBackendError> {
        let fp_todo = Err(SolverBackendError::UnsupportedFloatingpointOperation);
        Ok(match op {
            // TODO: is this the proper encoding?
            UnaryOp::I32TruncF32S => val.fp().to_sbv(32).into(),
            UnaryOp::I32TruncF32U => val.fp().to_ubv(32).into(),
            UnaryOp::I32TruncF64S => val.fp().to_sbv(32).into(),
            UnaryOp::I32TruncF64U => val.fp().to_ubv(32).into(),
            UnaryOp::I64TruncF32S => val.fp().to_sbv(64).into(),
            UnaryOp::I64TruncF32U => val.fp().to_ubv(64).into(),
            UnaryOp::I64TruncF64S => val.fp().to_sbv(64).into(),
            UnaryOp::I64TruncF64U => val.fp().to_ubv(64).into(),
            // TODO: is this the proper encoding?
            UnaryOp::I32TruncSatF32S => val.fp().to_sbv(32).into(),
            UnaryOp::I32TruncSatF32U => val.fp().to_ubv(32).into(),
            UnaryOp::I32TruncSatF64S => val.fp().to_sbv(32).into(),
            UnaryOp::I32TruncSatF64U => val.fp().to_ubv(32).into(),
            UnaryOp::I64TruncSatF32S => val.fp().to_sbv(64).into(),
            UnaryOp::I64TruncSatF32U => val.fp().to_ubv(64).into(),
            UnaryOp::I64TruncSatF64S => val.fp().to_sbv(64).into(),
            UnaryOp::I64TruncSatF64U => val.fp().to_ubv(64).into(),
            UnaryOp::F32DemoteF64 => val.fp().to_fp64().into(),
            UnaryOp::F64PromoteF32 => val.fp().to_fp32().into(),
            // TODO: i32 to fp non-bitcast
            UnaryOp::F32ConvertI32S => return fp_todo, // val.bv().to_fp_from_sbv(32).into(),
            UnaryOp::F32ConvertI32U => return fp_todo, // val.bv().to_fp_from_ubv(32).into(),
            UnaryOp::F32ConvertI64S => return fp_todo, // val.bv().to_fp_from_sbv(64).into(),
            UnaryOp::F32ConvertI64U => return fp_todo, // val.bv().to_fp_from_ubv(64).into(),
            UnaryOp::F64ConvertI32S => return fp_todo, // val.bv().to_fp_from_sbv(32).into(),
            UnaryOp::F64ConvertI32U => return fp_todo, // val.bv().to_fp_from_ubv(32).into(),
            UnaryOp::F64ConvertI64S => return fp_todo, // val.bv().to_fp_from_sbv(64).into(),
            UnaryOp::F64ConvertI64U => return fp_todo, // val.bv().to_fp_from_ubv(64).into(),
            // TODO: fp to bv bitcast
            UnaryOp::I32ReinterpretF32 => return fp_todo,
            UnaryOp::I64ReinterpretF64 => return fp_todo,
            UnaryOp::F32ReinterpretI32 => val.bv().to_fp32().into(),
            UnaryOp::F64ReinterpretI64 => val.bv().to_fp64().into(),
            UnaryOp::FAbs => val.fp().abs().into(),
            UnaryOp::FNeg => val.fp().neg().into(),
            UnaryOp::FSqrt => val.fp().sqrt().into(),
            // TODO: smt-lib fp doesn't have ceil, floor, trunc?
            UnaryOp::FCeil => return fp_todo, // val.fp().ceil().into(),
            UnaryOp::FFloor => return fp_todo, // val.fp().floor().into(),
            UnaryOp::FTrunc => return fp_todo, // val.fp().trunc().into(),
            UnaryOp::FNearest => val.fp().round_to_integral(RoundingMode::RNE).into(),
            _ => unreachable!(),
        })
    }

    fn build_binary(
        &self,
        op: BinaryOp,
        a: BitwuzlaVal,
        b: BitwuzlaVal,
    ) -> Result<BitwuzlaVal, SolverBackendError> {
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
            | BinaryOp::Rotr
            | BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::LtU
            | BinaryOp::LtS
            | BinaryOp::GtU
            | BinaryOp::GtS
            | BinaryOp::LeU
            | BinaryOp::LeS
            | BinaryOp::GeU
            | BinaryOp::GeS => self.build_binary_bv(op, a.bv(), b.bv()).map(Into::into),
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
            | BinaryOp::FCopysign => self.build_binary_fp(op, a.fp(), b.fp()),
        }
    }

    fn build_binary_bv(&self, op: BinaryOp, a: BV_, b: BV_) -> Result<BV_, SolverBackendError> {
        assert_eq!(a.get_width(), b.get_width());
        let shift_amount = || {
            b.and(&BV::from_u64(
                self.btor.clone(),
                a.get_width() - 1,
                b.get_width(),
            ))
        };
        Ok(match op {
            BinaryOp::Add => a.add(&b),
            BinaryOp::Sub => a.sub(&b),
            BinaryOp::Mul => a.mul(&b),
            BinaryOp::DivS => a.sdiv(&b),
            BinaryOp::DivU => a.udiv(&b),
            BinaryOp::RemS => a.srem(&b),
            BinaryOp::RemU => a.urem(&b),
            BinaryOp::And => a.and(&b),
            BinaryOp::Or => a.or(&b),
            BinaryOp::Xor => a.xor(&b),
            BinaryOp::Shl => a.sll(&shift_amount()),
            BinaryOp::ShrS => a.sra(&shift_amount()),
            BinaryOp::ShrU => a.srl(&shift_amount()),
            BinaryOp::Rotl => a.rol(&shift_amount()),
            BinaryOp::Rotr => a.ror(&shift_amount()),
            BinaryOp::Eq => a._eq(&b).uext(31),
            BinaryOp::Ne => a._ne(&b).uext(31),
            BinaryOp::LtU => a.ult(&b).uext(31),
            BinaryOp::LtS => a.slt(&b).uext(31),
            BinaryOp::GtU => a.ugt(&b).uext(31),
            BinaryOp::GtS => a.sgt(&b).uext(31),
            BinaryOp::LeU => a.ulte(&b).uext(31),
            BinaryOp::LeS => a.slte(&b).uext(31),
            BinaryOp::GeU => a.ugte(&b).uext(31),
            BinaryOp::GeS => a.sgte(&b).uext(31),
            _ => unreachable!(),
        })
    }

    fn build_binary_fp(
        &self,
        op: BinaryOp,
        a: FP_,
        b: FP_,
    ) -> Result<BitwuzlaVal, SolverBackendError> {
        let fp_todo = Err(SolverBackendError::UnsupportedFloatingpointOperation);
        Ok(match op {
            BinaryOp::FEq => a._eq(&b).uext(31).into(),
            BinaryOp::FNe => a._eq(&b).not().uext(31).into(),
            BinaryOp::FLt => a.lt(&b).uext(31).into(),
            BinaryOp::FGt => a.gt(&b).uext(31).into(),
            BinaryOp::FLe => a.leq(&b).uext(31).into(),
            BinaryOp::FGe => a.geq(&b).uext(31).into(),
            BinaryOp::FAdd => a.add(&b, RoundingMode::RNE).into(),
            BinaryOp::FSub => a.sub(&b, RoundingMode::RNE).into(),
            BinaryOp::FMul => a.mul(&b, RoundingMode::RNE).into(),
            BinaryOp::FDiv => a.div(&b, RoundingMode::RNE).into(),
            BinaryOp::FMin => a.min(&b).into(),
            BinaryOp::FMax => a.max(&b).into(),
            BinaryOp::FCopysign => {
                return fp_todo;
                // a.copysign(&b).into()
            }
            _ => unreachable!(),
        })
    }

    fn event_as_constraint(
        &mut self,
        event: &ConcolicEvent,
        context: &Symvals,
    ) -> Result<Bool_, SolverBackendError> {
        Ok(match event {
            ConcolicEvent::PathConstraint {
                condition, taken, ..
            } => {
                let cond = self.get_symval(*condition, context)?.bv();
                if *taken {
                    cond._ne(&BV::zero(self.btor.clone(), 32))
                } else {
                    cond._eq(&BV::zero(self.btor.clone(), 32))
                }
            }
            ConcolicEvent::MemoryConstraint { address, sym, .. } => {
                let addr = BV::from_u32(self.btor.clone(), *address, 32);
                self.get_symval(*sym, context)?.bv()._eq(&addr)
            }
            ConcolicEvent::TryAlternative { .. } => todo!(),
            ConcolicEvent::TrySolveMemcmp { pairs, .. } => {
                let _true = Bool::from_bool(self.btor.clone(), true);
                pairs
                    .iter()
                    .map(|(a, b)| {
                        let a = self.get_symval(*a, context)?.bv();
                        let b = self.get_symval(*b, context)?.bv();
                        Ok(a._eq(&b))
                    })
                    .try_fold(_true, |a, b| Ok(a.and(&b?)))?
            }
            ConcolicEvent::TrySolveStrcmplike {
                symvals,
                reference,
                ignorecase,
                ..
            } => {
                let _true = Bool::from_bool(self.btor.clone(), true);
                let symvals = symvals
                    .iter()
                    .map(|v| self.get_symval(*v, context).map(BitwuzlaVal::bv))
                    .collect::<Result<Vec<_>, _>>()?;
                let upper_a = BV::from_u32(self.btor.clone(), b'A' as u32, 8);
                let upper_z = BV::from_u32(self.btor.clone(), b'Z' as u32, 8);
                let case_bit = BV::from_u32(self.btor.clone(), 0x20, 8);
                symvals
                    .iter()
                    .zip(reference)
                    .try_fold(_true, |acc, (sym, &ref_)| {
                        let ref_ = BV::from_u32(self.btor.clone(), ref_ as u32, 8);
                        let lower = |x: &BV_| {
                            x.ugte(&upper_a)
                                .and(&x.ulte(&upper_z))
                                .cond_bv(&x.or(&case_bit), x)
                        };
                        let res = if *ignorecase {
                            lower(sym)._eq(&lower(&ref_))
                        } else {
                            sym._eq(&ref_)
                        };
                        Ok(acc.and(&res))
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
        let constraint = self.event_as_constraint(event, context)?;
        // TODO(refactor): move to event_as_constraint?
        let constraint = match event {
            ConcolicEvent::TryAlternative { .. }
            | ConcolicEvent::TrySolveMemcmp { .. }
            | ConcolicEvent::TrySolveStrcmplike { .. } => constraint.not(),
            _ => constraint,
        };
        println!("solving for negated condition   ...");
        let res = self.btor.check_sat_assuming(&[constraint.not()]);
        println!(
            "solving for negated condition   ... done: {:?} ({:?})",
            res,
            start.elapsed()
        );
        if start.elapsed().as_secs_f32() > 1.0 {
            if let Some(spec) = self.spec.as_ref() {
                println!("slow solve @ {:?}", spec.format_location(event.location()));
            }
            println!("{:?}", event);
        }
        Ok(res == SolverResult::Sat)
    }

    pub(crate) fn apply_model(&self, input: &mut [u8]) {
        for (i, bv) in &self.inp_vals {
            let solution = bv.get_a_solution();
            input[*i as usize] = solution.as_u64().unwrap() as u8;
            // eprintln!("apply_model[{}] = {:#x}", *i as usize, input[*i as usize]);
        }
    }

    pub(crate) fn provide_hint(&mut self, input: &[u8], mask: &BitSlice) {
        let mut hints = Vec::new();
        for i in mask.iter_ones() {
            let hint = input[i];
            let hint = BV::from_u32(self.btor.clone(), hint as u32, 8);
            let bv = self.get_inp_bv(i as u16);
            hints.push(hint._eq(&bv));
        }
        self.btor.check_sat_assuming(&hints);
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

        let start = std::time::Instant::now();
        let constraint = self.event_as_constraint(event, context)?;
        constraint.assert();

        let mut res = SolverResult::Unknown;

        if try_solve {
            println!("solving with asserted condition ...");
            res = self.btor.sat();
            println!(
                "solving with asserted condition ... done: {:?} ({:?})",
                res,
                start.elapsed()
            );
            if start.elapsed().as_secs_f32() > 0.5 {
                println!("\n^ slow!");
            }
        } else {
            if cfg!(not(feature = "concolic_debug_verify")) {
                return Ok(());
            }
        }

        if res == SolverResult::Unknown {
            // help the solver out with the original assignment as assumptions
            let mut hints = Vec::new();
            for (i, bv) in &self.inp_vals {
                let hint = input[*i as usize];
                let hint = BV::from_u32(self.btor.clone(), hint as u32, 8);
                hints.push(hint._eq(bv));
            }
            if try_solve {
                println!("solving with assert and hints   ...");
            }
            res = self.btor.check_sat_assuming(&hints);
            if try_solve {
                println!(
                    "solving with assert and hints   ... done: {:?} ({:?})",
                    res,
                    start.elapsed()
                );
            }
        }

        if res != SolverResult::Sat {
            println!();
            println!("{:?}", event);
            std::fs::write("/tmp/inp.bin", input).unwrap();
        }
        assert_eq!(res, SolverResult::Sat);

        Ok(())
    }

    pub(crate) fn eval_as_u64_with_input(
        &mut self,
        val: SymValRef,
        input: &[u8],
        context: &Symvals,
    ) -> Result<u64, SolverBackendError> {
        let bv = self.get_symval(val, context)?;
        let mut assumptions = Vec::new();
        for (i, bv) in &self.inp_vals {
            let hint = input[*i as usize];
            let hint = BV::from_u32(self.btor.clone(), hint as u32, 8);
            assumptions.push(hint._eq(bv));
        }
        let res = self.btor.sat();
        assert_eq!(res, SolverResult::Sat);

        let model = self.btor.check_sat_assuming(&assumptions);

        if bv.is_bv() {
            let solution = bv.bv().get_a_solution();
            Ok(solution.as_u64().unwrap())
        } else {
            Err(SolverBackendError::UnsupportedFloatingpointOperation)
        }
    }
}
