use crate::{HashMap, HashSet};
use std::sync::Arc;

use bitvec::slice::BitSlice;
use z3::{
    SatResult, Solver, Symbol,
    ast::{BV, Bool, Dynamic, Float, RoundingMode},
};

use crate::{concolic::MemoryAccessKind, ir::ModuleSpec};

use super::{BinaryOp, ConcolicEvent, SolverBackendError, SymVal, SymValRef, Symvals, UnaryOp};

trait DynamicHelper {
    fn bv(&self) -> BV;
    fn fp(&self) -> Float;
}

impl DynamicHelper for Dynamic {
    fn bv(&self) -> BV {
        self.as_bv().unwrap()
    }

    fn fp(&self) -> Float {
        self.as_float().unwrap()
    }
}

trait BoolHelper {
    fn zero_ext(&self, w: u32) -> BV;
}
impl BoolHelper for Bool {
    fn zero_ext(&self, w: u32) -> BV {
        let sz = w + 1;
        let zero = BV::from_u64(0, sz);
        let one = BV::from_u64(1, sz);
        self.ite(&one, &zero)
    }
}

pub(crate) struct SolverInstance {
    solver: z3::Solver,
    vals: HashMap<SymValRef, Dynamic>,
    vals_err: HashMap<SymValRef, SolverBackendError>,
    seen: HashSet<SymValRef>,
    pub(crate) inp_vals: HashMap<u16, BV>,
    spec: Option<Arc<ModuleSpec>>,
}

impl SolverInstance {
    pub(crate) fn new(spec: Option<Arc<ModuleSpec>>) -> Self {
        let solver = Solver::new();
        SolverInstance {
            solver,
            vals: HashMap::default(),
            vals_err: HashMap::default(),
            seen: HashSet::default(),
            inp_vals: HashMap::default(),
            spec,
        }
    }

    fn get_inp_bv(&mut self, i: u16) -> BV {
        self.inp_vals
            .entry(i)
            .or_insert_with(|| {
                let symbol = format!("inp-{}", i);
                BV::new_const(Symbol::String(symbol), 8)
            })
            .clone()
    }

    fn get_symval(
        &mut self,
        symref: SymValRef,
        context: &Symvals,
    ) -> Result<Dynamic, SolverBackendError> {
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
        match res.clone() {
            Ok(res) => {
                self.vals.insert(symref, res);
            }
            Err(res) => {
                self.vals_err.insert(symref, res);
            }
        }
        res
    }

    fn get_symval_(
        &mut self,
        symref: SymValRef,
        context: &Symvals,
    ) -> Result<Dynamic, SolverBackendError> {
        let sym = context.fetch(symref);
        Ok(match sym {
            SymVal::Concrete => unreachable!(),
            SymVal::InputByte(index) => self.get_inp_bv(index).into(),
            SymVal::ConstI8(v) => BV::from_u64(v as _, 8).into(),
            SymVal::ConstI32(v) => BV::from_u64(v as _, 32).into(),
            SymVal::ConstI64(v) => BV::from_u64(v, 64).into(),
            SymVal::ConstF32(v) => Float::from_f32(*v).into(),
            SymVal::ConstF64(v) => Float::from_f64(*v).into(),
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
                let zero = BV::from_u64(0, 32);
                let cond = cond.eq(&zero).not();
                cond.ite(&a, &b)
            }
            SymVal::ExtractByte {
                kind: _,
                val,
                byte_index,
            } => {
                let byte_index = byte_index as u32;
                let val = self.get_symval(val, context)?;
                val.bv().extract(byte_index * 8 + 7, byte_index * 8).into()
            }
            SymVal::CombineBytes { kind, vals } => {
                assert_eq!(vals.len(), kind.access_width_bytes());
                // zero-width bvs are not allowed :(
                let mut res: Option<BV> = None;
                for byte in vals {
                    let byte = self.get_symval(byte, context)?.bv();
                    res = Some(match res {
                        Some(res) => byte.concat(&res),
                        None => byte,
                    });
                }
                let res = res.unwrap();
                if matches!(kind, MemoryAccessKind::F32) {
                    // TODO: res.to_fp32().into()
                    return Err(SolverBackendError::UnsupportedFloatingpointOperation);
                } else if matches!(kind, MemoryAccessKind::F64) {
                    // TODO: res.to_fp64().into()
                    return Err(SolverBackendError::UnsupportedFloatingpointOperation);
                } else if kind.value_width_bytes() != kind.access_width_bytes() {
                    let extend_by =
                        (kind.value_width_bytes() * 8 - kind.access_width_bytes() * 8) as u32;
                    if kind.sign_extend() {
                        res.sign_ext(extend_by).into()
                    } else {
                        res.zero_ext(extend_by).into()
                    }
                } else {
                    assert_eq!(res.get_size(), kind.value_width_bytes() as u32 * 8);
                    res.into()
                }
            }
            #[expect(unused)]
            SymVal::Load {
                addr32,
                addr32_concrete,
                fixed_offset,
                kind,
                epoch,
            } => todo!(),
        })
    }

    fn build_unary(&self, op: UnaryOp, val: Dynamic) -> Result<Dynamic, SolverBackendError> {
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

    fn build_unary_bv(&self, op: UnaryOp, val: BV) -> Result<BV, SolverBackendError> {
        let width = val.get_size();
        Ok(match op {
            UnaryOp::Clz | UnaryOp::Ctz => {
                let zero = BV::from_u64(0, width);
                let one = BV::from_u64(1, width);
                let one_1 = BV::from_u64(1, 1);
                let mut cnt = zero.clone();
                let mut seen = Bool::from_bool(false);
                for i in 0..width {
                    let i = if matches!(op, UnaryOp::Clz) {
                        width - i - 1
                    } else {
                        i
                    };
                    seen |= &val.extract(i, i).eq(&one_1);
                    cnt += &seen.ite(&zero, &one);
                }
                cnt
            }
            UnaryOp::Popcnt => {
                let mut cnt = BV::from_u64(0, width);
                for i in 0..width {
                    let bit = val.extract(i, i);
                    cnt += &bit.zero_ext(width - 1);
                }
                cnt
            }
            UnaryOp::Eqz => val.eq(BV::from_u64(0, width)).zero_ext(31),
            UnaryOp::I32Extend8S => val.extract(7, 0).sign_ext(24),
            UnaryOp::I32Extend16S => val.extract(15, 0).sign_ext(16),
            UnaryOp::I32WrapI64 => val.extract(31, 0),
            UnaryOp::I64Extend8S => val.extract(7, 0).sign_ext(56),
            UnaryOp::I64Extend16S => val.extract(15, 0).sign_ext(48),
            UnaryOp::I64Extend32S => val.extract(31, 0).sign_ext(32),
            UnaryOp::I64ExtendI32S => val.sign_ext(32),
            UnaryOp::I64ExtendI32U => val.zero_ext(32),
            _ => unreachable!(),
        })
    }

    fn build_unary_fp(&self, _op: UnaryOp, _val: Dynamic) -> Result<Dynamic, SolverBackendError> {
        Err(SolverBackendError::UnsupportedFloatingpointOperation)
        /*
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
            UnaryOp::FAbs => return fp_todo,
            UnaryOp::FNeg => (-val.fp()).into(),
            UnaryOp::FSqrt => return fp_todo,
            // smt-lib fp doesn't have ceil, floor, trunc
            UnaryOp::FCeil => return fp_todo,
            UnaryOp::FFloor => return fp_todo,
            UnaryOp::FTrunc => return fp_todo,
            UnaryOp::FNearest => val.fp().round_to_integral(RoundingMode::RNE).into(),
            _ => unreachable!(),
        })
        */
    }

    fn build_binary(
        &self,
        op: BinaryOp,
        a: Dynamic,
        b: Dynamic,
    ) -> Result<Dynamic, SolverBackendError> {
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

    fn build_binary_bv(&self, op: BinaryOp, a: BV, b: BV) -> Result<BV, SolverBackendError> {
        assert_eq!(a.get_size(), b.get_size());
        let shift_amount = || b.bvand(BV::from_u64(a.get_size() as u64 - 1, b.get_size()));
        Ok(match op {
            BinaryOp::Add => a.bvadd(&b),
            BinaryOp::Sub => a.bvsub(&b),
            BinaryOp::Mul => a.bvmul(&b),
            BinaryOp::DivS => a.bvsdiv(&b),
            BinaryOp::DivU => a.bvudiv(&b),
            BinaryOp::RemS => a.bvsrem(&b),
            BinaryOp::RemU => a.bvurem(&b),
            BinaryOp::And => a.bvand(&b),
            BinaryOp::Or => a.bvor(&b),
            BinaryOp::Xor => a.bvxor(&b),
            BinaryOp::Shl => a.bvshl(shift_amount()),
            BinaryOp::ShrS => a.bvashr(shift_amount()),
            BinaryOp::ShrU => a.bvlshr(shift_amount()),
            BinaryOp::Rotl => a.bvrotl(shift_amount()),
            BinaryOp::Rotr => a.bvrotr(shift_amount()),
            BinaryOp::Eq => a.eq(&b).zero_ext(31),
            BinaryOp::Ne => a.eq(&b).not().zero_ext(31),
            BinaryOp::LtU => a.bvult(&b).zero_ext(31),
            BinaryOp::LtS => a.bvslt(&b).zero_ext(31),
            BinaryOp::GtU => a.bvugt(&b).zero_ext(31),
            BinaryOp::GtS => a.bvsgt(&b).zero_ext(31),
            BinaryOp::LeU => a.bvule(&b).zero_ext(31),
            BinaryOp::LeS => a.bvsle(&b).zero_ext(31),
            BinaryOp::GeU => a.bvuge(&b).zero_ext(31),
            BinaryOp::GeS => a.bvsge(&b).zero_ext(31),
            _ => unreachable!(),
        })
    }

    fn build_binary_fp(
        &self,
        op: BinaryOp,
        a: Float,
        b: Float,
    ) -> Result<Dynamic, SolverBackendError> {
        let fp_todo = Err(SolverBackendError::UnsupportedFloatingpointOperation);
        // TODO: i think this would be correct:
        // Z3_mk_fpa_round_nearest_ties_to_even
        let rm = RoundingMode::round_towards_zero();
        Ok(match op {
            BinaryOp::FEq => a.eq(&b).zero_ext(31).into(),
            BinaryOp::FNe => a.eq(&b).not().zero_ext(31).into(),
            BinaryOp::FLt => a.lt(&b).zero_ext(31).into(),
            BinaryOp::FGt => a.gt(&b).zero_ext(31).into(),
            BinaryOp::FLe => a.le(&b).zero_ext(31).into(),
            BinaryOp::FGe => a.ge(&b).zero_ext(31).into(),
            BinaryOp::FAdd => a.add_with_rounding_mode(&b, &rm).into(),
            BinaryOp::FSub => a.sub_with_rounding_mode(&b, &rm).into(),
            BinaryOp::FMul => a.mul_with_rounding_mode(&b, &rm).into(),
            BinaryOp::FDiv => a.div_with_rounding_mode(&b, &rm).into(),
            // TODO: min/max for z3.rs
            BinaryOp::FMin | // => a.min(&b).into(),
            BinaryOp::FMax | // => a.max(&b).into(),
            BinaryOp::FCopysign => {
                return fp_todo;
                // a.copysign(&b).into()
            }
            _ => unreachable!(),
        })
    }

    pub(crate) fn event_as_constraint(
        &mut self,
        event: &ConcolicEvent,
        context: &Symvals,
    ) -> Result<Bool, SolverBackendError> {
        Ok(match event {
            ConcolicEvent::PathConstraint {
                condition, taken, ..
            } => {
                let cond = self.get_symval(*condition, context)?.bv();
                if *taken {
                    cond.eq(BV::from_u64(0, 32)).not()
                } else {
                    cond.eq(BV::from_u64(0, 32))
                }
            }
            ConcolicEvent::MemoryConstraint { address, sym, .. } => {
                let addr = BV::from_u64(*address as _, 32);
                self.get_symval(*sym, context)?.bv().eq(&addr)
            }
            ConcolicEvent::TryAlternative { .. } => todo!(),
            ConcolicEvent::TrySolveMemcmp { pairs, .. } => {
                let _true = Bool::from_bool(true);
                pairs
                    .iter()
                    .map(|(a, b)| {
                        let a = self.get_symval(*a, context)?.bv();
                        let b = self.get_symval(*b, context)?.bv();
                        Ok(a.eq(&b))
                    })
                    .try_fold(_true, |a, b| Ok(a & (&b?)))?
            }
            ConcolicEvent::TrySolveStrcmplike {
                symvals,
                reference,
                ignorecase,
                ..
            } => {
                let _true = Bool::from_bool(true);
                let symvals = symvals
                    .iter()
                    .map(|v| self.get_symval(*v, context).map(|x| x.bv()))
                    .collect::<Result<Vec<_>, _>>()?;
                let upper_a = BV::from_u64(b'A' as _, 8);
                let upper_z = BV::from_u64(b'Z' as _, 8);
                let case_bit = BV::from_u64(0x20, 8);
                symvals
                    .iter()
                    .zip(reference)
                    .try_fold(_true, |acc, (sym, &ref_)| {
                        let ref_ = BV::from_u64(ref_ as _, 8);
                        let lower = |x: &BV| {
                            (x.bvuge(&upper_a) & x.bvule(&upper_z)).ite(&(x | case_bit.clone()), x)
                        };
                        let res = if *ignorecase {
                            lower(sym).eq(lower(&ref_))
                        } else {
                            sym.eq(&ref_)
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
        self.z3_set_timeout();
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
        let res = self.solver.check_assumptions(&[constraint.not()]);
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
        Ok(res == SatResult::Sat)
    }

    pub(crate) fn apply_model(&self, input: &mut [u8]) {
        self.z3_set_timeout();
        // TODO: apply only used inp_vals?
        let model = self.solver.get_model().unwrap();
        for (i, bv) in &self.inp_vals {
            if let Some(solution) = model.get_const_interp(bv) {
                input[*i as usize] = solution.as_u64().unwrap() as u8;
                eprintln!("apply_model[{}] = {:#x}", *i as usize, input[*i as usize]);
            }
        }
    }

    pub(crate) fn provide_hint(&mut self, input: &[u8], mask: &BitSlice) {
        let mut hints = Vec::new();
        for i in mask.iter_ones() {
            let hint = input[i];
            let hint = BV::from_u64(hint as _, 8);
            let bv = self.get_inp_bv(i as u16);
            hints.push(hint.eq(&bv));
        }
        self.solver.check_assumptions(&hints);
    }

    pub(crate) fn assert(
        &mut self,
        event: &ConcolicEvent,
        input: &[u8],
        context: &Symvals,
        try_solve: bool,
    ) -> Result<(), SolverBackendError> {
        self.z3_set_timeout();
        match event {
            ConcolicEvent::TryAlternative { .. }
            | ConcolicEvent::TrySolveMemcmp { .. }
            | ConcolicEvent::TrySolveStrcmplike { .. } => return Ok(()),
            _ => {}
        }

        let start = std::time::Instant::now();
        let constraint = self.event_as_constraint(event, context)?;
        self.solver.assert(&constraint);

        let mut res = SatResult::Unknown;

        if try_solve {
            println!("solving with asserted condition ...");
            res = self.solver.check();
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
            let mut hints = Vec::new();
            for (i, bv) in &self.inp_vals {
                let hint = input[*i as usize];
                let hint = BV::from_u64(hint as u64, 8);
                hints.push(hint.eq(bv));
            }
            if try_solve {
                println!("solving with assert and hints   ...");
            }
            res = self.solver.check_assumptions(&hints);
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
            println!("{:?}", event);
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
    ) -> Result<u64, SolverBackendError> {
        let bv = self.get_symval(val, context)?;
        let mut assumptions = Vec::new();
        for (i, bv) in &self.inp_vals {
            let hint = input[*i as usize];
            let hint = BV::from_u64(hint as _, 8);
            assumptions.push(hint.eq(bv));
        }
        let res = self.solver.check();
        assert_eq!(res, SatResult::Sat);

        let _model = self.solver.check_assumptions(&assumptions);
        let model = self.solver.get_model().unwrap();

        let bv = model.eval(&bv.bv(), true);

        if let Some(solution) = bv {
            // let solution = bv.bv().get_a_solution();
            Ok(solution.as_u64().unwrap())
        } else {
            Err(SolverBackendError::UnspecifiedError)
        }
    }

    fn z3_set_timeout(&self) {
        z3::Context::thread_local().update_param_value("timeout", "1000");
    }
}
