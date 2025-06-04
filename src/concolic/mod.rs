#![cfg_attr(not(feature = "concolic"), allow(unused))]

use std::marker::PhantomData;
use std::sync::Arc;

use crate::ir::ModuleSpec;
use crate::{HashMap, HashSet};

use crate::ir::Location;
use bitvec::prelude::BitVec;
use bitvec::slice::BitSlice;
use ordered_float::OrderedFloat;
use speedy::{Readable, Writable};

#[cfg(feature = "concolic")]
pub(crate) mod smtlib_backend;
#[cfg(feature = "concolic")]
mod smtlib_helpers;
#[cfg(feature = "concolic")]
pub(crate) use smtlib_backend::SolverInstance as SmtlibSolver;

#[cfg(feature = "concolic_bitwuzla")]
pub(crate) mod bitwuzla_backend;
#[cfg(feature = "concolic_bitwuzla")]
pub(crate) use bitwuzla_backend::SolverInstance as BitwuzlaSolver;

#[cfg(feature = "concolic_z3")]
pub(crate) mod z3_backend;
#[cfg(feature = "concolic_z3")]
pub(crate) use z3_backend::SolverInstance as Z3Solver;

#[allow(unused)]
pub(crate) enum SolverKind {
    Z3,
    Bitwuzla,
    SmtlibZ3,
    SmtlibCVC5,
}

// Note: There doesn't seem to be a better way to avoid "unused 'ctx parameter"
//       warnings for builds without concolic support..
#[non_exhaustive]
pub(crate) enum ConcolicSolver<'ctx> {
    #[cfg(feature = "concolic_z3")]
    Z3(Z3Solver<'ctx>),
    #[cfg(feature = "concolic_bitwuzla")]
    Bitwuzla(BitwuzlaSolver),
    #[cfg(feature = "concolic")]
    Smtlib(SmtlibSolver<'ctx>),
    _Unsupported(std::convert::Infallible, PhantomData<&'ctx ()>),
}

// TODO: refactor as trait?
#[cfg_attr(not(feature = "concolic"), allow(unused))]
impl ConcolicSolver<'_> {
    pub(crate) fn apply_model(&mut self, input: &mut [u8]) {
        match self {
            #[cfg(feature = "concolic_z3")]
            ConcolicSolver::Z3(x) => x.apply_model(input),
            #[cfg(feature = "concolic_bitwuzla")]
            ConcolicSolver::Bitwuzla(x) => x.apply_model(input),
            #[cfg(feature = "concolic")]
            ConcolicSolver::Smtlib(x) => x.apply_model(input),
            _ => unreachable!(),
        }
    }

    pub(crate) fn provide_hint(&mut self, input: &[u8], mask: &BitSlice) {
        match self {
            #[cfg(feature = "concolic_z3")]
            ConcolicSolver::Z3(x) => x.provide_hint(input, mask),
            #[cfg(feature = "concolic_bitwuzla")]
            ConcolicSolver::Bitwuzla(x) => x.provide_hint(input, mask),
            #[cfg(feature = "concolic")]
            ConcolicSolver::Smtlib(x) => x.provide_hint(input, mask),
            _ => unreachable!(),
        }
    }

    pub(crate) fn try_negate(
        &mut self,
        event: &ConcolicEvent,
        context: &Symvals,
    ) -> Result<bool, SolverBackendError> {
        match self {
            #[cfg(feature = "concolic_z3")]
            ConcolicSolver::Z3(x) => x.try_negate(event, context),
            #[cfg(feature = "concolic_bitwuzla")]
            ConcolicSolver::Bitwuzla(x) => x.try_negate(event, context),
            #[cfg(feature = "concolic")]
            ConcolicSolver::Smtlib(x) => x.try_negate(event, context),
            _ => unreachable!(),
        }
    }

    pub(crate) fn assert(
        &mut self,
        event: &ConcolicEvent,
        input: &[u8],
        context: &Symvals,
        try_solve: bool,
    ) -> Result<(), SolverBackendError> {
        match self {
            #[cfg(feature = "concolic_z3")]
            ConcolicSolver::Z3(x) => x.assert(event, input, context, try_solve),
            #[cfg(feature = "concolic_bitwuzla")]
            ConcolicSolver::Bitwuzla(x) => x.assert(event, input, context, try_solve),
            #[cfg(feature = "concolic")]
            ConcolicSolver::Smtlib(x) => x.assert(event, input, context, try_solve),
            _ => unreachable!(),
        }
    }
}

pub(crate) struct ConcolicProvider {
    #[cfg(feature = "concolic_z3")]
    z3_ctx: z3::Context,

    #[cfg(feature = "concolic")]
    smtlib_storage: smtlib::Storage,

    spec: Option<Arc<ModuleSpec>>,
}

impl ConcolicProvider {
    pub(crate) fn is_available() -> bool {
        cfg!(any(feature = "concolic_z3", feature = "concolic_bitwuzla"))
    }

    pub(crate) fn new(spec: Option<Arc<ModuleSpec>>) -> Self {
        #[cfg(feature = "concolic_z3")]
        let z3_ctx = {
            let mut cfg = z3::Config::new();
            cfg.set_timeout_msec(1_000);
            z3::Context::new(&cfg)
        };
        Self {
            #[cfg(feature = "concolic_z3")]
            z3_ctx,
            #[cfg(feature = "concolic")]
            smtlib_storage: smtlib::Storage::new(),
            spec,
        }
    }

    #[allow(unused_mut)]
    pub(crate) fn new_solver(&self, mut kind: Option<SolverKind>) -> Option<ConcolicSolver<'_>> {
        #[cfg(feature = "concolic_z3")]
        {
            kind = kind.or(Some(SolverKind::Z3));
        }
        #[cfg(feature = "concolic_bitwuzla")]
        {
            kind = kind.or(Some(SolverKind::Bitwuzla));
        }
        #[cfg(feature = "concolic")]
        {
            kind = kind.or(Some(SolverKind::SmtlibCVC5));
        }
        match kind {
            #[cfg(feature = "concolic_bitwuzla")]
            Some(SolverKind::Bitwuzla) => Some(ConcolicSolver::Bitwuzla(BitwuzlaSolver::new(
                self.spec.clone(),
            ))),
            #[cfg(feature = "concolic_z3")]
            Some(SolverKind::Z3) => Some(ConcolicSolver::Z3(Z3Solver::new(
                self.spec.clone(),
                &self.z3_ctx,
            ))),
            #[cfg(feature = "concolic")]
            Some(SolverKind::SmtlibCVC5) => Some(ConcolicSolver::Smtlib(SmtlibSolver::new(
                self.spec.clone(),
                &self.smtlib_storage,
                smtlib::Solver::new(
                    &self.smtlib_storage,
                    Box::new(smtlib::backend::cvc5_binary::Cvc5Binary::new("cvc5").unwrap())
                        as Box<dyn smtlib::Backend>,
                )
                .unwrap(),
            ))),
            _ => None,
        }
    }
}

mod ops;
pub(crate) use ops::*;

#[derive(Debug, Clone)]
pub(crate) enum SolverBackendError {
    UnsupportedFloatingpointOperation,
    UnspecifiedError,
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Readable, Writable)]
#[repr(transparent)]
// TODO(perf-mem): serialize as varint?
pub(crate) struct SymValRef(u32);
impl SymValRef {
    pub(crate) fn concrete() -> Self {
        Self(0)
    }
    pub(crate) fn is_concrete(&self) -> bool {
        *self == Self::concrete()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Readable, Writable)]
#[repr(u8)]
pub(crate) enum SymVal {
    // Dummy value for fast symbolic expression tracking
    Concrete,
    // symbolic environment
    InputByte(u16),
    // symbolic expressions
    ConstI8(u8),
    ConstI32(u32),
    ConstI64(u64),
    ConstF32(OrderedFloat<f32>),
    ConstF64(OrderedFloat<f64>),
    Unary(UnaryOp, SymValRef),
    Binary(BinaryOp, SymValRef, SymValRef),
    Select {
        condition: SymValRef,
        a: SymValRef,
        b: SymValRef,
    },
    ExtractByte {
        kind: MemoryAccessKind,
        val: SymValRef,
        byte_index: usize,
    },
    CombineBytes {
        kind: MemoryAccessKind,
        vals: Vec<SymValRef>,
    },
    Load {
        addr32: SymValRef,
        addr32_concrete: u32,
        fixed_offset: u32,
        kind: MemoryAccessKind,
        epoch: usize,
    },
}

impl SymVal {
    // Note: Should this be an iterator or smallvec instead?
    pub(crate) fn refs(&self) -> Vec<SymValRef> {
        match self {
            Self::Concrete
            | Self::InputByte(_)
            | Self::ConstI8(_)
            | Self::ConstI32(_)
            | Self::ConstI64(_)
            | Self::ConstF32(_)
            | Self::ConstF64(_) => Vec::new(),
            Self::Unary(_, v) => vec![*v],
            Self::Binary(_, a, b) => vec![*a, *b],
            Self::Select { condition, a, b } => vec![*condition, *a, *b],
            Self::ExtractByte { val, .. } => vec![*val],
            Self::Load { addr32, .. } => vec![*addr32],
            Self::CombineBytes { vals, .. } => vals.clone(),
        }
    }

    pub(crate) fn refs_mut(&mut self) -> Vec<&mut SymValRef> {
        match self {
            Self::Concrete
            | Self::InputByte(_)
            | Self::ConstI8(_)
            | Self::ConstI32(_)
            | Self::ConstI64(_)
            | Self::ConstF32(_)
            | Self::ConstF64(_) => Vec::new(),
            Self::Unary(_, v) => vec![v],
            Self::Binary(_, a, b) => vec![a, b],
            Self::Select { condition, a, b } => vec![condition, a, b],
            Self::ExtractByte { val, .. } => vec![val],
            Self::Load { addr32, .. } => vec![addr32],
            Self::CombineBytes { vals, .. } => vals.iter_mut().collect(),
        }
    }
}

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, Readable, Writable)]
#[repr(u8)]
pub(crate) enum MemoryAccessKind {
    I32,
    I32AsS8,
    I32AsU8,
    I32AsS16,
    I32AsU16,
    I64,
    I64AsS8,
    I64AsU8,
    I64AsS16,
    I64AsU16,
    I64AsS32,
    I64AsU32,
    F32,
    F64,
}

impl MemoryAccessKind {
    fn access_width_bytes(&self) -> usize {
        match self {
            Self::I32 => 4,
            Self::I32AsS8 | Self::I32AsU8 => 1,
            Self::I32AsS16 | Self::I32AsU16 => 2,
            Self::I64 => 8,
            Self::I64AsS8 | Self::I64AsU8 => 1,
            Self::I64AsS16 | Self::I64AsU16 => 2,
            Self::I64AsS32 | Self::I64AsU32 => 4,
            Self::F32 => 4,
            Self::F64 => 8,
        }
    }

    fn value_width_bytes(&self) -> usize {
        match self {
            Self::I32 | Self::I32AsS8 | Self::I32AsU8 | Self::I32AsS16 | Self::I32AsU16 => 4,
            Self::I64
            | Self::I64AsS8
            | Self::I64AsU8
            | Self::I64AsS16
            | Self::I64AsU16
            | Self::I64AsS32
            | Self::I64AsU32 => 8,
            Self::F32 => 4,
            Self::F64 => 8,
        }
    }

    #[expect(unused)]
    fn sign_extend(&self) -> bool {
        matches!(
            self,
            Self::I32AsS8 | Self::I32AsS16 | Self::I64AsS8 | Self::I64AsS16 | Self::I64AsS32
        )
    }

    pub(crate) fn from_opcode_and_ty(
        opcode: cranelift::codegen::ir::Opcode,
        ty: cranelift::prelude::Type,
    ) -> Self {
        use cranelift::codegen::ir::{types, Opcode};
        match (opcode, ty) {
            (Opcode::Load, types::I32) => Self::I32,
            (Opcode::Load, types::I64) => Self::I64,
            (Opcode::Load, types::F32) => Self::F32,
            (Opcode::Load, types::F64) => Self::F64,
            (Opcode::Uload8, types::I32) => Self::I32AsU8,
            (Opcode::Sload8, types::I32) => Self::I32AsS8,
            (Opcode::Uload16, types::I32) => Self::I32AsU16,
            (Opcode::Sload16, types::I32) => Self::I32AsS16,
            (Opcode::Uload8, types::I64) => Self::I64AsU8,
            (Opcode::Sload8, types::I64) => Self::I64AsS8,
            (Opcode::Uload16, types::I64) => Self::I64AsU16,
            (Opcode::Sload16, types::I64) => Self::I64AsS16,
            (Opcode::Uload32, types::I64) => Self::I64AsU32,
            (Opcode::Sload32, types::I64) => Self::I64AsS32,
            (Opcode::Store, types::I32) => Self::I32,
            (Opcode::Store, types::I64) => Self::I64,
            (Opcode::Store, types::F32) => Self::F32,
            (Opcode::Store, types::F64) => Self::F64,
            (Opcode::Istore8, types::I32) => Self::I32AsU8,
            (Opcode::Istore16, types::I32) => Self::I32AsU16,
            (Opcode::Istore8, types::I64) => Self::I64AsU8,
            (Opcode::Istore16, types::I64) => Self::I64AsU16,
            (Opcode::Istore32, types::I64) => Self::I64AsU32,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum ConcolicEvent {
    // Branch condition was symbolic, we need to concretize for concolic execution
    PathConstraint {
        location: Location,
        condition: SymValRef,
        taken: bool,
    },
    // Address was symbolic, we want to concretize to simplify memory modelling
    MemoryConstraint {
        location: Location,
        address: u32,
        sym: SymValRef,
        purpose: MemoryConstraintPurpose,
    },
    // TODO: Where could we automatically apply tryalternatives? The select instruction? Indirect branches?
    #[allow(unused)]
    TryAlternative {
        location: Location,
        concrete: SymValRef,
        symbolic: SymValRef,
        interesting: Vec<()>, // concrete values of interest?
    },
    TrySolveMemcmp {
        location: Location,
        pairs: Vec<(SymValRef, SymValRef)>,
    },
    TrySolveStrcmplike {
        location: Location,
        symvals: Vec<SymValRef>,
        reference: Vec<u8>,
        ignorecase: bool,
    },
}

#[derive(Debug, Clone)]
pub(crate) enum MemoryConstraintPurpose {
    Load,
    LoadWithFixedOffset(u32),
    Store,
    StoreWithFixedOffset(u32),
    MemoryIntrinsicLength,
}

impl ConcolicEvent {
    pub(crate) fn location(&self) -> Location {
        match self {
            Self::PathConstraint { location, .. }
            | Self::MemoryConstraint { location, .. }
            | Self::TryAlternative { location, .. }
            | Self::TrySolveMemcmp { location, .. }
            | Self::TrySolveStrcmplike { location, .. } => *location,
        }
    }

    fn symrefs(&self) -> Vec<SymValRef> {
        match self {
            Self::PathConstraint {
                location: _,
                condition,
                taken: _,
            } => {
                vec![*condition]
            }
            Self::MemoryConstraint {
                location: _,
                address: _,
                purpose: _,
                sym,
            } => {
                vec![*sym]
            }
            Self::TryAlternative {
                location: _,
                concrete,
                symbolic,
                interesting: _,
            } => {
                vec![*concrete, *symbolic]
            }
            Self::TrySolveMemcmp { location: _, pairs } => {
                pairs.iter().flat_map(|(a, b)| [*a, *b]).collect()
            }
            Self::TrySolveStrcmplike {
                location: _,
                symvals,
                reference: _,
                ignorecase: _,
            } => symvals.clone(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Symvals {
    buffer: Vec<u8>,
    debug: bool,
    track_module_byte_offsets: bool,
    module_byte_offsets: Vec<u32>,
    refs: Vec<SymValRef>,
}

impl Symvals {
    pub(crate) fn new(debug: bool) -> Self {
        let track_module_byte_offsets = false; // TODO
        let mut s = Self {
            buffer: Vec::new(),
            track_module_byte_offsets,
            module_byte_offsets: Vec::new(),
            refs: Vec::new(),
            debug,
        };
        s.clear();
        s
    }
    pub(crate) fn store(&mut self, sym_val: SymVal, module_byte_offset: u32) -> SymValRef {
        if cfg!(debug_assertions) {
            for r in sym_val.refs() {
                assert!((r.0 as usize) < self.buffer.len() || r.is_concrete());
            }
        }

        use std::io::{Cursor, Seek, SeekFrom};
        let pos = self.buffer.len().try_into().expect("SymValRef overflow");
        let mut cursor = Cursor::new(&mut self.buffer);
        cursor.seek(SeekFrom::End(0)).unwrap();
        sym_val.write_to_stream(cursor).unwrap();
        if pos > 0 && self.debug {
            eprintln!("symval/{pos}: {sym_val:?}");
        }
        if self.track_module_byte_offsets {
            self.module_byte_offsets.push(module_byte_offset);
        }
        SymValRef(pos)
    }

    pub(crate) fn fetch(&self, sym_ref: SymValRef) -> SymVal {
        let pos = sym_ref.0 as usize;
        assert!(self.buffer.len() >= pos);
        SymVal::read_from_buffer(&self.buffer[pos..]).unwrap()
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.clear();
        self.module_byte_offsets.clear();
        assert!(self.store(SymVal::Concrete, 0) == SymValRef::concrete());
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.buffer.len()
    }

    pub(crate) fn debug_event(&self, event: &ConcolicEvent) {
        eprintln!("concolic-event: {event:?}");
        let mut q = Vec::new();
        match event {
            ConcolicEvent::PathConstraint { condition, .. } => q.push((*condition, 0)),
            ConcolicEvent::MemoryConstraint { sym, .. } => q.push((*sym, 0)),
            ConcolicEvent::TryAlternative {
                concrete, symbolic, ..
            } => {
                q.push((*symbolic, 0));
                q.push((*concrete, 0));
            }
            ConcolicEvent::TrySolveMemcmp { pairs, .. } => {
                for (a, b) in pairs {
                    q.push((*a, 0));
                    q.push((*b, 0));
                }
                q.reverse();
            }
            ConcolicEvent::TrySolveStrcmplike { symvals, .. } => {
                for val in symvals {
                    q.push((*val, 0));
                }
                q.reverse();
            }
        }
        let mut seen = HashSet::default();
        while let Some((el, depth)) = q.pop() {
            let indentation = "  ".repeat(depth);
            if !seen.insert(el.0) {
                eprintln!("| {indentation}-> {el:?}: ...");
                continue;
            }
            if depth > 40 {
                eprintln!("| {indentation} {el:?}: ... snip ...");
                continue;
            }

            let rel = self.fetch(el);
            eprintln!("| {indentation}-> {el:?}: {rel:?}");
            let subrefs = rel.refs();
            for subref in subrefs.into_iter().rev() {
                q.push((subref, depth + 1));
            }
        }
    }
}

#[derive(Clone)]
struct MemoryLog {
    epoch: usize,
    log: Vec<MemoryLogEntry>,
}

impl MemoryLog {
    fn clear(&mut self) {
        self.epoch = 0;
        self.log.clear();
    }

    fn store(&mut self, x: MemoryLogEntry) {
        // self.log.push(MemoryLogEntry::Write);
        self.log.push(dbg!(x))
    }

    fn load(&mut self) -> SymVal {
        /*SymVal::Load {
            kind,
            offset,
            epoch: self.get_epoch(),
        }*/
        todo!()
    }

    fn get_epoch(&mut self) -> usize {
        if !matches!(self.log.last(), Some(MemoryLogEntry::Epoch)) {
            self.log.push(MemoryLogEntry::Epoch);
            self.epoch += 1;
        }
        self.epoch
    }
}

#[derive(Clone, Debug)]
enum MemoryLogEntry {
    Write {
        addr32: SymValRef,
        addr32_concrete: u32,
        fixed_offset: u32,
        value: SymValRef,
        todo_value_concrete: (),
        kind: MemoryAccessKind,
    },
    Epoch,
}

#[derive(Clone)]
pub(crate) struct ConcolicContext {
    pub global_symvars: Box<[SymValRef]>,
    pub symvals: Symvals,
    heap: Vec<SymValRef>,
    pub events: Vec<ConcolicEvent>,
    debug: bool,
    memory_log: Option<MemoryLog>,
}

impl ConcolicContext {
    pub(crate) fn new(num_globals: usize) -> Self {
        let debug = std::env::var("CONCOLICDEBUG").as_deref().unwrap_or("0") == "1";
        let model_mem = std::env::var("CONCOLICMEM").as_deref().unwrap_or("0") == "1";
        let memory_log = model_mem.then_some(MemoryLog {
            epoch: 0,
            log: Vec::new(),
        });
        Self {
            global_symvars: vec![SymValRef::concrete(); num_globals].into_boxed_slice(),
            symvals: Symvals::new(debug),
            heap: Vec::new(),
            events: Vec::new(),
            memory_log,
            debug,
        }
    }

    pub(crate) fn store(&mut self, mut sym_val: SymVal, module_byte_offset: u32) -> SymValRef {
        match sym_val {
            SymVal::Binary(BinaryOp::Add, x, y) => match (self.fetch(x), self.fetch(y)) {
                (SymVal::ConstI32(0), o) | (o, SymVal::ConstI32(0)) => {
                    dbg!();
                    sym_val = o;
                }
                (SymVal::Binary(BinaryOp::Add, a, b), SymVal::ConstI32(c))
                | (SymVal::ConstI32(c), SymVal::Binary(BinaryOp::Add, a, b)) => {
                    match (self.fetch(a), self.fetch(b)) {
                        (SymVal::ConstI32(a), _b) => {
                            dbg!();
                            sym_val = SymVal::Binary(
                                BinaryOp::Add,
                                b,
                                self.store(SymVal::ConstI32(a.wrapping_add(c)), module_byte_offset),
                            )
                        }
                        (_a, SymVal::ConstI32(b)) => {
                            dbg!();
                            sym_val = SymVal::Binary(
                                BinaryOp::Add,
                                a,
                                self.store(SymVal::ConstI32(b.wrapping_add(c)), module_byte_offset),
                            )
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            SymVal::ExtractByte {
                kind: extract_kind,
                val,
                byte_index,
            } => {
                if let SymVal::CombineBytes {
                    kind: combine_kind,
                    vals,
                } = self.fetch(val)
                {
                    if extract_kind == combine_kind {
                        dbg!();
                        sym_val = self.fetch(vals[byte_index]);
                    }
                }
            }
            SymVal::Binary(BinaryOp::And, a, b) => match (self.fetch(a), self.fetch(b)) {
                (SymVal::ConstI32(c), SymVal::CombineBytes { kind, vals })
                | (SymVal::CombineBytes { kind, vals }, SymVal::ConstI32(c)) => {
                    if c == 255
                        && matches!(kind, MemoryAccessKind::I32AsS8 | MemoryAccessKind::I32AsU8)
                    {
                        assert_eq!(vals.len(), 1);
                        dbg!();
                        sym_val = SymVal::CombineBytes {
                            kind: MemoryAccessKind::I32AsU8,
                            vals,
                        };
                    }
                }
                (_, _) => {}
            },
            // TODO: (combinebytes(...) >> X) & 0x_FF_
            // TODO: (extractbyte(x | (y << 8) | (z << 16)))
            // would need to be able to handle all sorts of shift-and-or constructions though..
            // analysis setup: keep "this section only moves bits" groups for each node?
            // => reset at arithmetic, input, consts
            // => force at lsr,lsl,rotl,rotr
            // => apply for and if operand is const
            // => for or with two symbolic operands: check known bitpattern. how?
            // maybe also keep track of "known bits" for every symref?
            _ => {}
        };

        self.symvals.store(sym_val, module_byte_offset)
    }

    pub(crate) fn fetch(&self, sym_ref: SymValRef) -> SymVal {
        self.symvals.fetch(sym_ref)
    }

    pub(crate) fn reset(&mut self) {
        self.heap.clear();
        self.events.clear();
        self.symvals.clear();
        self.global_symvars.fill(SymValRef::concrete());
    }

    fn push_event(&mut self, event: ConcolicEvent) {
        if self.debug {
            eprintln!("event #{}", self.events.len());
            self.symvals.debug_event(&event);
        }
        self.events.push(event);
    }

    pub(crate) fn push_path_constraint(
        &mut self,
        location: Location,
        condition: SymValRef,
        taken: bool,
    ) {
        self.push_event(ConcolicEvent::PathConstraint {
            condition,
            location,
            taken,
        });
    }

    pub(crate) fn push_memory_constraint(
        &mut self,
        location: Location,
        addr_sym: SymValRef,
        addr: u32,
        purpose: MemoryConstraintPurpose,
    ) {
        // TODO(concolic): track unmodified data segments and relax memory constraints for
        // read-only regions => would fix hex transform
        if self.memory_log.is_some() {
            match purpose {
                MemoryConstraintPurpose::Load
                | MemoryConstraintPurpose::LoadWithFixedOffset(_)
                | MemoryConstraintPurpose::Store
                | MemoryConstraintPurpose::StoreWithFixedOffset(_) => return,
                MemoryConstraintPurpose::MemoryIntrinsicLength => {}
            }
        }

        self.push_event(ConcolicEvent::MemoryConstraint {
            location,
            address: addr,
            sym: addr_sym,
            purpose,
        });
    }

    pub(crate) fn mark_input(&mut self, pos: usize, len: usize) {
        assert!(len <= u16::MAX as usize);
        self.ensure_heap_init_for(pos as u32, len as u32);
        for i in 0..len {
            self.heap[pos + i] = self.store(SymVal::InputByte(i as u16), 0);
        }
    }

    pub(crate) fn memory_load(
        &mut self,
        addr32: SymValRef,
        addr32_concrete: u32,
        fixed_offset: u32,
        kind: MemoryAccessKind,
        memory: &[u8],
        module_byte_offset: u32,
    ) -> SymValRef {
        let addr = addr32_concrete + fixed_offset;

        if let Some(mlog) = self.memory_log.as_mut() {
            let sym_val = SymVal::Load {
                kind,
                addr32,
                addr32_concrete,
                fixed_offset,
                epoch: mlog.get_epoch(),
            };
            return self.store(sym_val, module_byte_offset);
        }

        let mut vals = Vec::new();
        for i in 0..kind.access_width_bytes() {
            let val = self
                .heap
                .get(addr as usize + i)
                .copied()
                .unwrap_or_else(SymValRef::concrete);
            vals.push(val);
        }
        if vals
            .iter()
            .all(|&el| el.is_concrete() || matches!(self.symvals.fetch(el), SymVal::ConstI8(_)))
        {
            return SymValRef::concrete();
        }
        for (i, val) in vals.iter_mut().enumerate() {
            let pos = addr as usize + i;
            if val.is_concrete() {
                // TODO(perf-conc-mem): dedupe?
                *val = self.store(SymVal::ConstI8(memory[pos]), module_byte_offset);
            }
        }

        // simplify simple store+reload ops
        if let SymVal::ExtractByte {
            kind: range_kind,
            val: range_val,
            byte_index: 0,
        } = self.fetch(vals[0])
        {
            if range_kind == kind
                && range_kind.access_width_bytes() == range_kind.value_width_bytes()
                && vals.iter().enumerate().all(|(i, x)| {
                    matches!(
                        self.fetch(*x),
                        SymVal::ExtractByte {
                            kind: byte_kind,
                            val: byte_val,
                            byte_index: byte_i
                        } if range_kind == byte_kind && range_val == byte_val && i == byte_i
                    )
                })
            {
                return range_val;
            }
        }

        assert_eq!(vals.len(), kind.access_width_bytes());
        self.store(SymVal::CombineBytes { kind, vals }, module_byte_offset)
    }

    pub(crate) fn memory_store(
        &mut self,
        addr32: SymValRef,
        addr32_concrete: u32,
        fixed_offset: u32,
        value: SymValRef,
        kind: MemoryAccessKind,
        module_byte_offset: u32,
    ) {
        if let Some(mlog) = self.memory_log.as_mut() {
            mlog.store(MemoryLogEntry::Write {
                addr32,
                addr32_concrete,
                fixed_offset,
                value,
                kind,
                todo_value_concrete: (),
            });
            return;
        }

        let addr = addr32_concrete + fixed_offset;
        self.ensure_heap_init_for(addr, kind.access_width_bytes() as u32);
        for i in 0..kind.access_width_bytes() {
            if value.is_concrete() {
                self.heap[addr as usize + i] = SymValRef::concrete();
            } else {
                let val = SymVal::ExtractByte {
                    kind,
                    val: value,
                    byte_index: i,
                };
                // simplify simple load+store
                if let SymVal::CombineBytes {
                    kind: comb_kind,
                    vals,
                } = self.fetch(value)
                {
                    if comb_kind == kind {
                        self.heap[addr as usize + i] = vals[i];
                        continue;
                    }
                }
                self.heap[addr as usize + i] = self.store(val, module_byte_offset);
            }
        }
    }

    pub(crate) fn memory_fill(&mut self, dst: u32, val: SymValRef, len: u32) {
        self.ensure_heap_init_for(dst, len);
        self.heap[dst as usize..][..len as usize].fill(val);
    }

    pub(crate) fn memory_copy(&mut self, dst: u32, src: u32, len: u32) {
        self.ensure_heap_init_for(src, len);
        self.ensure_heap_init_for(dst, len);
        self.heap
            .copy_within((src as usize)..(src as usize + len as usize), dst as usize);
    }

    fn ensure_heap_init_for(&mut self, pos: u32, len: u32) {
        if self.heap.len() < pos as usize + len as usize {
            self.heap
                .resize(pos as usize + len as usize, SymValRef::concrete());
        }
    }

    pub(crate) fn trace_memcmp(
        &mut self,
        location: Location,
        a: usize,
        b: usize,
        n: usize,
        memory: &[u8],
        module_byte_offset: u32,
    ) {
        let (Some(a_mem), Some(b_mem)) = (memory.get(a..a + n), memory.get(b..b + n)) else {
            return;
        };
        if n > 1024 || a_mem == b_mem {
            return;
        }

        let a_is_conc = self.heap[a..][..n].iter().all(SymValRef::is_concrete);
        let b_is_conc = self.heap[b..][..n].iter().all(SymValRef::is_concrete);
        if a_is_conc && b_is_conc {
            return; // unsat
        }

        let mut get = |start: usize, mem: &[u8]| {
            let mut res = Vec::new();
            for (i, &conc) in mem.iter().enumerate() {
                let symval = self.heap[start + i];
                if symval.is_concrete() {
                    res.push(self.store(SymVal::ConstI8(conc), module_byte_offset));
                } else {
                    res.push(symval);
                }
            }
            res
        };
        let pairs = get(a, a_mem).into_iter().zip(get(b, b_mem)).collect();
        self.push_event(ConcolicEvent::TrySolveMemcmp { pairs, location });
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn trace_strcmplike(
        &mut self,
        location: Location,
        a: usize,
        b: usize,
        n: Option<usize>,
        ignorecase: bool,
        memory: &[u8],
        module_byte_offset: u32,
    ) {
        let n = n.unwrap_or_else(|| {
            let a_n = self.heap[a..]
                .iter()
                .zip(&memory[a..])
                .position(|(sym, &conc)| sym.is_concrete() && conc == 0)
                .unwrap_or(0);
            let b_n = self.heap[b..]
                .iter()
                .zip(&memory[b..])
                .position(|(sym, &conc)| sym.is_concrete() && conc == 0)
                .unwrap_or(0);
            a_n.min(b_n) + 1
        });
        let (Some(a_mem), Some(b_mem)) = (memory.get(a..a + n), memory.get(b..b + n)) else {
            return;
        };
        if n > 1024 || a_mem == b_mem {
            return;
        }
        let a_is_conc = self.heap[a..][..n].iter().all(SymValRef::is_concrete);
        let b_is_conc = self.heap[b..][..n].iter().all(SymValRef::is_concrete);

        let (symval_start, reference) = match (a_is_conc, b_is_conc) {
            (false, false) => return, // hard to solve
            (true, false) => (b, a_mem.to_vec()),
            (false, true) => (a, b_mem.to_vec()),
            (true, true) => return, // unsat
        };

        let mut symvals = Vec::new();
        #[allow(clippy::needless_range_loop)]
        for i in symval_start..symval_start + n {
            let symval = self.heap[i];
            if symval.is_concrete() {
                symvals.push(self.store(SymVal::ConstI8(memory[i]), module_byte_offset));
            } else {
                symvals.push(symval);
            }
        }

        self.push_event(ConcolicEvent::TrySolveStrcmplike {
            location,
            ignorecase,
            symvals,
            reference,
        });
    }

    #[cfg(all(feature = "concolic", not(feature = "concolic_bitwuzla")))]
    pub(crate) fn eval_as_u64_with_input(&self, val: SymValRef, input: &[u8]) -> Option<u64> {
        let storage = smtlib::Storage::new();
        let solver = smtlib::Solver::new(
            &storage,
            Box::new(smtlib::backend::cvc5_binary::Cvc5Binary::new("cvc5").unwrap())
                as Box<dyn smtlib::Backend>,
        )
        .unwrap();
        let mut solver = SmtlibSolver::new(None, &storage, solver);
        solver
            .eval_as_u64_with_input(val, input, &self.symvals)
            .unwrap()
    }
    #[cfg(feature = "concolic_bitwuzla")]
    pub(crate) fn eval_as_u64_with_input(&self, val: SymValRef, input: &[u8]) -> Option<u64> {
        let mut solver = BitwuzlaSolver::new(None);
        // eprintln!("eval({:?})", val);
        let solved = solver
            .eval_as_u64_with_input(val, input, &self.symvals)
            .ok();
        // eprintln!("eval({:?}) => {:?}", val, solved);
        solved
    }

    pub(crate) fn approx_trace_mem_usage(&self) -> usize {
        self.heap.len() * std::mem::size_of::<SymValRef>()
            + self.events.len() * std::mem::size_of::<ConcolicEvent>() * 2
            + self.symvals.byte_len()
    }

    fn deduplicate_events_by_location(events: &[ConcolicEvent]) -> Vec<ConcolicEvent> {
        if events.len() < 1024 {
            events.to_vec()
        } else {
            let mut location_idxs = HashMap::<_, Vec<usize>>::default();
            let mut live = HashSet::default();
            for (i, event) in events.iter().enumerate() {
                let key = match &event {
                    ConcolicEvent::PathConstraint {
                        location, taken, ..
                    } => (*location, *taken),
                    _ => (event.location(), false),
                };
                location_idxs.entry(key).or_default().push(i);
            }

            for ids in location_idxs.values() {
                if ids.len() <= 16 {
                    for &i in ids {
                        live.insert(i);
                    }
                } else {
                    for &i in &ids[..8] {
                        live.insert(i);
                    }
                    // for &i in &ids[ids.len() - 8..] {
                    //     live.insert(i);
                    // }
                }
            }

            events
                .iter()
                .enumerate()
                .filter(|(i, _v)| live.contains(i))
                .map(|(_i, v)| v.clone())
                .collect()
        }
    }

    pub(crate) fn compact_to_trace(&self, input: &[u8]) -> ConcolicTrace {
        let mut events = Self::deduplicate_events_by_location(&self.events);
        let events_by_location = events.iter().enumerate().fold(
            HashMap::<Location, Vec<usize>>::default(),
            |mut acc, (i, v)| {
                acc.entry(v.location()).or_default().push(i);
                acc
            },
        );

        let mut symvals = Symvals::new(false);
        let mut mapping: HashMap<SymVal, SymValRef> = HashMap::default();
        let mut light_cache: HashMap<SymValRef, SymValRef> = HashMap::default();

        // #[decurse::decurse_unsound]
        fn map_val_(
            r: SymValRef,
            src_symvals: &Symvals,
            dst_symvals: &mut Symvals,
            full_cache: &mut HashMap<SymVal, SymValRef>,
            light_cache: &mut HashMap<SymValRef, SymValRef>,
        ) -> SymValRef {
            if let Some(x) = light_cache.get(&r) {
                return *x;
            }
            let mut symval = src_symvals.fetch(r);
            for subref in symval.refs_mut() {
                *subref = map_val_(*subref, src_symvals, dst_symvals, full_cache, light_cache);
            }
            let res = *full_cache
                .entry(symval.clone())
                .or_insert_with(move || dst_symvals.store(symval, 0));
            light_cache.insert(r, res);
            res
        }

        let mut map_val = |r: &mut SymValRef| {
            *r = map_val_(
                *r,
                &self.symvals,
                &mut symvals,
                &mut mapping,
                &mut light_cache,
            );
        };

        for el in &mut events {
            match el {
                ConcolicEvent::PathConstraint {
                    location: _,
                    condition,
                    taken: _,
                } => {
                    map_val(condition);
                }
                ConcolicEvent::MemoryConstraint {
                    location: _,
                    address: _,
                    purpose: _,
                    sym,
                } => {
                    map_val(sym);
                }
                ConcolicEvent::TryAlternative {
                    location: _,
                    concrete,
                    symbolic,
                    interesting: _,
                } => {
                    map_val(concrete);
                    map_val(symbolic);
                }
                ConcolicEvent::TrySolveMemcmp { location: _, pairs } => {
                    for (a, b) in pairs {
                        map_val(a);
                        map_val(b);
                    }
                }
                ConcolicEvent::TrySolveStrcmplike {
                    location: _,
                    symvals,
                    reference: _,
                    ignorecase: _,
                } => {
                    for val in symvals {
                        map_val(val);
                    }
                }
            }
        }
        /*
        println!(
            "symvals compact: {} -> {}",
            humansize::format_size(self.symvals.byte_len(), humansize::DECIMAL),
            humansize::format_size(symvals.byte_len(), humansize::DECIMAL)
        );
        */

        // #[decurse::decurse_unsound]
        fn symval_inputs(
            r: SymValRef,
            symvals: &Symvals,
            cache: &mut HashMap<SymValRef, BitVec>,
            input_len: usize,
        ) -> BitVec {
            if let Some(x) = cache.get(&r) {
                return x.clone();
            }
            let mut res = BitVec::repeat(false, input_len);
            let symval = symvals.fetch(r);
            if let SymVal::InputByte(x) = symval {
                res.set(x as usize, true);
                return res;
            }
            for subref in symval.refs() {
                res |= symval_inputs(subref, symvals, cache, input_len);
            }
            cache.insert(r, res.clone());
            res
        }

        let mut inputs_cache = HashMap::default();
        let event_inputs = events
            .iter()
            .map(|event| {
                let mut res = BitVec::repeat(false, input.len());
                for symref in event.symrefs() {
                    res |= symval_inputs(symref, &symvals, &mut inputs_cache, input.len());
                }
                res
            })
            .collect();

        ConcolicTrace {
            events,
            event_inputs,
            events_by_location,
            input: input.to_vec(),
            symvals,
        }
    }
}

#[derive(Clone)]
pub(crate) struct ConcolicTrace {
    pub input: Vec<u8>,
    pub symvals: Symvals,
    pub events: Vec<ConcolicEvent>,
    pub event_inputs: Vec<BitVec>,
    pub events_by_location: HashMap<Location, Vec<usize>>,
}
