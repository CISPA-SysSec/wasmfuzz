use std::{
    any::Any,
    hash::{DefaultHasher, Hash, Hasher},
};

use cranelift::codegen::ir;
use cranelift::prelude::*;

use crate::{
    ir::{InsnIdx, Location, ModuleSpec},
    jit::{CompilationKind, FuncTranslator},
};

mod feedback_lattice;
pub(crate) use feedback_lattice::{FeedbackLattice, FeedbackLatticeCodegen};

mod call_params;
mod cmpcov;
mod code_coverage;
mod input_size;
mod instruction_limit;
mod mem;
mod path_hash;
mod perffuzz;
mod swarm;
mod traits;
pub(crate) use traits::*;

pub(crate) use call_params::*;
pub(crate) use cmpcov::*;
pub(crate) use code_coverage::*;
pub(crate) use input_size::*;
pub(crate) use instruction_limit::*;
pub(crate) use mem::*;
pub(crate) use path_hash::*;
pub(crate) use perffuzz::*;
pub(crate) use swarm::*;

/* Why do we need this?
We previously implemented ErasedInstrumentation for T: KVInstrumentationPass directly, but that breaks down with a second generic impl:

impl<K, V: FeedbackLattice, T> ErasedInstrumentationPass for T
where
    K: Ord + Clone,
    T: KVInstrumentationPass<Key = K, Value = V> + 'static,
{ ... }

error[E0119]: conflicting implementations of trait `traits::ErasedInstrumentationPass`
   --> src/instrumentation/traits.rs:238:1
    |
238 | / impl<K, V: FeedbackLattice, T> ErasedInstrumentationPass for T
239 | | where
240 | |     K: Ord + Clone,
241 | |     T: KVInstrumentationPass<Key = K, Value = V> + 'static,
    | |___________________________________________________________^ conflicting implementation
    |
   ::: src/instrumentation/code_coverage.rs:108:1
    |
108 | / impl<K: Ord + Clone, T: CodeCovInstrumentationPass<Key = K> + 'static> ErasedInstrumentationPass
109 | |     for T
    | |_________- first implementation here

I'm not sure if there's a way to convince rustc that these types do not overlap. Negative trait bounds might work, but that's not stable yet.
Instead, we explicitly delegate calls based on a helper enum:
*/
enum ErasedInstrumentationPassHelper<K, V> {
    KV(Box<dyn KVInstrumentationPass<Key = K, Value = V>>),
    CodeCov(Box<dyn CodeCovInstrumentationPass<Key = K>>),
    HashBitset(Box<dyn HashBitsetInstrumentationPass<Key = K>>),
    #[allow(unused)]
    Erased(Box<dyn ErasedInstrumentationPass>),
}
pub struct Passes(pub Vec<Box<dyn ErasedInstrumentationPass>>);

impl Passes {
    pub(crate) fn empty() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn push(&mut self, pass: Box<dyn ErasedInstrumentationPass>) {
        self.0.push(pass);
    }

    pub(crate) fn push_kv<
        K: Ord + Into<Location> + Clone + 'static,
        V: FeedbackLattice + 'static,
        T: KVInstrumentationPass<Key = K, Value = V> + 'static,
    >(
        &mut self,
        pass: T,
    ) {
        let helper = ErasedInstrumentationPassHelper::KV(
            Box::new(pass) as Box<dyn KVInstrumentationPass<Key = K, Value = V>>
        );
        self.push(Box::new(helper) as Box<dyn ErasedInstrumentationPass>)
    }

    // Note: This is a bit of a mess. We specify PassHelper<Value=bool> in order
    // to satisfy the trait implementation bounds.
    pub(crate) fn push_cc<
        K: Ord + Into<Location> + Clone + 'static,
        T: CodeCovInstrumentationPass<Key = K> + 'static,
    >(
        &mut self,
        pass: T,
    ) {
        let helper: ErasedInstrumentationPassHelper<K, bool> =
            ErasedInstrumentationPassHelper::CodeCov(
                Box::new(pass) as Box<dyn CodeCovInstrumentationPass<Key = K>>
            );
        self.push(Box::new(helper) as Box<dyn ErasedInstrumentationPass>)
    }

    // Note: This is a bit of a mess. We specify PassHelper<Value=bool> in order
    // to satisfy the trait implementation bounds.
    pub(crate) fn push_hash<
        K: Ord + Into<Location> + Clone + 'static,
        T: HashBitsetInstrumentationPass<Key = K> + 'static,
    >(
        &mut self,
        pass: T,
    ) {
        let helper: ErasedInstrumentationPassHelper<K, bool> =
            ErasedInstrumentationPassHelper::HashBitset(
                Box::new(pass) as Box<dyn HashBitsetInstrumentationPass<Key = K>>
            );
        self.push(Box::new(helper) as Box<dyn ErasedInstrumentationPass>)
    }

    pub(crate) fn push_erased<T: ErasedInstrumentationPass + 'static>(&mut self, pass: T) {
        let helper: ErasedInstrumentationPassHelper<FuncIdx, bool> =
            ErasedInstrumentationPassHelper::Erased(
                Box::new(pass) as Box<dyn ErasedInstrumentationPass>
            );
        self.push(Box::new(helper) as Box<dyn ErasedInstrumentationPass>)
    }

    pub(crate) fn iter(&self) -> std::slice::Iter<'_, Box<dyn ErasedInstrumentationPass>> {
        self.0.iter()
    }

    pub(crate) fn iter_mut(
        &mut self,
    ) -> std::slice::IterMut<'_, Box<dyn ErasedInstrumentationPass>> {
        self.0.iter_mut()
    }
}

pub struct InstrCtx<'a, 'b, 'c, 'd, 'e> {
    pub bcx: &'a mut cranelift::prelude::FunctionBuilder<'e>,
    pub state: &'d mut FuncTranslator<'b, 'c>,
}

impl InstrCtx<'_, '_, '_, '_, '_> {
    fn instance_meta<K: Hash, V: Default + 'static>(&mut self, key: K) -> &mut V {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let key_u64 = hasher.finish();
        let el = self
            .state
            .pass_meta
            .entry(key_u64)
            .or_insert_with(|| Box::<V>::default() as Box<dyn Any>);
        el.downcast_mut::<V>().unwrap()
    }
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub(crate) struct FuncIdx(pub u32);
impl From<FuncIdx> for Location {
    fn from(value: FuncIdx) -> Self {
        Self {
            function: value.0,
            index: 0,
        }
    }
}

pub(crate) struct AssociatedCoverageArray<K: Ord + Clone, V: FeedbackLattice> {
    keys: Box<[K]>,
    entries: Box<[V]>,
    saved: Box<[V]>,
}
impl<K: Ord + Clone, V: Clone + FeedbackLattice> AssociatedCoverageArray<K, V> {
    pub fn new(keys: &[K]) -> Self {
        let mut keys = keys.to_vec();
        keys.sort();
        debug_assert!(
            keys.windows(2).all(|x| x[1] > x[0]),
            "found duplicate keys in AssociatedCoverageArray"
        );
        let keys = keys.into_boxed_slice();
        let entries = vec![V::bottom(); keys.len()].into_boxed_slice();
        let saved = vec![V::bottom(); keys.len()].into_boxed_slice();
        debug_assert!(!V::bottom().is_extended_by(&V::bottom()));
        debug_assert!(!V::bottom().is_top());
        Self {
            keys,
            entries,
            saved,
        }
    }

    fn val_ptr(&self, key: &K) -> Option<*const V> {
        let index = self.keys.binary_search(key).ok()?;
        Some(&self.entries[index] as *const _)
    }

    pub fn update_and_scan(&mut self) -> bool {
        self.entries
            .iter()
            .zip(self.saved.iter_mut())
            .fold(false, |mut res, (a, b)| {
                res |= b.is_extended_by(a);
                *b = b.unify(a);
                res
            })
    }

    pub fn reset(&mut self) {
        self.entries.fill(V::bottom());
        self.saved.fill(V::bottom());
    }

    pub fn saved_val(&self, key: &K) -> V {
        let index = self.keys.binary_search(key).unwrap();
        self.saved[index].clone()
    }

    pub fn has_key(&self, key: &K) -> bool {
        self.keys.binary_search(key).is_ok()
    }

    #[allow(unused)]
    pub fn iter_entries(&self) -> impl Iterator<Item = (&K, &V)> {
        self.keys.iter().zip(self.entries.iter())
    }
    pub fn iter_saved(&self) -> impl Iterator<Item = (&K, &V)> {
        self.keys.iter().zip(self.saved.iter())
    }
}

impl<K: std::fmt::Debug + Ord + Clone, V: std::fmt::Debug + FeedbackLattice>
    AssociatedCoverageArray<K, V>
{
    #[allow(unused)]
    fn debug_print(&self) {
        eprintln!();
        for ((k, v), prev) in self
            .keys
            .iter()
            .zip(self.entries.iter())
            .zip(self.saved.iter())
        {
            if v.is_bottom() && prev.is_bottom() {
                continue;
            }
            eprintln!("k: {k:>5?}\tentry: {v:>5?}\t(saved: {prev:>5?})");
        }
    }
}

impl<K: Ord + Clone, V: Clone + FeedbackLattice + FeedbackLatticeCodegen>
    AssociatedCoverageArray<K, V>
{
    fn instrument_coverage<P: KVInstrumentationPass>(
        &self,
        key: &K,
        val: ir::Value,
        ctx: InstrCtx,
        _pass: &P,
    ) {
        let Some(slot) = self.val_ptr(key) else {
            return;
        };
        if ctx.state.options.kind == CompilationKind::Reusable {
            // TODO: don't require loading the slot for single-write passes?
            let slot_ptr = ctx.state.host_ptr(ctx.bcx, slot as *const _);
            let prev = ctx.bcx.ins().load(
                <V as FeedbackLatticeCodegen>::cranelift_ty(),
                MemFlags::trusted(),
                slot_ptr,
                0,
            );
            let val = <V as FeedbackLatticeCodegen>::unify(val, prev, ctx.bcx);
            ctx.bcx.ins().store(MemFlags::trusted(), val, slot_ptr, 0);
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub(crate) struct Edge {
    pub(crate) function: u32,
    pub(crate) from: InsnIdx,
    pub(crate) to: InsnIdx,
}
impl Edge {
    pub(crate) fn new(function: u32, from: InsnIdx, to: InsnIdx) -> Self {
        Self { function, from, to }
    }
}
impl From<Edge> for Location {
    fn from(value: Edge) -> Self {
        Self {
            function: value.function,
            index: value.from.0,
        }
    }
}

fn iter_edges(spec: &ModuleSpec) -> impl Iterator<Item = Edge> + '_ {
    spec.functions.iter().flat_map(|func| {
        func.critical_insn_edges.iter().map(|&(from, to)| Edge {
            function: func.idx,
            from,
            to,
        })
    })
}

fn iter_funcs(spec: &ModuleSpec) -> impl Iterator<Item = FuncIdx> + '_ {
    spec.functions.iter().map(|f| FuncIdx(f.idx))
}

fn iter_bbs(spec: &ModuleSpec) -> impl Iterator<Item = Location> + '_ {
    spec.functions.iter().flat_map(|f| {
        f.basic_block_starts.iter().map(|index| Location {
            function: f.idx,
            index: index.0,
        })
    })
}

fn iter_cmp_instrs(spec: &ModuleSpec) -> impl Iterator<Item = Location> + '_ {
    use crate::ir::{NumericInstruction, WFOperator};
    spec.functions.iter().flat_map(|f| {
        f.operators
            .iter()
            .enumerate()
            .filter_map(|(idx, op)| match op {
                WFOperator::Numeric(NumericInstruction::I32RelOp(_))
                | WFOperator::Numeric(NumericInstruction::I64RelOp(_))
                | WFOperator::Numeric(NumericInstruction::F32RelOp(_))
                | WFOperator::Numeric(NumericInstruction::F64RelOp(_))
                | WFOperator::Numeric(NumericInstruction::I32TestOp(_))
                | WFOperator::Numeric(NumericInstruction::I64TestOp(_)) => {
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
