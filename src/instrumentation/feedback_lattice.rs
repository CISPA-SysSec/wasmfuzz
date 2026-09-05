use cranelift::codegen::ir::{self, InstBuilder, MemFlagsData, Value};
use cranelift::prelude::FunctionBuilder;

use crate::jit::CompilationKind;
use crate::jit::vmcontext::VMContext;

use super::{AssociatedCoverageArray, InstrCtx, KVInstrumentationPass};

pub(crate) trait FeedbackLattice: PartialEq + Eq + Clone {
    /// Does `other` contain novel progress compared to self?
    /// As a lattice operation: Is other either incomparable or greater than `self`?
    ///
    /// `is_extended_by` corresponds to `a.unify(b) != a`.
    fn is_extended_by(&self, other: &Self) -> bool;
    /// Combine feedback from `self` and `other`. (lattice join)
    #[must_use]
    fn unify(&self, other: &Self) -> Self;
    fn bottom() -> Self;
    fn is_top(&self) -> bool;
    fn is_bottom(&self) -> bool {
        self == &Self::bottom()
    }

    /// Represent this value's "score". Used to quantify feedback progression.
    // should satisfy:
    // a.is_extended_by(b) =>
    // a.as_linear_score() < a.unify(b).as_linear_score()
    #[expect(unused)]
    fn as_linear_score(&self) -> Option<u64> {
        None
    }
}

pub(crate) trait FeedbackLatticeCodegen {
    fn unify(v1: ir::Value, v2: ir::Value, bcx: &mut FunctionBuilder) -> ir::Value;
    fn cranelift_ty() -> ir::Type;
}

impl FeedbackLattice for bool {
    fn is_extended_by(&self, other: &Self) -> bool {
        other > self
    }
    fn unify(&self, other: &Self) -> Self {
        *self || *other
    }
    fn as_linear_score(&self) -> Option<u64> {
        Some(*self as u64)
    }
    fn bottom() -> Self {
        false
    }
    fn is_top(&self) -> bool {
        *self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct ValueRange {
    pub low: u64,
    pub high: u64,
}

impl FeedbackLattice for ValueRange {
    fn is_extended_by(&self, other: &Self) -> bool {
        other.low < self.low || other.high > self.high
    }
    fn unify(&self, other: &Self) -> Self {
        Self {
            low: self.low.min(other.low),
            high: self.high.max(other.high),
        }
    }
    fn as_linear_score(&self) -> Option<u64> {
        Some(self.high.saturating_sub(self.low))
    }
    fn bottom() -> Self {
        Self {
            low: u64::MAX,
            high: u64::MIN,
        }
    }
    fn is_top(&self) -> bool {
        self.low == u64::MIN && self.high == u64::MAX
    }
}

impl<K: Ord + Clone> AssociatedCoverageArray<K, ValueRange> {
    pub(crate) fn instrument_range<P: KVInstrumentationPass>(
        &self,
        key: &K,
        mut val: Value,
        ty: ir::Type,
        ctx: &mut InstrCtx,
        _pass: &P,
    ) {
        let Some(slot) = self.val_ptr(key) else {
            return;
        };

        val = match ty {
            ir::types::F32 | ir::types::F64 => ctx.bcx.ins().fcvt_to_uint_sat(ir::types::I64, val),
            ir::types::I64 => val,
            _ => ctx.bcx.ins().uextend(ir::types::I64, val),
        };

        if ctx.state.options.kind == CompilationKind::Reusable {
            let slot_ptr = ctx.state.host_ptr(ctx.bcx, slot as *const _);
            let prev_low = ctx
                .bcx
                .ins()
                .load(ir::types::I64, MemFlagsData::trusted(), slot_ptr, 0);
            let prev_high = ctx
                .bcx
                .ins()
                .load(ir::types::I64, MemFlagsData::trusted(), slot_ptr, 8);
            let low = ctx.bcx.ins().umin(val, prev_low);
            let high = ctx.bcx.ins().umax(val, prev_high);
            ctx.bcx.ins().store(MemFlagsData::trusted(), low, slot_ptr, 0);
            ctx.bcx.ins().store(MemFlagsData::trusted(), high, slot_ptr, 8);
        }
    }
}

use std::cmp::Ordering;
use std::iter::Peekable;
use std::ops::Deref;

struct MergeAscendingDedup<L, R>
where
    L: Iterator<Item = R::Item>,
    R: Iterator,
{
    left: Peekable<L>,
    right: Peekable<R>,
}

impl<L, R> MergeAscendingDedup<L, R>
where
    L: Iterator<Item = R::Item>,
    R: Iterator,
{
    fn new(left: L, right: R) -> Self {
        Self {
            left: left.peekable(),
            right: right.peekable(),
        }
    }
}

impl<L, R> Iterator for MergeAscendingDedup<L, R>
where
    L: Iterator<Item = R::Item>,
    R: Iterator,
    L::Item: Ord,
{
    type Item = L::Item;

    fn next(&mut self) -> Option<L::Item> {
        let which = match (self.left.peek(), self.right.peek()) {
            (Some(l), Some(r)) => l.cmp(r),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => return None,
        };

        match which {
            Ordering::Less => self.left.next(),
            Ordering::Equal => {
                self.left.next();
                self.right.next()
            }
            Ordering::Greater => self.right.next(),
        }
    }
}

/// A set of up to `N` distinct values. Sets that would grow past `N` collapse
/// into `top` ("we've seen too many values here to keep track").
// invariants:
// - `elems[..size]` is sorted and duplicate-free
// - `elems[size..]` is zeroed, so that derived `PartialEq` is set equality
// - `top` is canonical (`size == N + 1`, `elems` zeroed) so that all `top`s
//   compare equal
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct ValueSet<const N: usize> {
    pub size: usize,
    // invariant: these are sorted
    pub elems: [u64; N],
}

impl<const N: usize> ValueSet<N> {
    fn top() -> Self {
        Self {
            size: N + 1,
            elems: [0; N],
        }
    }
    fn elems(&self) -> &[u64] {
        debug_assert!(!self.is_top());
        &self.elems[..self.size]
    }
    #[cfg_attr(not(test), expect(unused))]
    fn contains(&self, el: u64) -> bool {
        self.is_top() || self.elems().binary_search(&el).is_ok()
    }
    fn insert(&mut self, el: u64) {
        if self.is_top() {
            return;
        }
        let Err(pos) = self.elems().binary_search(&el) else {
            return;
        };
        // NB: ^ This is equivalent to if self.contains(el) { return; }
        if self.size == N {
            *self = Self::top();
            return;
        }
        self.elems.copy_within(pos..self.size, pos + 1);
        self.elems[pos] = el;
        self.size += 1;
    }
}

impl<const N: usize> FeedbackLattice for ValueSet<N> {
    fn is_extended_by(&self, other: &Self) -> bool {
        // TODO(perf): check this without constructing a new array?
        self.unify(other).size > self.size
    }
    fn unify(&self, other: &Self) -> Self {
        if self.is_top() || other.is_top() {
            return Self::top();
        }
        let mut elems = [0; N];
        let mut size = 0;

        for &el in MergeAscendingDedup::new(self.elems().iter(), other.elems().iter()) {
            if size == N {
                // the union doesn't fit into our fixed-size buffer
                return Self::top();
            }
            elems[size] = el;
            size += 1;
        }
        Self { size, elems }
    }
    fn bottom() -> Self {
        Self {
            size: 0,
            elems: [0; N],
        }
    }
    fn is_top(&self) -> bool {
        self.size > N
    }
}

impl<const N: usize, K: Ord + Clone> AssociatedCoverageArray<K, ValueSet<N>> {
    pub(crate) fn instrument_set<P: KVInstrumentationPass>(
        &self,
        key: &K,
        mut val: Value,
        ty: ir::Type,
        ctx: &mut InstrCtx,
        _pass: &P,
    ) {
        let Some(slot) = self.val_ptr(key) else {
            return;
        };

        unsafe extern "C" fn set_insert_elem<const N: usize>(
            valset: *mut ValueSet<N>,
            elem: u64,
            _vmctx: *mut VMContext,
        ) {
            let valset = unsafe { &mut *valset };
            valset.insert(elem);
        }

        match ty {
            ir::types::F32 => {
                val = ctx.bcx.ins().bitcast(ir::types::I32, MemFlagsData::new(), val);
                val = ctx.bcx.ins().uextend(ir::types::I64, val);
            }
            ir::types::F64 => {
                val = ctx.bcx.ins().bitcast(ir::types::I64, MemFlagsData::new(), val);
            }
            ir::types::I64 => {}
            _ => val = ctx.bcx.ins().uextend(ir::types::I64, val),
        };

        if ctx.state.options.kind == CompilationKind::Reusable {
            let slot_ptr = ctx.state.host_ptr(ctx.bcx, slot as *const _);
            ctx.state.host_call_with_types(
                ctx.bcx,
                set_insert_elem::<N> as *const fn(),
                &[ctx.state.ptr_ty(), ir::types::I64],
                &[],
                &[slot_ptr, val],
            );
        }
    }
}

pub(crate) trait FLInteger: Copy + Clone + Eq + Ord + std::ops::Add + std::ops::Sub {
    fn zero() -> Self;
    fn max() -> Self;
    fn cranelift_ty() -> ir::Type;
    #[allow(unused)]
    fn as_u64(&self) -> u64;
}

macro_rules! impl_flint {
    ($ty:ty, $cranelift_ty:expr) => {
        impl FLInteger for $ty {
            fn zero() -> Self {
                0
            }
            fn max() -> Self {
                <$ty>::MAX
            }
            fn cranelift_ty() -> ir::Type {
                $cranelift_ty
            }
            fn as_u64(&self) -> u64 {
                *self as u64
            }
        }
    };
}

impl_flint!(u8, ir::types::I8);
impl_flint!(u16, ir::types::I16);
impl_flint!(u32, ir::types::I32);
impl_flint!(u64, ir::types::I64);

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct Maximize<T: FLInteger>(pub T);
impl<T: FLInteger> FeedbackLattice for Maximize<T> {
    fn is_extended_by(&self, other: &Self) -> bool {
        other.0 > self.0
    }
    fn unify(&self, other: &Self) -> Self {
        Self(self.0.max(other.0))
    }
    fn as_linear_score(&self) -> Option<u64> {
        Some(self.0.as_u64())
    }
    fn bottom() -> Self {
        Self(<T as FLInteger>::zero())
    }
    fn is_top(&self) -> bool {
        self.0 == <T as FLInteger>::max()
    }
}

impl<T: FLInteger> FeedbackLatticeCodegen for Maximize<T> {
    fn unify(v1: ir::Value, v2: ir::Value, bcx: &mut FunctionBuilder) -> ir::Value {
        bcx.ins().umax(v1, v2)
    }

    fn cranelift_ty() -> ir::Type {
        <T as FLInteger>::cranelift_ty()
    }
}
impl<T: FLInteger> Deref for Maximize<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(transparent)]
pub(crate) struct Minimize<T: FLInteger>(T);
impl<T: FLInteger> FeedbackLattice for Minimize<T> {
    fn is_extended_by(&self, other: &Self) -> bool {
        other.0 < self.0
    }
    fn unify(&self, other: &Self) -> Self {
        Self(self.0.min(other.0))
    }
    fn as_linear_score(&self) -> Option<u64> {
        Some(<T as FLInteger>::max().as_u64() - self.0.as_u64())
    }
    fn bottom() -> Self {
        Self(<T as FLInteger>::max())
    }
    fn is_top(&self) -> bool {
        self.0 == <T as FLInteger>::zero()
    }
}

impl<T: FLInteger> FeedbackLatticeCodegen for Minimize<T> {
    fn unify(v1: ir::Value, v2: ir::Value, bcx: &mut FunctionBuilder) -> ir::Value {
        bcx.ins().umin(v1, v2)
    }

    fn cranelift_ty() -> ir::Type {
        <T as FLInteger>::cranelift_ty()
    }
}

impl<T: FLInteger> Deref for Minimize<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{FeedbackLattice, ValueSet};

    fn set<const N: usize>(vals: &[u64]) -> ValueSet<N> {
        let mut res = ValueSet::<N>::bottom();
        for &val in vals {
            res.insert(val);
        }
        res
    }

    #[test]
    fn test_valueset_insert() {
        let empty = set::<4>(&[]);
        assert!(empty.is_bottom());
        assert!(!empty.is_top());
        assert!(empty.elems().is_empty());

        // duplicates collapse, elements end up sorted
        assert_eq!(set::<4>(&[7, 7, 7]).elems(), &[7]);
        assert_eq!(set::<4>(&[4, 1, 3, 1, 2, 4]).elems(), &[1, 2, 3, 4]);

        // exactly N fits, N+1 doesn't
        let full = set::<4>(&[4, 3, 2, 1]);
        assert_eq!(full.size, 4);
        assert!(!full.is_top());
        assert!(set::<4>(&[1, 2, 3, 4, 5]).is_top());

        // ... and every way of overflowing gives the same `top`
        assert_eq!(set::<4>(&[1, 2, 3, 4, 5]), set::<4>(&[9, 8, 7, 6, 5]));
        // inserting into `top` keeps it there
        let mut top = set::<4>(&[1, 2, 3, 4, 5]);
        top.insert(1);
        assert!(top.is_top());
    }

    #[test]
    fn test_valueset_contains() {
        let s = set::<4>(&[3, 1]);
        assert!(s.contains(1));
        assert!(s.contains(3));
        assert!(!s.contains(2));
        // `top` stands for "some set we lost track of", so it contains anything
        assert!(set::<4>(&[1, 2, 3, 4, 5]).contains(1234));
    }

    #[test]
    fn test_valueset_unify() {
        // disjoint, still fits
        assert_eq!(set::<4>(&[1, 2]).unify(&set(&[3, 4])), set(&[1, 2, 3, 4]));
        // overlapping elements are only counted once
        assert_eq!(
            set::<4>(&[1, 2, 3]).unify(&set(&[2, 3, 4])),
            set(&[1, 2, 3, 4])
        );
        // the union is what has to fit, not the operands
        assert!(set::<4>(&[1, 2, 3]).unify(&set(&[4, 5])).is_top());
        // `top` swallows everything, from either side
        let top = set::<4>(&[1, 2, 3, 4, 5]);
        assert!(top.unify(&set(&[1])).is_top());
        assert!(set::<4>(&[1]).unify(&top).is_top());
        assert!(top.unify(&ValueSet::bottom()).is_top());
    }

    #[test]
    fn test_valueset_lattice_laws() {
        let samples: Vec<ValueSet<4>> = vec![
            set(&[]),
            set(&[1]),
            set(&[1, 2]),
            set(&[2, 3]),
            set(&[3, 4, 5]),
            set(&[1, 2, 3, 4]),
            set(&[1, 2, 3, 4, 5]),
        ];
        let bottom = ValueSet::<4>::bottom();
        for a in &samples {
            assert_eq!(a.unify(&bottom), *a, "identity");
            assert_eq!(a.unify(a), *a, "idempotence");
            assert!(!a.is_extended_by(a));
            for b in &samples {
                assert_eq!(a.unify(b), b.unify(a), "commutativity");
                // documented on the trait: `is_extended_by` <=> `a.unify(b) != a`
                assert_eq!(a.is_extended_by(b), a.unify(b) != *a);
                for c in &samples {
                    assert_eq!(a.unify(b).unify(c), a.unify(&b.unify(c)), "associativity");
                }
            }
        }
    }
}
