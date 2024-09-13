use bitvec::prelude::*;
use cranelift::codegen::ir::{types::I8, InstBuilder, MemFlags};

use crate::{
    ir::{Location, ModuleSpec},
    jit::CompilationKind,
};

use super::{CodeCovInstrumentationPass, Edge, FuncIdx, InstrCtx};

pub(crate) struct CoverageBitset<K: Ord + Clone> {
    keys: Box<[K]>,
    entries: BitBox,
    saved: BitBox,
}
impl<K: Ord + Clone> CoverageBitset<K> {
    pub fn new(keys: &[K]) -> Self {
        let mut keys = keys.to_vec();
        keys.sort();
        debug_assert!(
            keys.windows(2).all(|x| x[1] > x[0]),
            "found duplicate keys in AssociatedCoverageArray"
        );
        let keys = keys.into_boxed_slice();
        let entries = BitVec::repeat(false, keys.len()).into_boxed_bitslice();
        let saved = BitVec::repeat(false, keys.len()).into_boxed_bitslice();
        Self {
            keys,
            entries,
            saved,
        }
    }

    pub fn update_and_scan(&mut self) -> bool {
        let is_update = self
            .entries
            .domain()
            .zip(self.saved.domain())
            .any(|(e, s)| (e & !s) != 0);
        if is_update {
            self.saved |= &self.entries;
        }
        is_update
    }

    pub fn reset(&mut self) {
        self.entries.fill(false);
        self.saved.fill(false);
    }

    fn instrument<P: CodeCovInstrumentationPass>(&self, key: &K, ctx: InstrCtx, _pass: &P) {
        let Ok(index) = self.keys.binary_search(key) else {
            return;
        };

        let elem_bitptr = self.entries.get(index).unwrap().into_bitptr();
        let mut entry_mask: usize = elem_bitptr.bit().mask::<Lsb0>().into_inner();
        let entry_offset =
            elem_bitptr.pointer() as usize - self.entries.as_bitptr().pointer() as usize;
        let mut entry_offset: i32 = entry_offset.try_into().unwrap();
        while entry_mask & 0xff == 0 {
            entry_mask >>= 8;
            entry_offset += 1;
        }
        let entries_ptr = ctx
            .state
            .host_ptr(ctx.bcx, self.entries.as_bitptr().pointer());

        if ctx.state.options.kind == CompilationKind::Reusable {
            let val = ctx.bcx.ins().load(
                // Note: We're handling offsetting into the usize-sized
                // elements explicitly above in order to keep the mask
                // immediate size down.
                I8,
                MemFlags::trusted(),
                entries_ptr,
                entry_offset,
            );
            let val = ctx.bcx.ins().bor_imm(val, entry_mask as i64);
            ctx.bcx
                .ins()
                .store(MemFlags::trusted(), val, entries_ptr, entry_offset);
        }
    }

    pub(crate) fn iter_covered_keys(&self) -> impl Iterator<Item = K> + '_ {
        self.saved.iter_ones().map(|i| self.keys[i].clone())
    }

    pub(crate) fn saved_val(&self, key: &K) -> bool {
        let index = self.keys.binary_search(key).unwrap();
        self.saved[index]
    }
}

pub(crate) struct EdgeCoveragePass {
    pub coverage: CoverageBitset<Edge>,
}

impl CodeCovInstrumentationPass for EdgeCoveragePass {
    type Key = Edge;
    fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: CoverageBitset::new(&super::iter_edges(spec).collect::<Vec<_>>()),
        }
    }

    fn shortcode(&self) -> &'static str {
        "edges"
    }

    fn instrument_edge(&self, edge: Edge, ctx: InstrCtx) {
        self.coverage.instrument(&edge, ctx, self);
    }

    fn coverage(&self) -> &CoverageBitset<Self::Key> {
        &self.coverage
    }

    fn coverage_mut(&mut self) -> &mut CoverageBitset<Self::Key> {
        &mut self.coverage
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

pub(crate) struct FunctionCoveragePass {
    pub coverage: CoverageBitset<FuncIdx>,
}

impl CodeCovInstrumentationPass for FunctionCoveragePass {
    type Key = FuncIdx;
    fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: CoverageBitset::new(&super::iter_funcs(spec).collect::<Vec<_>>()),
        }
    }

    fn shortcode(&self) -> &'static str {
        "funcs"
    }

    fn coverage(&self) -> &CoverageBitset<Self::Key> {
        &self.coverage
    }

    fn coverage_mut(&mut self) -> &mut CoverageBitset<Self::Key> {
        &mut self.coverage
    }

    fn instrument_function(&self, ctx: InstrCtx) {
        self.coverage
            .instrument(&FuncIdx(ctx.state.fidx), ctx, self);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

pub(crate) struct BBCoveragePass {
    pub coverage: CoverageBitset<Location>,
}

impl CodeCovInstrumentationPass for BBCoveragePass {
    type Key = Location;

    fn new(spec: &ModuleSpec) -> Self {
        Self {
            coverage: CoverageBitset::new(&super::iter_bbs(spec).collect::<Vec<_>>()),
        }
    }

    fn shortcode(&self) -> &'static str {
        "bbs"
    }

    fn coverage(&self) -> &CoverageBitset<Self::Key> {
        &self.coverage
    }

    fn coverage_mut(&mut self) -> &mut CoverageBitset<Self::Key> {
        &mut self.coverage
    }

    fn instrument_basic_block(&self, ctx: InstrCtx) {
        self.coverage.instrument(&ctx.state.loc(), ctx, self);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}
