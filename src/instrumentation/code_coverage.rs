use bitvec::prelude::*;
use cranelift::codegen::ir::{InstBuilder, MemFlagsData, types::I32};

use crate::{
    ir::{Location, ModuleSpec},
    jit::CompilationKind,
};

use super::{CodeCovInstrumentationPass, Edge, FuncIdx, InstrCtx};

pub(crate) struct CoverageBitset<K: Ord + Clone> {
    pub keys: Box<[K]>,
    pub entries: BitBox,
    pub saved: BitBox,
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
        tracy_full::zone!("CoverageBitset::update_and_scan");
        super::union_bitboxes(&mut self.saved, &self.entries)
    }

    pub fn reset(&mut self) {
        self.entries.fill(false);
        self.saved.fill(false);
    }

    pub fn reset_keep_saved(&mut self) {
        self.entries.fill(false);
    }

    fn instrument<P: CodeCovInstrumentationPass>(&self, key: &K, ctx: InstrCtx, _pass: &P) {
        let Ok(index) = self.keys.binary_search(key) else {
            return;
        };

        let elem_bitptr = self.entries.get(index).unwrap().into_bitptr();
        let elem_offset =
            elem_bitptr.pointer() as usize - self.entries.as_bitptr().pointer() as usize;
        // Bit number within the little-endian storage (bit `b` lives in byte
        // `b / 8`, bit `b % 8`, whatever the storage element size).
        let bit = elem_offset * 8 + elem_bitptr.bit().into_inner() as usize;
        // Set it with a 32-bit `or` on the aligned u32 that holds it: x64 only
        // fuses load+op+store into one `or mem, imm` for 32/64-bit types, an
        // i8 update stays load/or/store. The storage is usize words, so the
        // aligned u32 is in bounds; the other 31 bits are or-ed with zero.
        let entry_offset: i32 = ((bit / 32) * 4).try_into().unwrap();
        let entry_mask: u32 = 1 << (bit % 32);
        let entries_ptr = ctx
            .state
            .host_ptr(ctx.bcx, self.entries.as_bitptr().pointer());

        if ctx.state.options.kind == CompilationKind::Reusable {
            let val = ctx.bcx.ins().load(
                I32,
                MemFlagsData::trusted(),
                entries_ptr,
                entry_offset,
            );
            let val = ctx.bcx.ins().bor_imm_u(val, entry_mask as i64);
            ctx.bcx
                .ins()
                .store(MemFlagsData::trusted(), val, entries_ptr, entry_offset);
        }
    }

    pub(crate) fn iter_covered_keys(&self) -> impl Iterator<Item = K> + '_ {
        self.saved.iter_ones().map(|i| self.keys[i].clone())
    }

    #[allow(unused)]
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
    fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: CoverageBitset::new(
                &super::iter_edges(spec)
                    .filter(|x| {
                        key_filter(&Location {
                            function: x.function,
                            index: x.from.0,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
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
    fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: CoverageBitset::new(
                &super::iter_funcs(spec)
                    .filter(|x| {
                        key_filter(&Location {
                            function: x.0,
                            index: 0,
                        })
                    })
                    .collect::<Vec<_>>(),
            ),
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

    fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        Self {
            coverage: CoverageBitset::new(
                &super::iter_bbs(spec).filter(key_filter).collect::<Vec<_>>(),
            ),
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
