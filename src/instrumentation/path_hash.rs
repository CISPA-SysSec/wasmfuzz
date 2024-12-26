use std::hash::Hash;

use bitvec::{prelude::*, ptr::Mut, slice};
use cranelift::codegen::ir::{self, types::I8, InstBuilder, MemFlags};
use cranelift::module::{DataDescription, DataId, Module};

use crate::jit::vmcontext::VMContext;
use crate::{ir::ModuleSpec, jit::CompilationKind, HashSet};

use super::{Edge, FuncIdx, HashBitsetInstrumentationPass, InstrCtx};

fn hash_to_u64<T: std::hash::Hash>(val: T) -> u64 {
    use std::hash::Hasher;
    // let mut hasher = rustc_hash::FxHasher::default();
    // 0x13371337.hash(&mut hasher); // set initial state
    let mut hasher = std::hash::DefaultHasher::default();
    val.hash(&mut hasher);
    // TODO: figure out why fxhash sucks in this case (see path_cov_test)
    hasher.finish()
}

pub(crate) struct HashBitset {
    pub entries: BitBox,
    pub saved: BitBox,
    pub new_coverage: Box<bool>,
}
impl HashBitset {
    pub fn new_for_elems(count: usize, blowup_factor: usize) -> Self {
        Self::new_with_size(((count + 1) * blowup_factor).next_power_of_two())
    }

    pub fn new_with_size(size: usize) -> Self {
        assert!(size.is_power_of_two());
        let entries = BitVec::repeat(false, size).into_boxed_bitslice();
        Self {
            saved: entries.clone(),
            entries,
            new_coverage: Box::new(false),
        }
    }

    pub fn update_and_scan(&mut self) -> bool {
        let new_cov_hint = *std::mem::take(&mut self.new_coverage);
        new_cov_hint && super::union_bitboxes(&mut self.saved, &self.entries)
    }

    pub fn reset(&mut self) {
        self.entries.fill(false);
        self.saved.fill(false);
    }

    pub fn reset_keep_saved(&mut self) {
        self.entries.fill(false);
    }

    #[allow(unused)]
    fn instrument<P: HashBitsetInstrumentationPass>(
        &self,
        key: ir::Value,
        mut ctx: InstrCtx,
        pass: &P,
    ) {
        // TODO: handle this with a function call?
        let size = self.entries.len();
        debug_assert!(size.is_power_of_two());
        let index = ctx.bcx.ins().band_imm(key, (size - 1) as i64);
        let offset = ctx.bcx.ins().ushr_imm(index, 3);
        let bit = ctx.bcx.ins().band_imm(key, 0b111);
        let one = ctx.bcx.ins().iconst(I8, 1);
        let mask = ctx.bcx.ins().rotl(one, bit);

        let entries_ptr = ctx
            .state
            .host_ptr(ctx.bcx, self.entries.as_bitptr().pointer());
        let entry_ptr = ctx.bcx.ins().iadd(entries_ptr, offset);

        if ctx.state.options.kind == CompilationKind::Reusable {
            let val = ctx.bcx.ins().load(I8, MemFlags::trusted(), entry_ptr, 0);
            let val = ctx.bcx.ins().bor(val, mask);
            ctx.bcx.ins().store(MemFlags::trusted(), val, entry_ptr, 0);
        }
    }

    fn mix_and_instrument<P: HashBitsetInstrumentationPass, V: Hash>(
        &self,
        contrib: V,
        mut ctx: InstrCtx,
        pass: &P,
    ) {
        let data = get_hash_var(pass, &mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let hash_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

        assert!(self.entries.len().is_power_of_two());
        #[no_mangle]
        unsafe extern "C" fn mix_and_update_bitset(
            new_cov: *mut bool,
            hash_ptr: *mut u64,
            bitslice_ptr: *mut usize,
            bitslice_len: u32,
            contribution: u32,
            _: *mut VMContext,
        ) {
            // let new_val = hash_to_u64((*hash_ptr, contribution));
            // let new_val = *hash_ptr ^ contribution as u64;
            // *hash_ptr = new_val;

            // TODO: better gear-style rolling hash?
            // also do something that can squash similar edges in a row?

            // *hash_ptr = (*hash_ptr << 32).wrapping_add(contribution as u64);
            // *hash_ptr = (*hash_ptr << 16) | (contribution as u64 & 0xffff);
            // dbg!(*hash_ptr, contribution);
            *hash_ptr = (*hash_ptr << 8) | (contribution as u64 & 0xff);

            let bitslice_ptr: BitPtr<Mut, usize, Lsb0> = BitPtr::from_mut(&mut *bitslice_ptr);
            let bitslice = slice::from_raw_parts_unchecked_mut(bitslice_ptr, bitslice_len as usize);
            let mask = bitslice.len() - 1;
            // dbg!(new_val, mask, new_val as usize & mask, contribution);
            let index = hash_to_u64(*hash_ptr) as usize;
            if !bitslice[index & mask] {
                // eprintln!("mix_and_instrument: new bit at {:#x}", index & mask);
                *new_cov = true;
                bitslice.set(index & mask, true);
            }

            // clear the hash periodically in a context-sensitive manner in
            // order to get reasonable hitrates
            // *hash_ptr = new_val;
            // if new_val % 2 == 0 {
            //     *hash_ptr = 0;
            // }
        }

        let contrib = hash_to_u64(contrib) as u32 as i64;
        let contrib = ctx.bcx.ins().iconst(ir::types::I32, contrib);

        let new_cov_ptr = pass.coverage().new_coverage.as_ref() as *const _;
        let new_cov_ptr = ctx.state.host_ptr(ctx.bcx, new_cov_ptr as *const _);
        let bitslice_ptr = ctx
            .state
            .host_ptr(ctx.bcx, self.entries.as_bitptr().pointer());
        let bitslice_len = ctx
            .bcx
            .ins()
            .iconst(ir::types::I32, self.entries.len() as i64);

        let _call = ctx.state.host_call(
            ctx.bcx,
            mix_and_update_bitset as unsafe extern "C" fn(_, _, _, _, _, _),
            &[new_cov_ptr, hash_ptr, bitslice_ptr, bitslice_len, contrib],
        );
        // let is_new = ctx.bcx.inst_results(call)[0];

        // TODO: handle trapping
    }
}

fn get_hash_var<P: HashBitsetInstrumentationPass>(pass: &P, ctx: &mut InstrCtx) -> DataId {
    let key = pass.shortcode();
    if ctx.instance_meta::<_, Option<DataId>>(key).is_none() {
        let val = ctx
            .state
            .module
            .declare_anonymous_data(true, false)
            .unwrap();
        let mut data_desc = DataDescription::new();
        data_desc.define_zeroinit(std::mem::size_of::<u64>());
        data_desc.set_align(std::mem::align_of::<u64>() as _);
        ctx.state.module.define_data(val, &data_desc).unwrap();
        *ctx.instance_meta::<_, Option<DataId>>(key).insert(val)
    } else {
        ctx.instance_meta::<_, Option<DataId>>(key).unwrap()
    }
}

fn instrument_trampoline<P: HashBitsetInstrumentationPass>(pass: &P, mut ctx: InstrCtx) {
    let data = get_hash_var(pass, &mut ctx);

    let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
    let buffer = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

    ctx.bcx.emit_small_memset(
        ctx.state.module.target_config(),
        buffer,
        0,
        std::mem::size_of::<u64>() as _,
        std::mem::align_of::<u64>() as _,
        MemFlags::trusted(),
    );

    let new_cov_ptr = pass.coverage().new_coverage.as_ref() as *const _;
    let new_cov_ptr = ctx.state.host_ptr(ctx.bcx, new_cov_ptr as *const _);
    let zero = ctx.bcx.ins().iconst(ir::types::I8, 0);
    ctx.bcx
        .ins()
        .store(MemFlags::trusted(), zero, new_cov_ptr, 0);
}

pub(crate) struct FuncPathHashPass {
    pub coverage: HashBitset,
    pub keys: HashSet<FuncIdx>,
}

impl FuncPathHashPass {
    pub fn new(spec: &ModuleSpec) -> Self {
        let keys = super::iter_funcs(spec).collect::<HashSet<_>>();
        Self {
            coverage: HashBitset::new_for_elems(keys.len(), 1024),
            keys,
        }
    }
}

impl HashBitsetInstrumentationPass for FuncPathHashPass {
    type Key = FuncIdx;

    fn shortcode(&self) -> &'static str {
        "func-path-hash"
    }

    fn coverage(&self) -> &HashBitset {
        &self.coverage
    }

    fn coverage_mut(&mut self) -> &mut HashBitset {
        &mut self.coverage
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(self, ctx);
    }

    fn instrument_function(&self, ctx: InstrCtx) {
        let key = FuncIdx(ctx.state.fidx);
        if !self.keys.contains(&key) {
            return;
        }
        self.coverage.mix_and_instrument(key, ctx, self);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

pub(crate) struct EdgePathHashPass {
    pub coverage: HashBitset,
    pub keys: HashSet<Edge>,
}

impl EdgePathHashPass {
    pub fn new(spec: &ModuleSpec) -> Self {
        let keys = super::iter_edges(spec).collect::<HashSet<_>>();
        Self {
            coverage: HashBitset::new_for_elems(keys.len(), 1024),
            keys,
        }
    }
}

impl HashBitsetInstrumentationPass for EdgePathHashPass {
    type Key = Edge;

    fn shortcode(&self) -> &'static str {
        "edge-path-hash"
    }

    fn coverage(&self) -> &HashBitset {
        &self.coverage
    }

    fn coverage_mut(&mut self) -> &mut HashBitset {
        &mut self.coverage
    }

    fn instrument_trampoline(&self, ctx: InstrCtx) {
        instrument_trampoline(self, ctx);
    }

    fn instrument_edge(&self, key: Edge, ctx: InstrCtx) {
        if !self.keys.contains(&key) {
            return;
        }
        self.coverage.mix_and_instrument(key, ctx, self);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}
