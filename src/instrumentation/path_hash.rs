use std::hash::Hash;

use bitvec::{prelude::*, ptr::Mut, slice};
use cranelift::codegen::ir::{self, InstBuilder, MemFlagsData, types::I8};
use cranelift::module::{DataDescription, DataId, Module};

use crate::jit::vmcontext::VMContext;
use crate::{HashSet, ir::ModuleSpec, jit::CompilationKind};

use super::{Edge, FuncIdx, HashBitsetInstrumentationPass, InstrCtx, Location};

fn hash_to_u64<T: std::hash::Hash>(val: T) -> u64 {
    use std::hash::Hasher;
    // let mut hasher = rustc_hash::FxHasher::default();
    // 0x13371337.hash(&mut hasher); // set initial state
    let mut hasher = std::hash::DefaultHasher::default();
    val.hash(&mut hasher);
    // TODO: figure out why fxhash sucks in this case (see path_cov_test)
    hasher.finish()
}

// SipHash-1-3 with zero keys of one u64 (what `hash_to_u64::<u64>` computes
// with std's `DefaultHasher`), as straight-line code. `sip13_u64_ref` is the
// host mirror the tests compare against.
const SIP_INIT: [u64; 4] = [
    0x736f6d6570736575,
    0x646f72616e646f6d,
    0x6c7967656e657261,
    0x7465646279746573,
];

fn sip13_u64(bcx: &mut cranelift::frontend::FunctionBuilder, m: ir::Value) -> ir::Value {
    let c = |bcx: &mut cranelift::frontend::FunctionBuilder, x: u64| {
        bcx.ins().iconst(ir::types::I64, x as i64)
    };
    let mut v = SIP_INIT.map(|x| c(bcx, x));
    fn round(bcx: &mut cranelift::frontend::FunctionBuilder, v: &mut [ir::Value; 4]) {
        v[0] = bcx.ins().iadd(v[0], v[1]);
        v[1] = bcx.ins().rotl_imm_u(v[1], 13);
        v[1] = bcx.ins().bxor(v[1], v[0]);
        v[0] = bcx.ins().rotl_imm_u(v[0], 32);
        v[2] = bcx.ins().iadd(v[2], v[3]);
        v[3] = bcx.ins().rotl_imm_u(v[3], 16);
        v[3] = bcx.ins().bxor(v[3], v[2]);
        v[0] = bcx.ins().iadd(v[0], v[3]);
        v[3] = bcx.ins().rotl_imm_u(v[3], 21);
        v[3] = bcx.ins().bxor(v[3], v[0]);
        v[2] = bcx.ins().iadd(v[2], v[1]);
        v[1] = bcx.ins().rotl_imm_u(v[1], 17);
        v[1] = bcx.ins().bxor(v[1], v[2]);
        v[2] = bcx.ins().rotl_imm_u(v[2], 32);
    }
    v[3] = bcx.ins().bxor(v[3], m);
    round(bcx, &mut v);
    v[0] = bcx.ins().bxor(v[0], m);
    let b = 8u64 << 56;
    v[3] = bcx.ins().bxor_imm_u(v[3], b as i64);
    round(bcx, &mut v);
    v[0] = bcx.ins().bxor_imm_u(v[0], b as i64);
    v[2] = bcx.ins().bxor_imm_u(v[2], 0xff);
    for _ in 0..3 {
        round(bcx, &mut v);
    }
    let a = bcx.ins().bxor(v[0], v[1]);
    let b = bcx.ins().bxor(v[2], v[3]);
    bcx.ins().bxor(a, b)
}

#[cfg(test)]
fn sip13_u64_ref(m: u64) -> u64 {
    let mut v = SIP_INIT;
    let round = |v: &mut [u64; 4]| {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    };
    v[3] ^= m;
    round(&mut v);
    v[0] ^= m;
    let b = 8u64 << 56;
    v[3] ^= b;
    round(&mut v);
    v[0] ^= b;
    v[2] ^= 0xff;
    for _ in 0..3 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[test]
fn sip13_matches_default_hasher() {
    let mut x = 0x0123_4567_89ab_cdefu64;
    for i in 0..10_000u64 {
        for m in [i, x, i << 56, u64::MAX - i] {
            assert_eq!(sip13_u64_ref(m), hash_to_u64(m));
        }
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    }
}

/*
SAFETY: The underlying storage areas of `entries` and `new_coverage` are baked into the JIT
compilation artifact. This means that they can't be moved until the JIT artifacts are discarded.
It might be worthwhile to explicitly wrap them in a Pin.
*/
pub(crate) struct HashBitset {
    pub entries: BitBox,
    pub saved: BitBox,
    pub new_coverage: Box<bool>,
}
impl HashBitset {
    pub fn new_for_elems(count: usize, blowup_factor: usize) -> Self {
        let size = (count + 1) * blowup_factor;
        // limit size to 128kb. we might have thousands of trace metadatas in the corpus.
        let size = size.min(100_000);
        Self::new_with_size(size.next_power_of_two())
    }

    pub fn new_with_size(size: usize) -> Self {
        assert!(size.is_power_of_two());
        assert!(size > 0);
        let entries = BitVec::repeat(false, size).into_boxed_bitslice();
        Self {
            saved: entries.clone(),
            entries,
            new_coverage: Box::new(false),
        }
    }

    pub fn update_and_scan(&mut self) -> bool {
        let new_cov_hint = std::mem::take(self.new_coverage.as_mut());
        new_cov_hint && super::union_bitboxes(&mut self.saved, &self.entries)
    }

    pub fn reset(&mut self) {
        self.entries.fill(false);
        self.saved.fill(false);
    }

    pub fn reset_keep_saved(&mut self) {
        self.entries.fill(false);
    }

    #[expect(unused)]
    fn instrument<P: HashBitsetInstrumentationPass>(
        &self,
        key: ir::Value,
        mut ctx: InstrCtx,
        pass: &P,
    ) {
        // TODO: handle this with a function call?
        let size = self.entries.len();
        debug_assert!(size.is_power_of_two());
        let index = ctx.bcx.ins().band_imm_u(key, (size - 1) as i64);
        let offset = ctx.bcx.ins().ushr_imm_u(index, 3);
        let bit = ctx.bcx.ins().band_imm_u(key, 0b111);
        let one = ctx.bcx.ins().iconst(I8, 1);
        let mask = ctx.bcx.ins().rotl(one, bit);

        let entries_ptr = ctx
            .state
            .host_ptr(ctx.bcx, self.entries.as_bitptr().pointer());
        let entry_ptr = ctx.bcx.ins().iadd(entries_ptr, offset);

        if ctx.state.options.kind == CompilationKind::Reusable {
            let val = ctx
                .bcx
                .ins()
                .load(I8, MemFlagsData::trusted(), entry_ptr, 0);
            let val = ctx.bcx.ins().bor(val, mask);
            ctx.bcx
                .ins()
                .store(MemFlagsData::trusted(), val, entry_ptr, 0);
        }
    }

    /// `inline`: emit the update as straight-line code (~90 instructions)
    /// instead of a host call; meant for sites that are few per function.
    fn mix_and_instrument<P: HashBitsetInstrumentationPass, V: Hash>(
        &self,
        contrib: V,
        mut ctx: InstrCtx,
        pass: &P,
        inline: bool,
    ) {
        assert!(std::ptr::eq(self as *const _, pass.coverage() as *const _));
        let data = get_hash_var(pass, &mut ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let hash_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

        assert!(self.entries.len().is_power_of_two());
        #[unsafe(no_mangle)]
        unsafe extern "C" fn mix_and_update_bitset(
            new_cov: *mut bool,
            hash_ptr: *mut u64,
            bitslice_ptr: *mut usize,
            bitslice_len: u32,
            contribution: u32,
            _: *mut VMContext,
        ) {
            unsafe {
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
                let bitslice =
                    slice::from_raw_parts_unchecked_mut(bitslice_ptr, bitslice_len as usize);
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
        }

        let contrib = hash_to_u64(contrib) as u32 as i64;

        static HOSTCALL: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let hostcall =
            *HOSTCALL.get_or_init(|| std::env::var_os("WASMFUZZ_PATH_HASH_HOSTCALL").is_some());
        if inline && !hostcall {
            // Same update as `mix_and_update_bitset`, emitted inline: the
            // same SipHash-1-3, so the same bits get set, without a host call.
            let flags = MemFlagsData::trusted();
            let old = ctx.bcx.ins().load(ir::types::I64, flags, hash_ptr, 0);
            let shifted = ctx.bcx.ins().ishl_imm_u(old, 8);
            let new = ctx.bcx.ins().bor_imm_u(shifted, contrib & 0xff);
            ctx.bcx.ins().store(flags, new, hash_ptr, 0);
            let h = sip13_u64(ctx.bcx, new);
            let idx = ctx.bcx.ins().band_imm_u(h, (self.entries.len() - 1) as i64);
            let word = ctx.bcx.ins().ushr_imm_u(idx, 6);
            let word_off = ctx.bcx.ins().ishl_imm_u(word, 3);
            let bitslice_ptr = ctx
                .state
                .host_ptr(ctx.bcx, self.entries.as_bitptr().pointer());
            let word_ptr = ctx.bcx.ins().iadd(bitslice_ptr, word_off);
            let bits = ctx.bcx.ins().load(ir::types::I64, flags, word_ptr, 0);
            let one = ctx.bcx.ins().iconst(ir::types::I64, 1);
            let mask = ctx.bcx.ins().ishl(one, idx);
            let is_set = ctx.bcx.ins().band(bits, mask);
            let set_block = ctx.bcx.create_block();
            let cont_block = ctx.bcx.create_block();
            ctx.bcx.set_cold_block(set_block);
            ctx.bcx.ins().brif(is_set, cont_block, &[], set_block, &[]);
            ctx.bcx.seal_block(set_block);
            ctx.bcx.switch_to_block(set_block);
            let bits = ctx.bcx.ins().bor(bits, mask);
            ctx.bcx.ins().store(flags, bits, word_ptr, 0);
            let new_cov_ptr = self.new_coverage.as_ref() as *const _;
            let new_cov_ptr = ctx.state.host_ptr(ctx.bcx, new_cov_ptr as *const _);
            let one = ctx.bcx.ins().iconst(I8, 1);
            ctx.bcx.ins().store(flags, one, new_cov_ptr, 0);
            ctx.bcx.ins().jump(cont_block, &[]);
            ctx.bcx.seal_block(cont_block);
            ctx.bcx.switch_to_block(cont_block);
            return;
        }

        let contrib = ctx.bcx.ins().iconst(ir::types::I32, contrib);

        let new_cov_ptr = self.new_coverage.as_ref() as *const _;
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
        MemFlagsData::trusted(),
    );

    let new_cov_ptr = pass.coverage().new_coverage.as_ref() as *const _;
    let new_cov_ptr = ctx.state.host_ptr(ctx.bcx, new_cov_ptr as *const _);
    let zero = ctx.bcx.ins().iconst(ir::types::I8, 0);
    ctx.bcx
        .ins()
        .store(MemFlagsData::trusted(), zero, new_cov_ptr, 0);
}

pub(crate) struct FuncPathHashPass {
    pub coverage: HashBitset,
    pub keys: HashSet<FuncIdx>,
}

impl FuncPathHashPass {
    pub fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        let keys = super::iter_funcs(spec)
            .filter(|x| key_filter(&Location::from(*x)))
            .collect::<HashSet<_>>();
        Self {
            coverage: HashBitset::new_for_elems(keys.len(), 64),
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
        self.coverage.mix_and_instrument(key, ctx, self, true);
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
    pub fn new<F: Fn(&Location) -> bool>(spec: &ModuleSpec, key_filter: F) -> Self {
        let keys = super::iter_edges(spec)
            .filter(|x| key_filter(&Location::from(*x)))
            .collect::<HashSet<_>>();
        Self {
            coverage: HashBitset::new_for_elems(keys.len(), 64),
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
        // One site per edge: inlining every one multiplies code size and
        // compile time, so this keeps the host call.
        self.coverage.mix_and_instrument(key, ctx, self, false);
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}
