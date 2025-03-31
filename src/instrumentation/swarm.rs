use cranelift::codegen::ir::{self, InstBuilder, MemFlags, Type, Value};
use cranelift::module::{DataDescription, DataId, Module};

use crate::ir::Location;
use crate::jit::module::TrapKind;
use crate::jit::SwarmConfig;

use super::{CovSnapshot, Edge, ErasedInstrumentationPass, FuncIdx, InstrCtx};

#[derive(Clone, PartialEq)]
enum MUKey {
    Edge(Edge),
    BB(Location),
    Function(u32),
}

pub(crate) struct SwarmShortCircuitPass {
    config: SwarmConfig,
    must_use_keys: Vec<MUKey>,
}

impl SwarmShortCircuitPass {
    pub(crate) fn new(config: SwarmConfig) -> Self {
        Self {
            must_use_keys: [
                config
                    .must_include_edges
                    .iter()
                    .copied()
                    .map(MUKey::Edge)
                    .collect::<Vec<_>>(),
                config
                    .must_include_bbs
                    .iter()
                    .copied()
                    .map(MUKey::BB)
                    .collect::<Vec<_>>(),
                config
                    .must_include_functions
                    .iter()
                    .copied()
                    .map(MUKey::Function)
                    .collect::<Vec<_>>(),
            ]
            .concat(),
            config,
        }
    }

    fn short_circuit(&self, ctx: &mut InstrCtx) {
        ctx.state
            .trap_here(TrapKind::SwarmShortCircuit(Some(ctx.state.loc())), ctx.bcx)
    }

    fn get_var(&self, ctx: &mut InstrCtx) -> DataId {
        let num_bools = self.must_use_keys.len();
        let key = "swarm-must-use-bools";
        if ctx.instance_meta::<_, Option<DataId>>(key).is_none() {
            let val = ctx
                .state
                .module
                .declare_anonymous_data(true, false)
                .unwrap();
            let mut data_desc = DataDescription::new();
            data_desc.define_zeroinit(num_bools);
            ctx.state.module.define_data(val, &data_desc).unwrap();
            *ctx.instance_meta::<_, Option<DataId>>(key).insert(val)
        } else {
            ctx.instance_meta::<_, Option<DataId>>(key).unwrap()
        }
    }

    fn instrument_mukey(&self, key: MUKey, ctx: &mut InstrCtx) {
        let data = self.get_var(ctx);
        let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
        let bools_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

        let idx = self.must_use_keys.iter().position(|x| *x == key).unwrap();

        let zero = ctx.bcx.ins().iconst(ir::types::I8, 0);
        ctx.bcx
            .ins()
            .store(MemFlags::trusted(), zero, bools_ptr, idx as i32);
    }

    fn trampoline_memset_mukeys(&self, iv: u8, ctx: &mut InstrCtx) {
        if !self.must_use_keys.is_empty() {
            let data = self.get_var(ctx);
            let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
            let bools_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

            ctx.bcx.emit_small_memset(
                ctx.state.module.target_config(),
                bools_ptr,
                iv,
                self.must_use_keys.len() as _,
                std::mem::align_of::<u8>() as _,
                MemFlags::trusted(),
            );
        }
    }
}

impl ErasedInstrumentationPass for SwarmShortCircuitPass {
    fn shortcode(&self) -> &'static str {
        "swarm-short-circuit"
    }

    fn instrument_function(&self, mut ctx: InstrCtx) {
        let f = ctx.state.loc().function;
        if self.config.avoid_functions.contains(&f) {
            self.short_circuit(&mut ctx);
        }
        if self.config.must_include_functions.contains(&f) {
            self.instrument_mukey(MUKey::Function(f), &mut ctx);
        }
    }

    fn instrument_basic_block(&self, mut ctx: InstrCtx) {
        let loc = ctx.state.loc();
        if self.config.avoid_bbs.contains(&loc) {
            self.short_circuit(&mut ctx);
        }
        if self.config.must_include_bbs.contains(&loc) {
            self.instrument_mukey(MUKey::BB(loc), &mut ctx);
        }
    }

    fn instrument_edge(&self, edge: Edge, mut ctx: InstrCtx) {
        if self.config.avoid_edges.contains(&edge) {
            self.short_circuit(&mut ctx);
        }
        if self.config.must_include_edges.contains(&edge) {
            self.instrument_mukey(MUKey::Edge(edge), &mut ctx);
        }
    }

    fn instrument_trampoline(&self, mut ctx: InstrCtx) {
        self.trampoline_memset_mukeys(0, &mut ctx);
    }
    fn instrument_fuzz_trampoline(
        &self,
        _inp_ptr: ir::Value,
        _inp_size: ir::Value,
        mut ctx: InstrCtx,
    ) {
        self.trampoline_memset_mukeys(1, &mut ctx);
    }

    fn instrument_trampoline_ret(&self, mut ctx: InstrCtx) {
        if !self.must_use_keys.is_empty() {
            let data = self.get_var(&mut ctx);
            let gv = ctx.state.module.declare_data_in_func(data, ctx.bcx.func);
            let bools_ptr = ctx.bcx.ins().symbol_value(ctx.state.ptr_ty(), gv);

            let mut c = ctx.bcx.ins().iconst(ir::types::I8, 1);
            for i in 0..self.must_use_keys.len() {
                let val =
                    ctx.bcx
                        .ins()
                        .load(ir::types::I8, MemFlags::trusted(), bools_ptr, i as i32);
                c = ctx.bcx.ins().band(c, val);
            }
            let trap = TrapKind::SwarmShortCircuit(Some(ctx.state.loc()));
            ctx.bcx.ins().trapnz(c, ctx.state.get_trap_code(trap));
        }
    }

    fn instrument_function_ret(&self, _ctx: InstrCtx) {}

    fn instrument_cmp(&self, _ty: Type, _lhs: Value, _rhs: Value, _ctx: InstrCtx) {}

    fn instrument_memory_load(
        &self,
        _address: Value,
        _imm_offset: u32,
        _res: Value,
        _ty: Type,
        _opcode: ir::Opcode,
        _ctx: InstrCtx,
    ) {
    }

    fn instrument_memory_store(
        &self,
        _address: Value,
        _imm_offset: u32,
        _val: Value,
        _ty: Type,
        _opcode: ir::Opcode,
        _ctx: InstrCtx,
    ) {
    }

    fn instrument_call(
        &self,
        _target: Option<FuncIdx>,
        _params: &[Value],
        _tys: &[Type],
        _ctx: InstrCtx,
    ) {
    }

    fn instrument_call_return(
        &self,
        _target: Option<FuncIdx>,
        _returns: &[Value],
        _tys: &[Type],
        _ctx: InstrCtx,
    ) {
    }

    fn instrument_global_set(&self, _index: u32, _val: Value, _ty: Type, _ctx: InstrCtx) {}

    fn update_and_scan_coverage(&mut self) -> bool {
        false
    }

    fn reset_coverage(&mut self) {}
    fn reset_coverage_keep_saved(&mut self) {}
    fn snapshot_coverage(&self) -> CovSnapshot {
        CovSnapshot::Noop
    }
}
