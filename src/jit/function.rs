use std::any::Any;

use crate::{HashMap, HashSet, instrumentation::Passes};

use cranelift::codegen::ir::{self, FuncRef, GlobalValue};
use cranelift::frontend::{FunctionBuilder, Variable};
use cranelift::jit::JITModule;
use cranelift::module::{FuncId, Module};
use cranelift::prelude::{InstBuilder, MemFlags, Signature, TrapCode, Value};
use ir::types::{I32, I64, Type};
use wasmparser::FuncType;

use super::{
    CompilationKind, CompilationOptions,
    builtins::{
        builtin_debug_wasmfuzz_write_stdout, builtin_memory_copy, builtin_memory_fill,
        builtin_memory_grow, builtin_memory_size, builtin_random_get,
        builtin_trace_wasmfuzz_write_stdout, fetch_vmctx, signature, translate_debug_log,
    },
    concolic::{
        translate_build_concolic_binop, translate_build_concolic_memory_load,
        translate_build_concolic_select, translate_build_concolic_unop,
        translate_concolic_debug_verify, translate_concolic_memory_copy,
        translate_concolic_memory_fill, translate_concolic_memory_store,
    },
    memory::translate_memory,
    module::TrapKind,
    util::{MemFlagsExt, wasm2tys},
    vmcontext::VMContext,
};
use crate::{
    AbortCode,
    instrumentation::{ErasedInstrumentationPass, InstrCtx},
    ir::{InsnIdx, Location, MemoryInstruction, ModuleSpec, WFOperator},
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum StackEntry {
    Undefined(Type),
    Value(Type, ir::Value),
}

impl StackEntry {
    fn ty(&self) -> Type {
        match self {
            Self::Undefined(ty) => *ty,
            Self::Value(ty, _) => *ty,
        }
    }
}

pub(crate) struct FuncTranslator<'a, 's> {
    pub vmctx: &'s mut VMContext,
    pub func_ids: &'s HashMap<u32, FuncId>,
    pub spec: &'s ModuleSpec,
    pub ip: InsnIdx,
    pub fidx: u32,
    stack: Vec<StackEntry>,
    stack_control_depths: Vec<usize>,
    pub blocks: HashMap<InsnIdx, ir::Block>,
    pub dead_bbs: HashSet<ir::Block>,
    pub concolic_vals: HashMap<Value, Value>,
    pub gv_vmctx: Option<GlobalValue>,
    pub heap: Option<GlobalValue>,
    pub func_refs: HashMap<FuncId, FuncRef>,
    pub options: &'a CompilationOptions,
    pub passes: Option<&'a mut Passes>,
    pub trapcodes: Vec<TrapKind>,
    #[allow(unused)]
    pub caller: Option<Location>,
    pub slot: HashMap<u32, Variable>,
    pub sigrefs: HashMap<Signature, ir::SigRef>,
    pub builtin_level: u32,
    pub(crate) pass_meta: &'a mut HashMap<u64, Box<dyn Any>>,
    ptr_ty: Type,
    pub module: &'a mut JITModule,
}

impl<'a, 's> FuncTranslator<'a, 's> {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        vmctx: &'s mut VMContext,
        func_ids: &'s HashMap<u32, FuncId>,
        spec: &'s ModuleSpec,
        func_idx: u32,
        func_refs: HashMap<FuncId, FuncRef>,
        options: &'a CompilationOptions,
        passes: &'a mut Passes,
        module: &'a mut JITModule,
        pass_meta: &'a mut HashMap<u64, Box<dyn Any>>,
    ) -> Self {
        let ptr_ty = module.target_config().pointer_type();
        FuncTranslator {
            vmctx,
            func_ids,
            ip: InsnIdx(0),
            fidx: func_idx,
            spec,
            stack: Vec::new(),
            stack_control_depths: vec![0],
            blocks: HashMap::default(),
            dead_bbs: HashSet::default(),
            concolic_vals: HashMap::default(),
            func_refs,
            gv_vmctx: None,
            heap: None,
            options,
            passes: Some(passes),
            trapcodes: vec![],
            caller: None,
            slot: HashMap::default(),
            sigrefs: HashMap::default(),
            builtin_level: 0,
            pass_meta,
            ptr_ty,
            module,
        }
    }

    pub(crate) fn block(&mut self, ip: InsnIdx, bcx: &mut FunctionBuilder) -> ir::Block {
        *self.blocks.entry(ip).or_insert_with(|| bcx.create_block())
    }

    pub(crate) fn pop1(&mut self, ty: Type, bcx: &mut FunctionBuilder) -> ir::Value {
        match self.stack.pop().expect("trying to pop on an empty stack") {
            StackEntry::Undefined(ty) => self.undef(ty, bcx),
            StackEntry::Value(ty_, val) => {
                assert_eq!(ty, ty_, "pop1: expected {ty:?} got {ty_:?}");
                if self.options.is_concolic() {
                    assert!(self.concolic_vals.contains_key(&val));
                }
                val
            }
        }
    }

    pub(crate) fn pop2(&mut self, ty: Type, bcx: &mut FunctionBuilder) -> (ir::Value, ir::Value) {
        let b = self.pop1(ty, bcx);
        let a = self.pop1(ty, bcx);
        (a, b)
    }

    pub(crate) fn popn(&mut self, tys: &[Type], bcx: &mut FunctionBuilder) -> Vec<ir::Value> {
        let n = tys.len();
        assert!(self.stack.len() >= n);
        let rvals = self.stack[self.stack.len() - n..].to_vec();
        let rvals = rvals
            .iter()
            .zip(tys)
            .map(|(entry, ex_ty)| {
                assert_eq!(entry.ty(), *ex_ty);
                match entry {
                    StackEntry::Undefined(ty) => self.undef(*ty, bcx),
                    StackEntry::Value(_ty, val) => *val,
                }
            })
            .collect();
        self.stack.truncate(self.stack.len() - n);
        rvals
    }

    pub(crate) fn peekn(&mut self, n: usize, bcx: &mut FunctionBuilder) -> Vec<ir::Value> {
        assert!(self.stack.len() >= n);
        let rvals = self.stack[self.stack.len() - n..].to_vec();

        rvals
            .iter()
            .map(|entry| match entry {
                StackEntry::Undefined(ty) => self.undef(*ty, bcx),
                StackEntry::Value(_ty, val) => *val,
            })
            .collect()
    }

    pub(crate) fn peek1(&mut self, ty: Type, bcx: &mut FunctionBuilder) -> ir::Value {
        match self.stack[self.stack.len() - 1] {
            StackEntry::Undefined(ty) => self.undef(ty, bcx),
            StackEntry::Value(ty_, val) => {
                assert_eq!(ty, ty_);
                val
            }
        }
    }

    pub(crate) fn peekty_at(&self, depth: usize) -> Type {
        assert!(self.stack.len() > depth);
        self.stack[self.stack.len() - 1 - depth].ty()
    }

    pub(crate) fn peekty(&self) -> Type {
        self.stack[self.stack.len() - 1].ty()
    }

    pub(crate) fn peekty2(&self) -> Type {
        let t1 = self.stack[self.stack.len() - 1].ty();
        let t2 = self.stack[self.stack.len() - 2].ty();
        assert_eq!(t1, t2);
        t1
    }

    pub(crate) fn push1(&mut self, ty: Type, val: ir::Value) {
        if self.options.is_concolic() {
            assert!(self.concolic_vals.contains_key(&val));
        }
        self.stack.push(StackEntry::Value(ty, val));
    }

    pub(crate) fn pushn(&mut self, tys: &[Type], vals: &[ir::Value]) {
        if self.options.is_concolic() {
            for val in vals {
                assert!(self.concolic_vals.contains_key(val));
            }
        }

        self.stack.extend(
            vals.iter()
                .zip(tys)
                .map(|(v, ty)| StackEntry::Value(*ty, *v)),
        )
    }

    pub(crate) fn get_concolic(&self, value: &ir::Value) -> ir::Value {
        debug_assert!(self.options.is_concolic());
        *self
            .concolic_vals
            .get(value)
            .expect("symvar missing for ir value")
    }

    pub(crate) fn set_concolic(
        &mut self,
        ty: Type,
        dest: ir::Value,
        symref: ir::Value,
        bcx: &mut FunctionBuilder,
    ) {
        if self.options.is_concolic() {
            debug_assert!(!self.concolic_vals.contains_key(&symref));
            debug_assert!(!self.concolic_vals.values().any(|&v| v == dest));
            if cfg!(debug_assertions) && self.concolic_vals.contains_key(&dest) {
                debug_assert!(*self.concolic_vals.get(&dest).unwrap() == symref);
            }
            self.concolic_vals.insert(dest, symref);
            if cfg!(feature = "concolic_debug_verify") {
                translate_concolic_debug_verify(dest, ty, symref, self, bcx);
            }
        }
    }

    pub(crate) fn set_concolic_concrete(
        &mut self,
        ty: Type,
        dest: ir::Value,
        bcx: &mut FunctionBuilder,
    ) {
        if self.options.is_concolic() {
            self.set_concolic(ty, dest, bcx.ins().iconst(I32, 0), bcx);
        }
    }

    pub(crate) fn fill_concolic_unop(
        &mut self,
        ty: Type,
        dest: ir::Value,
        op: crate::concolic::UnaryOp,
        source: ir::Value,
        bcx: &mut FunctionBuilder,
    ) {
        if !self.options.is_concolic() {
            return;
        }
        let symref = translate_build_concolic_unop(op, source, self, bcx);
        self.set_concolic(ty, dest, symref, bcx);
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) fn fill_concolic_binop(
        &mut self,
        dest_ty: Type,
        dest: ir::Value,
        op: crate::concolic::BinaryOp,
        a: ir::Value,
        b: ir::Value,
        ty: Type,
        bcx: &mut FunctionBuilder,
    ) {
        if !self.options.is_concolic() {
            return;
        }
        let symref = translate_build_concolic_binop(op, a, b, ty, self, bcx);
        self.set_concolic(dest_ty, dest, symref, bcx);
    }

    pub(crate) fn fill_concolic_select(
        &mut self,
        dest: ir::Value,
        cond: ir::Value,
        a: ir::Value,
        b: ir::Value,
        ty: Type,
        bcx: &mut FunctionBuilder,
    ) {
        if !self.options.is_concolic() {
            return;
        }
        let symref = translate_build_concolic_select(cond, a, b, ty, self, bcx);
        self.set_concolic(ty, dest, symref, bcx);
    }

    pub(crate) fn fill_concolic_memory_load(
        &mut self,
        result_ty: Type,
        dest: Value,
        addr32: Value,
        offset: u32,
        kind: crate::concolic::MemoryAccessKind,
        bcx: &mut FunctionBuilder,
    ) {
        if !self.options.is_concolic() {
            return;
        }
        let symref =
            translate_build_concolic_memory_load(addr32, offset, kind, self.loc(), self, bcx);
        self.set_concolic(result_ty, dest, symref, bcx);
    }

    pub(crate) fn concolic_memory_store(
        &mut self,
        val: Value,
        addr32: Value,
        offset: u32,
        kind: crate::concolic::MemoryAccessKind,
        bcx: &mut FunctionBuilder,
    ) {
        if !self.options.is_concolic() {
            return;
        }
        translate_concolic_memory_store(val, addr32, offset, kind, self.loc(), self, bcx);
    }

    pub(crate) fn push_control_frame(&mut self) {
        self.stack_control_depths.push(self.stack.len());
    }

    pub(crate) fn pop_control_frame(&mut self) {
        assert!(
            self.stack_control_depths.len() > 1,
            "no more control frame to pop (0 is dummy)"
        );
        let depth = self.stack_control_depths.pop().unwrap();
        self.stack.truncate(depth);
    }

    // adjust_* modifies the stack without requiring a usable codegen context
    pub(crate) fn adjust_pop_push(&mut self, pop: &[Type], push: &[Type]) {
        assert!(self.stack.len() >= pop.len());
        for (a, b) in pop.iter().zip(&self.stack[self.stack.len() - pop.len()..]) {
            assert_eq!(*a, b.ty());
        }
        self.stack.truncate(self.stack.len() - pop.len());
        for ty in push {
            self.stack.push(StackEntry::Undefined(*ty));
        }
    }

    pub(crate) fn adjust_pop_push_fty(&mut self, function_ty: &FuncType) {
        let params = wasm2tys(function_ty.params());
        let returns = wasm2tys(function_ty.results());
        self.adjust_pop_push(&params, &returns);
    }

    pub(crate) fn undef(&mut self, ty: Type, bcx: &mut FunctionBuilder) -> ir::Value {
        if self.options.debug_trace {
            super::builtins::translate_debug_log(
                "!!! using undefined value !!!".to_string(),
                self,
                bcx,
            );
        }
        // This value is undefined and will not be used in actual execution traces.
        // We assign a dummy to proceed with compilation
        let val = bcx.ins().iconst(ty, 0xfadebabe);
        self.set_concolic_concrete(ty, val, bcx);
        val
    }

    pub(crate) fn fspec(&self) -> &crate::ir::FuncSpec {
        &self.spec.functions[self.fidx as usize]
    }

    pub(crate) fn loc(&self) -> Location {
        Location {
            function: self.fidx,
            index: self.ip.0,
        }
    }

    // Check if current instruction insertion spot is unreachable
    pub(crate) fn dead(&self, bcx: &FunctionBuilder) -> bool {
        bcx.current_block()
            .is_some_and(|block| self.dead_bbs.contains(&block))
    }

    pub(crate) fn mark_dead(&mut self, bcx: &mut FunctionBuilder) {
        let block = bcx.current_block().unwrap();
        self.dead_bbs.insert(block);
    }

    pub(crate) fn ptr_ty(&self) -> Type {
        self.ptr_ty
    }

    pub(crate) fn get_vmctx(&mut self, bcx: &mut FunctionBuilder) -> GlobalValue {
        *self
            .gv_vmctx
            .get_or_insert_with(|| bcx.create_global_value(ir::GlobalValueData::VMContext))
    }

    pub(crate) fn get_heap_base(&mut self, bcx: &mut FunctionBuilder) -> Value {
        let ptr_ty = self.ptr_ty();
        let base = self.get_vmctx(bcx);
        let gv = *self.heap.get_or_insert_with(|| {
            bcx.create_global_value(ir::GlobalValueData::Load {
                base,
                offset: ir::immediates::Offset32::new(std::mem::offset_of!(VMContext, heap) as i32),
                global_type: ptr_ty,
                flags: ir::MemFlags::trusted().with_readonly(),
            })
        });
        bcx.ins().global_value(ptr_ty, gv)
    }

    pub(crate) fn translate_op(&mut self, op: &WFOperator, bcx: &mut FunctionBuilder, ip: InsnIdx) {
        self.ip = ip;
        let loc = Location {
            function: self.fidx,
            index: ip.0,
        };

        if self.options.verbose {
            let stack_str: String = self
                .stack
                .iter()
                .map(|el| match *el {
                    StackEntry::Undefined(ty) => {
                        format!("U{ty} ")
                    }
                    StackEntry::Value(ty, _val) => {
                        format!("V{ty} ")
                    }
                })
                .collect();
            if self.dead(bcx) {
                println!("{:04} X {{ {}}} {:?} <dead>", ip.0, stack_str, op);
            } else {
                println!("{:04} | {{ {}}} {:?}", ip.0, stack_str, op);
            }
        }

        if self.options.debug_trace
            && !std::env::var("JITTRACE")
                .map(|s| s == "thin")
                .unwrap_or(false)
        {
            let is_line = std::env::var("JITTRACE")
                .map(|s| s == "line")
                .unwrap_or(false);

            if is_line {
                let addr = self.fspec().operators_wasm_bin_offset_base as u64
                    + self.fspec().operator_offset_rel[self.ip.i()] as u64;
                let line = crate::ir::debuginfo_helper::resolve_source_location(
                    self.spec,
                    addr,
                    |mut sloc| {
                        sloc.next().map_or_else(String::new, |x| {
                            format!(
                                "{}:{}",
                                x.file().map(|x| x.full_path()).as_deref().unwrap_or("?"),
                                x.line()
                            )
                        })
                    },
                );
                super::builtins::translate_debug_log(
                    format!(
                        "{}/{:04}: {} {:?}",
                        self.fspec().symbol,
                        self.ip,
                        line.as_deref().unwrap_or("?:?"),
                        op,
                    ),
                    self,
                    bcx,
                );
            } else {
                super::builtins::translate_debug_log(
                    format!("{}/{:04}: {:?}", self.fspec().symbol, self.ip, op),
                    self,
                    bcx,
                );
            }
        }

        if self.fspec().is_bb_start[ip.i()] {
            super::instrumentation::instrument_bb(self, bcx, loc);
            self.iter_passes(bcx, |pass, ctx| pass.instrument_basic_block(ctx));
        }

        match op {
            WFOperator::Numeric(op) => super::numeric::translate_numeric(op, self, bcx),
            WFOperator::Parametric(op) => super::misc::translate_parametric(op, self, bcx),
            WFOperator::Variable(op) => super::misc::translate_variable(op, self, bcx),
            WFOperator::Table(op) => super::misc::translate_table(op, self, bcx),
            WFOperator::Memory(op) => super::memory::translate_memory(op, self, bcx),
            WFOperator::Control(op) => super::control::translate_control(op, self, bcx),
            WFOperator::Builtin { name, ty } => {
                if self.dead(bcx) {
                    return self.adjust_pop_push_fty(ty);
                }
                self.jit_builtin_call(name, Some(ty), bcx);
            }
            WFOperator::TodoUnimplemented(_) => {
                panic!("trying to jit unimplemented op: {op:?}");
            }
        }
    }

    pub(crate) fn jit_builtin_call(
        &mut self,
        builtin: &str,
        ty: Option<&FuncType>,
        bcx: &mut FunctionBuilder,
    ) {
        fn memarg_offset(offset: u64) -> wasmparser::MemArg {
            wasmparser::MemArg {
                align: 0,
                max_align: 0,
                memory: 0,
                offset,
            }
        }

        self.builtin_level += 1;
        // TODO: move to builtins.rs?
        if bcx.func.layout.entry_block().is_none() {
            bcx.ins().nop(); // FIXME(cranelift): thread 'main' panicked at 'Function is empty'
        }
        match builtin {
            "MemorySize" => {
                let [res] = self.host_call(
                    bcx,
                    builtin_memory_size as unsafe extern "C" fn(_) -> u32,
                    &[],
                );
                self.set_concolic_concrete(I32, res, bcx);
                self.push1(I32, res);
            }
            "MemoryGrow" => {
                let delta = self.pop1(I32, bcx);

                let [res] = self.host_call(
                    bcx,
                    builtin_memory_grow as unsafe extern "C" fn(_, _) -> u32,
                    &[delta],
                );

                self.set_concolic_concrete(I32, res, bcx);
                self.push1(I32, res);
            }
            "MemoryFill" => {
                let len = self.pop1(I32, bcx);
                let val = self.pop1(I32, bcx);
                let dest = self.pop1(I32, bcx);

                self.host_call(
                    bcx,
                    builtin_memory_fill as unsafe extern "C" fn(_, _, _, _),
                    &[dest, val, len],
                );

                if self.options.is_concolic() {
                    translate_concolic_memory_fill(dest, val, len, self, bcx);
                }
            }
            "MemoryCopy" => {
                let len = self.pop1(I32, bcx);
                let src_pos = self.pop1(I32, bcx);
                let dst_pos = self.pop1(I32, bcx);

                self.host_call(
                    bcx,
                    builtin_memory_copy as unsafe extern "C" fn(_, _, _, _),
                    &[dst_pos, src_pos, len],
                );

                if self.options.is_concolic() {
                    translate_concolic_memory_copy(dst_pos, src_pos, len, self, bcx);
                }
            }
            "wasi_snapshot_preview1::fd_write" => {
                /*
                int fd_write(int fd, __wasi_ciovec_t* iovs, int iovs_len, int* nwritten);
                typedef struct __wasi_ciovec_t {
                    const void *buf;
                    size_t buf_len;
                } __wasi_ciovec_t;
                */
                let nwritten_addr = self.pop1(I32, bcx);
                let iovs_len = self.pop1(I32, bcx);
                let iovs_addr = self.pop1(I32, bcx);
                let _fd = self.pop1(I32, bcx);

                let block = bcx.create_block();
                let block_iovs_addr = bcx.append_block_param(block, I32);
                let block_iovs_len = bcx.append_block_param(block, I32);
                let block_count = bcx.append_block_param(block, I32);

                let end = bcx.create_block();
                let end_count = bcx.append_block_param(end, I32);

                let zero = bcx.ins().iconst(I32, 0);
                bcx.ins()
                    .jump(block, &[iovs_addr.into(), iovs_len.into(), zero.into()]);

                bcx.switch_to_block(block);

                // Note: This is not correct but is probably fine.
                self.set_concolic_concrete(I32, block_iovs_addr, bcx);
                self.set_concolic_concrete(I32, block_iovs_len, bcx);
                self.set_concolic_concrete(I32, block_count, bcx);

                // write_stdout(iovs[0]->buf, iovs[0]->len);
                self.push1(I32, block_iovs_addr);
                translate_memory(&MemoryInstruction::I32Load(memarg_offset(0)), self, bcx); // iovs[0]->buf
                self.push1(I32, block_iovs_addr);
                translate_memory(&MemoryInstruction::I32Load(memarg_offset(4)), self, bcx); // iovs[0]->len

                let iov_len = self.pop1(I32, bcx);
                let iov_ptr = self.pop1(I32, bcx);

                match self.options.kind {
                    CompilationKind::Reusable => {
                        if std::env::var("STDOUTDEBUG")
                            .as_ref()
                            .map(|x| &**x)
                            .unwrap_or("0")
                            == "1"
                        {
                            self.host_call(
                                bcx,
                                builtin_debug_wasmfuzz_write_stdout
                                    as unsafe extern "C" fn(_, _, _),
                                &[iov_ptr, iov_len],
                            );
                        }
                    }
                    CompilationKind::Tracing => {
                        if self.options.tracing.stdout {
                            self.host_call(
                                bcx,
                                builtin_trace_wasmfuzz_write_stdout
                                    as unsafe extern "C" fn(_, _, _),
                                &[iov_ptr, iov_len],
                            );
                        }
                    }
                }

                // count += iovs[0]->len;
                let count = bcx.ins().iadd(block_count, iov_len);

                // iovs = &iovs[1] (+= 8)
                let iovs = bcx.ins().iadd_imm(block_iovs_addr, 8);

                // iov_len -= 1
                let one = bcx.ins().iconst(I32, 1);
                let iovs_len = bcx.ins().isub(block_iovs_len, one);

                // if (iov_len == 0) break;
                bcx.ins().brif(
                    iovs_len,
                    block,
                    &[iovs.into(), iovs_len.into(), count.into()],
                    end,
                    &[count.into()],
                );

                bcx.seal_block(block);
                bcx.seal_block(end);
                bcx.switch_to_block(end);
                self.set_concolic_concrete(I32, end_count, bcx);

                // *nwritten = count;
                self.push1(I32, nwritten_addr);
                self.push1(I32, end_count);
                translate_memory(&MemoryInstruction::I32Store(memarg_offset(0)), self, bcx);

                // return success
                self.push_i32(0, bcx);
            }
            "wasi_snapshot_preview1::clock_time_get" => {
                // consume arguments
                let time_ptr = self.pop1(I32, bcx);
                let _precision = self.pop1(I64, bcx);
                let _clock_id = self.pop1(I32, bcx);
                // store fixed time (in nanos) in `time_ptr`
                self.push1(I32, time_ptr);
                self.push_i64(1700000000 * 1000000000, bcx);
                translate_memory(&MemoryInstruction::I64Store(memarg_offset(0)), self, bcx);
                // return 0 (indicate success)
                self.push_i32(0, bcx);
            }
            "wasi_snapshot_preview1::fd_fdstat_get" => {
                // error out, only used for isatty?
                self.adjust_pop_push(&[I32, I32], &[]);
                self.push_i32(1, bcx);
            }
            "wasi_snapshot_preview1::environ_sizes_get" => {
                let environ_buf_size_addr = self.pop1(I32, bcx);
                let environ_count_addr = self.pop1(I32, bcx);
                // __wasi_errno_t err = __wasi_environ_sizes_get(&environ_count, &environ_buf_size);

                // *environ_count = 0
                self.push1(I32, environ_count_addr);
                self.push_i32(0, bcx);
                translate_memory(&MemoryInstruction::I32Store(memarg_offset(0)), self, bcx);
                // *environ_buf_size = 0
                self.push1(I32, environ_buf_size_addr);
                self.push_i32(0, bcx);
                translate_memory(&MemoryInstruction::I32Store(memarg_offset(0)), self, bcx);
                // success
                self.push_i32(0, bcx);
            }
            "wasi_snapshot_preview1::fd_prestat_get" => {
                // ignore args and return __WASI_ERRNO_BADF (8)
                self.adjust_pop_push(&[I32, I32], &[]);
                self.push_i32(8, bcx);
            }
            "wasi_snapshot_preview1::random_get" => {
                // fill the buffer with a pseudo-random but static sequence generated
                // by builtin_random_get
                let buf_len = self.pop1(I32, bcx);
                let buf = self.pop1(I32, bcx);

                self.host_call(
                    bcx,
                    builtin_random_get as unsafe extern "C" fn(_, _, _),
                    &[buf, buf_len],
                );

                // return success
                self.push_i32(0, bcx);
            }

            "wasmfuzz::exit_testcase" => {
                self.trap_here(TrapKind::ExitTestcase(Some(self.loc())), bcx);
            }

            _ => {
                self.adjust_pop_push_fty(ty.unwrap());
                translate_debug_log(
                    format!("jit_builtin_call unimplemented: {builtin:?}"),
                    self,
                    bcx,
                );
                bcx.ins().trap(self.trap_abort(AbortCode::Unimplemented));
                self.mark_dead(bcx);
            }
        }
        self.builtin_level -= 1;
    }

    pub(crate) fn get_trap_code(&mut self, kind: TrapKind) -> TrapCode {
        let kind = kind.strip_location();
        let idx = self
            .trapcodes
            .iter()
            .position(|x| *x == kind)
            .unwrap_or_else(|| {
                self.trapcodes.push(kind);
                self.trapcodes.len() - 1
            });
        TrapCode::user((idx + 1).try_into().unwrap()).unwrap()
    }

    pub(crate) fn trap_abort(&mut self, abort: AbortCode) -> TrapCode {
        self.get_trap_code(TrapKind::Abort(abort))
    }

    pub(crate) fn get_slot(
        &mut self,
        idx: u32,
        bcx: &mut FunctionBuilder,
        ty: ir::Type,
    ) -> Variable {
        if let Some(x) = self.slot.get(&idx) {
            *x
        } else {
            let var = bcx.declare_var(ty);
            self.slot.insert(idx, var);
            var
        }
    }

    pub(crate) fn get_slot_concolic(&mut self, idx: u32, bcx: &mut FunctionBuilder) -> Variable {
        self.get_slot(u32::MAX - idx, bcx, ir::types::I32)
    }

    // #[deprecated]
    pub(crate) fn host_ptr<T>(&self, bcx: &mut FunctionBuilder, ptr: *const T) -> ir::Value {
        // TODO: transition away from host ptrs in ir/asm!
        if true {
            let idx;
            let offset;
            {
                let mut host_ptrs = self.vmctx.host_ptrs_backing.try_borrow_mut().unwrap();
                let ptr = ptr as usize;
                let _idx = host_ptrs
                    .iter()
                    .position(|&x| x <= ptr && ptr <= x + 0x10000);
                match _idx {
                    Some(_idx) => {
                        idx = _idx;
                        offset = ptr - host_ptrs[idx];
                    }
                    None => {
                        idx = host_ptrs.len();
                        host_ptrs.push(ptr);
                        offset = 0;
                    }
                }
            }
            // self.get_vmctx(bcx);
            // avoid 'Function is empty'
            if bcx.func.layout.entry_block().is_none() {
                bcx.ins().nop();
            }
            let vmctx = bcx
                .func
                .special_param(ir::ArgumentPurpose::VMContext)
                .expect("Missing vmctx parameter");
            let flags = MemFlags::trusted_ro();
            let host_ptr_area = bcx.ins().load(
                self.ptr_ty(),
                flags,
                vmctx,
                std::mem::offset_of!(VMContext, host_ptrs) as i32,
            );
            let val = bcx.ins().load(
                self.ptr_ty(),
                flags,
                host_ptr_area,
                (idx * std::mem::size_of::<usize>()) as i32,
            );
            if offset != 0 {
                bcx.ins().iadd_imm(val, offset as i64)
            } else {
                val
            }
        } else {
            bcx.ins().iconst(self.ptr_ty(), ptr as i64)
        }
    }

    pub(crate) fn host_call<A: ToValueVec, R: TryFrom<Vec<Value>>>(
        &mut self,
        bcx: &mut FunctionBuilder<'_>,
        func: impl HostCallFn<Args = A, Rets = R>,
        args: &A,
    ) -> R {
        let param_tys = func.to_param_tys();
        let return_tys = func.to_ret_tys();

        // TODO: We could use a direct call here, but that'd require us to
        //       import the function into the JIT module and assign an id which
        //       doesn't seem that supported.
        let sig = signature(&param_tys, &return_tys, true);
        let sig = self.import_signature(sig, bcx);
        let callee = self.host_ptr(bcx, func.as_const_fn());
        let mut args_with_vmctx = args.to_value_vec();
        args_with_vmctx.push(fetch_vmctx(bcx));
        let call = bcx.ins().call_indirect(sig, callee, &args_with_vmctx);
        bcx.inst_results(call)
            .to_vec()
            .try_into()
            .unwrap_or_else(|_| unreachable!())
    }

    pub(crate) fn host_call_with_types(
        &mut self,
        bcx: &mut FunctionBuilder<'_>,
        func: *const fn(),
        param_tys: &[ir::types::Type],
        return_tys: &[ir::types::Type],
        args: &[Value],
    ) -> ir::Inst {
        // TODO: We could use a direct call here, but that'd require us to
        //       import the function into the JIT module and assign an id which
        //       doesn't seem that supported.
        let sig = signature(param_tys, return_tys, true);
        let sig = self.import_signature(sig, bcx);
        let callee = self.host_ptr(bcx, func);
        let mut args_with_vmctx = args.to_vec();
        args_with_vmctx.push(fetch_vmctx(bcx));
        bcx.ins().call_indirect(sig, callee, &args_with_vmctx)
    }

    pub(crate) fn import_signature(
        &mut self,
        sig: Signature,
        bcx: &mut FunctionBuilder,
    ) -> ir::SigRef {
        *self
            .sigrefs
            .entry(sig.clone())
            .or_insert_with(|| bcx.import_signature(sig))
    }

    pub(crate) fn func_ref(&self, function_index: u32) -> FuncRef {
        let func_id = self.func_ids[&function_index];
        self.func_refs[&func_id]
    }

    fn push_i32(&mut self, val: i32, bcx: &mut FunctionBuilder) {
        let val = bcx.ins().iconst(I32, val as u32 as i64);
        self.set_concolic_concrete(I32, val, bcx);
        self.push1(I32, val);
    }

    fn push_i64(&mut self, val: i64, bcx: &mut FunctionBuilder) {
        let val = bcx.ins().iconst(I64, val);
        self.set_concolic_concrete(I64, val, bcx);
        self.push1(I64, val);
    }

    pub(crate) fn iter_passes<F: Fn(&mut dyn ErasedInstrumentationPass, InstrCtx)>(
        &mut self,
        bcx: &mut FunctionBuilder,
        f: F,
    ) {
        let Some(passes) = self.passes.take() else {
            return;
        };
        for pass in passes.iter_mut() {
            let pass: &mut dyn ErasedInstrumentationPass = pass.as_mut();
            let ctx = InstrCtx { bcx, state: self };
            f(pass, ctx);
        }
        self.passes = Some(passes);
    }

    pub(crate) fn trap_here(&mut self, loc: TrapKind, bcx: &mut FunctionBuilder) {
        bcx.ins().trap(self.get_trap_code(loc));
        self.mark_dead(bcx);
    }
}

pub(crate) trait ToValueVec {
    fn to_value_vec(&self) -> Vec<Value>;
}

impl<const N: usize> ToValueVec for [Value; N] {
    fn to_value_vec(&self) -> Vec<Value> {
        self.to_vec()
    }
}

pub(crate) trait HostCallFn {
    type Args: ToValueVec;
    type Rets: ToValueVec;
    fn as_const_fn(&self) -> *const fn();
    fn to_param_tys(&self) -> Vec<ir::types::Type>;
    fn to_ret_tys(&self) -> Vec<ir::types::Type>;
}

trait HostCallTy {
    fn as_cranelift_ty() -> ir::types::Type;
}

mod fn_sig_impls {
    use super::VMContext;
    use super::{HostCallFn, HostCallTy};
    use crate::concolic::*;
    use crate::jit::concolic::ValTy;
    use cranelift::codegen::ir::Value;
    use cranelift::codegen::ir::types::*;

    macro_rules! count {
        () => (0usize);
        ( $x:tt $($xs:tt)* ) => (1usize + count!($($xs)*));
    }

    macro_rules! impl_ty {
        ($native_ty:ty => $cranelift_ty:expr) => {
            impl HostCallTy for $native_ty {
                fn as_cranelift_ty() -> Type {
                    $cranelift_ty
                }
            }
        };
    }

    macro_rules! impl_sig {
        (native: ($( $native_ty:ty ),*), cranelift: ($( $cranelift_ty:expr ),*)) => {
            impl HostCallFn for unsafe extern "C" fn($( $native_ty, )+ *mut VMContext) {
                type Args = [Value; count!($($cranelift_ty)+)];
                type Rets = [Value; 0];

                fn as_const_fn(&self) -> *const fn() {
                    *self as *const fn()
                }

                fn to_param_tys(&self) -> Vec<Type> {
                    vec![
                        $( $cranelift_ty, )+
                    ]
                }

                fn to_ret_tys(&self) -> Vec<Type> {
                    vec![]
                }
            }
        };

        (generic: ($( $arg_name:ident ),*)) => {
            impl<$($arg_name: HostCallTy,)*> HostCallFn for unsafe extern "C" fn($( $arg_name, )* *mut VMContext) {
                type Args = [Value; count!($($arg_name)*)];
                type Rets = [Value; 0];

                fn as_const_fn(&self) -> *const fn() {
                    *self as *const fn()
                }

                fn to_param_tys(&self) -> Vec<Type> {
                    vec![
                        $( $arg_name::as_cranelift_ty(), )*
                    ]
                }

                fn to_ret_tys(&self) -> Vec<Type> {
                    vec![]
                }
            }
        };

        (generic: ($( $arg_name:ident ),*) -> $ret_name:ident) => {
            impl<$ret_name: HostCallTy, $($arg_name: HostCallTy,)*> HostCallFn for unsafe extern "C" fn($( $arg_name, )* *mut VMContext) -> $ret_name {
                type Args = [Value; count!($($arg_name)*)];
                type Rets = [Value; 1];

                fn as_const_fn(&self) -> *const fn() {
                    *self as *const fn()
                }

                fn to_param_tys(&self) -> Vec<Type> {
                    vec![
                        $( $arg_name::as_cranelift_ty(), )*
                    ]
                }

                fn to_ret_tys(&self) -> Vec<Type> {
                    vec![$ret_name::as_cranelift_ty()]
                }
            }
        };

        (native: ($( $native_ty:ty ),*) -> $native_ret:ty, cranelift: ($( $cranelift_ty:expr ),*) -> $cranelift_ret:expr) => {
            impl HostCallFn for unsafe extern "C" fn($( $native_ty, )+ *mut VMContext) -> $native_ret {
                type Args = [Value; {
                    0 $(+ { let _ = $cranelift_ty; 1 })+
                    // is this how it's done? there has to be a better way
                }];
                type Rets = [Value; 1];

                fn as_const_fn(&self) -> *const fn() {
                    *self as *const fn()
                }

                fn to_param_tys(&self) -> Vec<Type> {
                    vec![
                        $( $cranelift_ty, )+
                    ]
                }

                fn to_ret_tys(&self) -> Vec<Type> {
                    vec![
                        $cranelift_ret
                    ]
                }
            }
        };
    }

    impl_ty!(bool => I8);
    impl_ty!(u8 => I8);
    impl_ty!(u16 => I16);
    impl_ty!(u32 => I32);
    impl_ty!(u64 => I64);
    impl_ty!(usize => I64);

    impl_ty!(UnaryOp => I8);
    impl_ty!(BinaryOp => I8);
    impl_ty!(ValTy => I8);
    impl_ty!(MemoryAccessKind => I8);
    impl_ty!(SymValRef => I32);

    impl<T: HostCallTy> HostCallTy for *mut T {
        fn as_cranelift_ty() -> Type {
            I64
        }
    }

    impl_sig!(generic: ());
    impl_sig!(generic: (A));
    impl_sig!(generic: (A, B));
    impl_sig!(generic: (A, B, C));
    impl_sig!(generic: (A, B, C, D));
    impl_sig!(generic: (A, B, C, D, E));
    impl_sig!(generic: (A, B, C, D, E, F));
    impl_sig!(generic: (A, B, C, D, E, F, G));
    impl_sig!(generic: (A, B, C, D, E, F, G, H));
    impl_sig!(generic: (A, B, C, D, E, F, G, H, I));

    impl_sig!(generic: () -> A);
    impl_sig!(generic: (A) -> B);
    impl_sig!(generic: (A, B) -> C);
    impl_sig!(generic: (A, B, C) -> D);
    impl_sig!(generic: (A, B, C, D) -> E);
    impl_sig!(generic: (A, B, C, D, E) -> F);
    impl_sig!(generic: (A, B, C, D, E, F) -> G);
    impl_sig!(generic: (A, B, C, D, E, F, G) -> H);
    impl_sig!(generic: (A, B, C, D, E, F, G, H) -> I);
}
