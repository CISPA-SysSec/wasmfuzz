use cranelift::prelude::*;

use crate::{
    concolic::{self, SymVal, SymValRef, UnaryOp},
    ir::Location,
    ir::heuristics::Libfunc,
};

use super::{FuncTranslator, util::wasm2tys, vmcontext::VMContext};

fn iconst_module_byte_location(bcx: &mut FunctionBuilder, state: &mut FuncTranslator) -> Value {
    bcx.ins().iconst(
        types::I32,
        state.fspec().operators_wasm_bin_offset_base as i64
            + state.fspec().operator_offset_rel[state.ip.i()] as i64,
    )
}

unsafe extern "C" fn builtin_build_concolic_unop(
    unop: UnaryOp,
    source: SymValRef,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) -> SymValRef {
    unsafe {
        if source.is_concrete() {
            return SymValRef::concrete();
        }
        let vmctx = &mut *vmctx;
        let sym_val = SymVal::Unary(unop, source);
        vmctx.concolic.store(sym_val, module_byte_offset)
    }
}

pub(crate) fn translate_build_concolic_unop(
    op: UnaryOp,
    source: Value,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) -> Value {
    let source_symex = state.get_concolic(&source);
    let op = bcx.ins().iconst(types::I8, op as i64);
    let module_byte_location = iconst_module_byte_location(bcx, state);
    let [res] = state.host_call(
        bcx,
        builtin_build_concolic_unop as unsafe extern "C" fn(_, _, _, _) -> SymValRef,
        &[op, source_symex, module_byte_location],
    );
    res
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum ValTy {
    I32,
    I64,
    F32,
    F64,
}

impl From<Type> for ValTy {
    fn from(ty: Type) -> Self {
        match ty {
            types::I32 => Self::I32,
            types::I64 => Self::I64,
            types::F32 => Self::F32,
            types::F64 => Self::F64,
            _ => unreachable!(),
        }
    }
}

impl ValTy {
    fn convert_val_to_u64(&self, val: Value, bcx: &mut FunctionBuilder) -> Value {
        match self {
            Self::I32 => bcx.ins().uextend(types::I64, val),
            Self::I64 => val,
            Self::F32 => {
                let val = bcx.ins().bitcast(types::I32, MemFlags::new(), val);
                bcx.ins().uextend(types::I64, val)
            }
            Self::F64 => bcx.ins().bitcast(types::I64, MemFlags::new(), val),
        }
    }
}

fn concrete_to_const(
    val: SymValRef,
    concrete: u64,
    ty: ValTy,
    vmctx: &mut VMContext,
    module_byte_offset: u32,
) -> SymValRef {
    if !val.is_concrete() {
        return val;
    }
    debug_assert!(ty as u8 <= ValTy::F64 as u8);
    let symval = match ty {
        ValTy::I32 => SymVal::ConstI32(concrete as u32),
        ValTy::I64 => SymVal::ConstI64(concrete),
        ValTy::F32 => SymVal::ConstF32(f32::from_bits(concrete as u32).into()),
        ValTy::F64 => SymVal::ConstF64(f64::from_bits(concrete).into()),
    };
    vmctx.concolic.store(symval, module_byte_offset)
}

unsafe extern "C" fn builtin_build_concolic_binop(
    binop: concolic::BinaryOp,
    mut a: SymValRef,
    mut b: SymValRef,
    a_conc: u64,
    b_conc: u64,
    ty: ValTy,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) -> SymValRef {
    unsafe {
        let vmctx = &mut *vmctx;
        if a.is_concrete() && b.is_concrete() {
            return SymValRef::concrete();
        }
        a = concrete_to_const(a, a_conc, ty, vmctx, module_byte_offset);
        b = concrete_to_const(b, b_conc, ty, vmctx, module_byte_offset);
        let sym_val = SymVal::Binary(binop, a, b);
        vmctx.concolic.store(sym_val, module_byte_offset)
    }
}

pub(crate) fn translate_build_concolic_binop(
    op: concolic::BinaryOp,
    a: Value,
    b: Value,
    ty: Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) -> Value {
    // TODO(cranelift): do concreteness-checks in an inlined clif function? should help regalloc a bunch
    let a_symex = state.get_concolic(&a);
    let b_symex = state.get_concolic(&b);
    let ty_: ValTy = ty.into();
    let a = ty_.convert_val_to_u64(a, bcx);
    let b = ty_.convert_val_to_u64(b, bcx);
    let op = bcx.ins().iconst(types::I8, op as i64);
    let ty_ = bcx.ins().iconst(types::I8, ty_ as i64);
    let module_byte_location = iconst_module_byte_location(bcx, state);

    let [res] = state.host_call(
        bcx,
        builtin_build_concolic_binop as unsafe extern "C" fn(_, _, _, _, _, _, _, _) -> SymValRef,
        &[op, a_symex, b_symex, a, b, ty_, module_byte_location],
    );
    res
}

unsafe extern "C" fn builtin_build_concolic_select(
    mut cond: SymValRef,
    mut a: SymValRef,
    mut b: SymValRef,
    cond_conc: u32,
    a_conc: u64,
    b_conc: u64,
    ty: ValTy,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) -> SymValRef {
    unsafe {
        let vmctx = &mut *vmctx;
        if cond.is_concrete() && a.is_concrete() && b.is_concrete() {
            return SymValRef::concrete();
        }
        if cond.is_concrete() {
            return if cond_conc != 0 { a } else { b };
        }
        cond = concrete_to_const(
            cond,
            cond_conc as u64,
            ValTy::I32,
            vmctx,
            module_byte_offset,
        );
        a = concrete_to_const(a, a_conc, ty, vmctx, module_byte_offset);
        b = concrete_to_const(b, b_conc, ty, vmctx, module_byte_offset);
        let sym_val = SymVal::Select {
            condition: cond,
            a,
            b,
        };
        vmctx.concolic.store(sym_val, module_byte_offset)
    }
}

pub(crate) fn translate_build_concolic_select(
    cond: Value,
    a: Value,
    b: Value,
    ty: Type,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) -> Value {
    let cond_symex = state.get_concolic(&cond);
    let a_symex = state.get_concolic(&a);
    let b_symex = state.get_concolic(&b);
    let ty_: ValTy = ty.into();
    let a = ty_.convert_val_to_u64(a, bcx);
    let b = ty_.convert_val_to_u64(b, bcx);
    let ty_ = bcx.ins().iconst(types::I8, ty_ as i64);
    let module_byte_location = iconst_module_byte_location(bcx, state);

    let [res] = state.host_call(
        bcx,
        builtin_build_concolic_select
            as unsafe extern "C" fn(_, _, _, _, _, _, _, _, _) -> SymValRef,
        &[
            cond_symex,
            a_symex,
            b_symex,
            cond,
            a,
            b,
            ty_,
            module_byte_location,
        ],
    );
    res
}

unsafe extern "C" fn builtin_build_concolic_memory_load(
    addr32: SymValRef,
    addr32_concrete: u32,
    fixed_offset: u32,
    kind: concolic::MemoryAccessKind,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) -> SymValRef {
    unsafe {
        let vmctx = &mut *vmctx;
        if !addr32.is_concrete() {
            let location = Location::from_u64(location);
            vmctx.concolic.push_memory_constraint(
                location,
                addr32,
                addr32_concrete,
                concolic::MemoryConstraintPurpose::LoadWithFixedOffset(fixed_offset),
            );
        }
        let memory = vmctx.heap_alloc.as_mut_slice();
        vmctx.concolic.memory_load(
            addr32,
            addr32_concrete,
            fixed_offset,
            kind,
            memory,
            module_byte_offset,
        )
    }
}

pub(crate) fn translate_build_concolic_memory_load(
    addr32: Value,
    offset: u32,
    kind: concolic::MemoryAccessKind,
    location: Location,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) -> Value {
    let offset = bcx.ins().iconst(types::I32, offset as i64);
    let kind = bcx.ins().iconst(types::I8, kind as i64);
    let symval_addr32 = state.get_concolic(&addr32);
    let location = bcx.ins().iconst(types::I64, location.as_u64() as i64);
    let module_byte_location = iconst_module_byte_location(bcx, state);

    let [res] = state.host_call(
        bcx,
        builtin_build_concolic_memory_load
            as unsafe extern "C" fn(_, _, _, _, _, _, _) -> SymValRef,
        &[
            symval_addr32,
            addr32,
            offset,
            kind,
            location,
            module_byte_location,
        ],
    );
    res
}

unsafe extern "C" fn builtin_build_concolic_memory_store(
    value: SymValRef,
    addr32: SymValRef,
    addr32_concrete: u32,
    fixed_offset: u32,
    kind: concolic::MemoryAccessKind,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        let vmctx = &mut *vmctx;
        if !addr32.is_concrete() {
            let location = Location::from_u64(location);
            vmctx.concolic.push_memory_constraint(
                location,
                addr32,
                addr32_concrete,
                concolic::MemoryConstraintPurpose::StoreWithFixedOffset(fixed_offset),
            );
        }
        vmctx.concolic.memory_store(
            addr32,
            addr32_concrete,
            fixed_offset,
            value,
            kind,
            module_byte_offset,
        );
    }
}

pub(crate) fn translate_concolic_memory_store(
    val: Value,
    addr32: Value,
    offset: u32,
    kind: concolic::MemoryAccessKind,
    location: Location,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let offset = bcx.ins().iconst(types::I32, offset as i64);
    let kind = bcx.ins().iconst(types::I8, kind as i64);
    let symval_val = state.get_concolic(&val);
    let symval_addr32 = state.get_concolic(&addr32);
    let location = bcx.ins().iconst(types::I64, location.as_u64() as i64);
    let module_byte_location = iconst_module_byte_location(bcx, state);

    state.host_call(
        bcx,
        builtin_build_concolic_memory_store as unsafe extern "C" fn(_, _, _, _, _, _, _, _),
        &[
            symval_val,
            symval_addr32,
            addr32,
            offset,
            kind,
            location,
            module_byte_location,
        ],
    );
}

unsafe extern "C" fn builtin_concolic_push_path_constraint_nz(
    condition: SymValRef,
    taken: u32,
    location: u64,
    vmctx: *mut VMContext,
) {
    unsafe {
        if condition.is_concrete() {
            return;
        }
        let taken = taken != 0u32;
        let location = Location::from_u64(location);
        let vmctx = &mut *vmctx;
        vmctx
            .concolic
            .push_path_constraint(location, condition, taken);
    }
}

pub(crate) fn translate_concolic_push_path_constraint_nz(
    cond: Value,
    location: Location,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let symval_condition = state.get_concolic(&cond);
    let taken = cond;
    let location = bcx.ins().iconst(types::I64, location.as_u64() as i64);

    state.host_call(
        bcx,
        builtin_concolic_push_path_constraint_nz as unsafe extern "C" fn(_, _, _, _),
        &[symval_condition, taken, location],
    );
}

unsafe extern "C" fn builtin_concolic_push_path_constraint_eq(
    value_sym: SymValRef,
    value: u64,
    val_ty: ValTy,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        if value_sym.is_concrete() {
            return;
        }
        let vmctx = &mut *vmctx;
        let value_const_sym = concrete_to_const(
            SymValRef::concrete(),
            value,
            val_ty,
            vmctx,
            module_byte_offset,
        );
        let location = Location::from_u64(location);
        let condition = vmctx.concolic.store(
            SymVal::Binary(concolic::BinaryOp::Eq, value_sym, value_const_sym),
            module_byte_offset,
        );
        vmctx
            .concolic
            .push_path_constraint(location, condition, true);
    }
}

pub(crate) fn translate_concolic_push_path_constraint_eq(
    value: Value,
    ty: Type,
    location: Location,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let ty_: ValTy = ty.into();
    let ty = bcx.ins().iconst(types::I8, ty_ as i64);
    let symval = state.get_concolic(&value);
    let location = bcx.ins().iconst(types::I64, location.as_u64() as i64);
    let module_byte_location = iconst_module_byte_location(bcx, state);

    let value = ty_.convert_val_to_u64(value, bcx);
    state.host_call(
        bcx,
        builtin_concolic_push_path_constraint_eq as unsafe extern "C" fn(_, _, _, _, _, _),
        &[symval, value, ty, location, module_byte_location],
    );
}

#[expect(unused)]
pub(crate) fn translate_concolic_try_alternative(
    value: Value,
    description: &'static str,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    // let op = bcx.ins().iconst(types::I8, op as i64);
    // let sig = signature(&[types::I32, types::I32, types::I32], &[types::I32], true);
    // let sig = state.import_signature(sig, bcx);
    // let callee = state.host_ptr(bcx, builtin_concolic_push_path_constraint as *const fn());
    // let vmctx = fetch_vmctx(bcx);
    // let call = bcx.ins().call_indirect(sig, callee, &[op, a, b, vmctx]);
    // bcx.inst_results(call)[0]
}

unsafe extern "C" fn builtin_concolic_trace_libcall_memcmp(
    a: u32,
    b: u32,
    n: u32,
    a_sym: SymValRef,
    b_sym: SymValRef,
    n_sym: SymValRef,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        if a_sym.is_concrete() && b_sym.is_concrete() && n_sym.is_concrete() {
            let vmctx = &mut *vmctx;
            let memory = vmctx.heap_alloc.as_mut_slice();
            vmctx.concolic.trace_memcmp(
                Location::from_u64(location),
                a as usize,
                b as usize,
                n as usize,
                memory,
                module_byte_offset,
            );
        }
    }
}

unsafe extern "C" fn builtin_concolic_trace_libcall_strncmp(
    a: u32,
    b: u32,
    n: u32,
    a_sym: SymValRef,
    b_sym: SymValRef,
    n_sym: SymValRef,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        if a_sym.is_concrete() && b_sym.is_concrete() && n_sym.is_concrete() {
            let vmctx = &mut *vmctx;
            let memory = vmctx.heap_alloc.as_mut_slice();
            vmctx.concolic.trace_strcmplike(
                Location::from_u64(location),
                a as usize,
                b as usize,
                Some(n as usize),
                false,
                memory,
                module_byte_offset,
            );
        }
    }
}

unsafe extern "C" fn builtin_concolic_trace_libcall_strncasecmp(
    a: u32,
    b: u32,
    n: u32,
    a_sym: SymValRef,
    b_sym: SymValRef,
    n_sym: SymValRef,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        if a_sym.is_concrete() && b_sym.is_concrete() && n_sym.is_concrete() {
            let vmctx = &mut *vmctx;
            let memory = vmctx.heap_alloc.as_mut_slice();
            vmctx.concolic.trace_strcmplike(
                Location::from_u64(location),
                a as usize,
                b as usize,
                Some(n as usize),
                true,
                memory,
                module_byte_offset,
            );
        }
    }
}

unsafe extern "C" fn builtin_concolic_trace_libcall_strcmp(
    a: u32,
    b: u32,
    a_sym: SymValRef,
    b_sym: SymValRef,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        if a_sym.is_concrete() && b_sym.is_concrete() {
            let vmctx = &mut *vmctx;
            let memory = vmctx.heap_alloc.as_mut_slice();
            vmctx.concolic.trace_strcmplike(
                Location::from_u64(location),
                a as usize,
                b as usize,
                None,
                false,
                memory,
                module_byte_offset,
            );
        }
    }
}
unsafe extern "C" fn builtin_concolic_trace_libcall_strcasecmp(
    a: u32,
    b: u32,
    a_sym: SymValRef,
    b_sym: SymValRef,
    location: u64,
    module_byte_offset: u32,
    vmctx: *mut VMContext,
) {
    unsafe {
        if a_sym.is_concrete() && b_sym.is_concrete() {
            let vmctx = &mut *vmctx;
            let memory = vmctx.heap_alloc.as_mut_slice();
            vmctx.concolic.trace_strcmplike(
                Location::from_u64(location),
                a as usize,
                b as usize,
                None,
                true,
                memory,
                module_byte_offset,
            );
        }
    }
}

pub(crate) fn translate_concolic_trace_libcall(
    libcall: Libfunc,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let builtin_fptr = match libcall {
        Libfunc::Memcmp => builtin_concolic_trace_libcall_memcmp as *const fn(),
        Libfunc::Strncmp => builtin_concolic_trace_libcall_strncmp as *const fn(),
        Libfunc::Strncasecmp => builtin_concolic_trace_libcall_strncasecmp as *const fn(),
        Libfunc::Strcmp => builtin_concolic_trace_libcall_strcmp as *const fn(),
        Libfunc::Strcasecmp => builtin_concolic_trace_libcall_strcasecmp as *const fn(),
    };
    let fty_params = wasm2tys(state.fspec().ty.params());
    let mut param_tys = Vec::new();
    param_tys.extend_from_slice(&fty_params);
    param_tys.extend_from_slice(&vec![types::I32; fty_params.len()]);
    param_tys.push(types::I64); // location
    param_tys.push(types::I32); // module_byte_location
    let mut params = Vec::new();
    for (idx, _) in fty_params.iter().enumerate() {
        params.push(bcx.use_var(state.get_slot(idx as u32)));
    }
    for (idx, _) in fty_params.iter().enumerate() {
        params.push(bcx.use_var(state.get_slot_concolic(idx as u32)));
    }
    let loc = state.caller.unwrap_or_else(|| state.loc());
    params.push(bcx.ins().iconst(types::I64, loc.as_u64() as i64));
    let module_byte_location = iconst_module_byte_location(bcx, state);
    params.push(module_byte_location);

    state.host_call_with_types(bcx, builtin_fptr, &param_tys, &[], &params);
}

pub(crate) fn translate_concolic_debug_verify(
    value: Value,
    ty: Type,
    symval: Value,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    if state.dead(bcx) {
        return;
    }
    let ty_: ValTy = ty.into();
    let value = ty_.convert_val_to_u64(value, bcx);
    let ty_ = bcx.ins().iconst(types::I8, ty_ as i64);
    let location = bcx.ins().iconst(types::I64, state.loc().as_u64() as i64);

    #[cfg(feature = "concolic")]
    state.host_call(
        bcx,
        builtin_concolic_debug_verify as unsafe extern "C" fn(_, _, _, _, _),
        &[symval, value, ty_, location],
    );
    #[cfg(not(feature = "concolic"))]
    let _ = (symval, value, ty_, location);
}

#[cfg(feature = "concolic")]
unsafe extern "C" fn builtin_concolic_debug_verify(
    value_sym: SymValRef,
    value: u64,
    _val_ty: ValTy,
    location: u64,
    vmctx: *mut VMContext,
) {
    if value_sym.is_concrete() {
        return;
    }
    let vmctx = &mut *vmctx;
    let location = Location::from_u64(location);

    if let Some(res) = vmctx
        .concolic
        .eval_as_u64_with_input(value_sym, &vmctx.input)
    {
        if res != value {
            dbg!(location, res, value, vmctx.concolic.fetch(value_sym));
            std::fs::write("/tmp/builtin_concolic_debug_verify.bin", &vmctx.input).unwrap();
        }
        assert_eq!(res, value);
    }
}

unsafe extern "C" fn builtin_concolic_memory_fill(
    dst: SymValRef,
    dst_conc: u32,
    val: SymValRef,
    _val_conc: u32,
    len: SymValRef,
    len_conc: u32,
    location: u64,
    vmctx: *mut VMContext,
) {
    unsafe {
        let location = Location::from_u64(location);
        let vmctx = &mut *vmctx;
        if !dst.is_concrete() {
            vmctx.concolic.push_memory_constraint(
                location,
                dst,
                dst_conc,
                concolic::MemoryConstraintPurpose::Store,
            );
        }
        if !len.is_concrete() {
            vmctx.concolic.push_memory_constraint(
                location,
                len,
                len_conc,
                concolic::MemoryConstraintPurpose::MemoryIntrinsicLength,
            );
        }
        vmctx.concolic.memory_fill(dst_conc, val, len_conc);
    }
}

pub(crate) fn translate_concolic_memory_fill(
    dst: Value,
    val: Value,
    len: Value,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let location = bcx.ins().iconst(types::I64, state.loc().as_u64() as i64);
    state.host_call(
        bcx,
        builtin_concolic_memory_fill as unsafe extern "C" fn(_, _, _, _, _, _, _, _),
        &[
            state.get_concolic(&dst),
            dst,
            state.get_concolic(&val),
            val,
            state.get_concolic(&len),
            len,
            location,
        ],
    );
}

unsafe extern "C" fn builtin_concolic_memory_copy(
    dst: SymValRef,
    dst_conc: u32,
    src: SymValRef,
    src_conc: u32,
    len: SymValRef,
    len_conc: u32,
    location: u64,
    vmctx: *mut VMContext,
) {
    unsafe {
        let location = Location::from_u64(location);
        let vmctx = &mut *vmctx;
        if !dst.is_concrete() {
            vmctx.concolic.push_memory_constraint(
                location,
                dst,
                dst_conc,
                concolic::MemoryConstraintPurpose::Store,
            );
        }
        if !src.is_concrete() {
            vmctx.concolic.push_memory_constraint(
                location,
                src,
                src_conc,
                concolic::MemoryConstraintPurpose::Load,
            );
        }
        if !len.is_concrete() {
            vmctx.concolic.push_memory_constraint(
                location,
                len,
                len_conc,
                concolic::MemoryConstraintPurpose::MemoryIntrinsicLength,
            );
        }
        vmctx.concolic.memory_copy(dst_conc, src_conc, len_conc);
    }
}

pub(crate) fn translate_concolic_memory_copy(
    dst: Value,
    src: Value,
    len: Value,
    state: &mut FuncTranslator,
    bcx: &mut FunctionBuilder,
) {
    let location = bcx.ins().iconst(types::I64, state.loc().as_u64() as i64);
    state.host_call(
        bcx,
        builtin_concolic_memory_copy as unsafe extern "C" fn(_, _, _, _, _, _, _, _),
        &[
            state.get_concolic(&dst),
            dst,
            state.get_concolic(&src),
            src,
            state.get_concolic(&len),
            len,
            location,
        ],
    );
}
