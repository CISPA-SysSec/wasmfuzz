use cranelift::codegen::ir;
use cranelift::frontend::FunctionBuilder;
use cranelift::prelude::MemFlagsData;
use wasmparser::ValType;

pub(crate) fn wasm2ty(ty: &ValType) -> ir::Type {
    match ty {
        ValType::I32 => ir::types::I32,
        ValType::I64 => ir::types::I64,
        ValType::F32 => ir::types::F32,
        ValType::F64 => ir::types::F64,
        _ => unimplemented!(),
    }
}

pub(crate) fn wasm2tys(wasmtys: &[ValType]) -> Vec<ir::Type> {
    wasmtys.iter().map(super::wasm2ty).collect::<Vec<_>>()
}

pub(crate) fn values_to_blockargs(vals: &[ir::Value]) -> Vec<ir::BlockArg> {
    vals.iter().map(|x| (*x).into()).collect()
}

pub trait MemFlagsExt {
    fn trusted_ro() -> MemFlagsData;
}

impl MemFlagsExt for MemFlagsData {
    fn trusted_ro() -> MemFlagsData {
        Self::trusted().with_readonly()
    }
}

pub(crate) fn intern_memflags(
    bcx: &mut FunctionBuilder<'_>,
    flags: ir::MemFlagsData,
) -> ir::MemFlags {
    bcx.func.dfg.mem_flags.insert_unchecked(flags)
}
