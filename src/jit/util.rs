use cranelift::codegen::ir;
use cranelift::prelude::MemFlags;
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

pub trait MemFlagsExt {
    fn trusted_ro() -> MemFlags;
}

impl MemFlagsExt for MemFlags {
    fn trusted_ro() -> MemFlags {
        let mut flags = Self::trusted();
        flags.set_readonly();
        flags
    }
}
