pub(crate) fn malloc_symbol(spec: &super::ModuleSpec) -> &'static str {
    if spec.exported_funcs.contains_key("wasmfuzz_malloc") {
        "wasmfuzz_malloc"
    } else if spec.exported_funcs.contains_key("malloc") {
        "malloc"
    } else {
        panic!("harness doesn't have wasmfuzz_malloc or malloc export")
    }
}
