set -e
git clone-rev.sh https://github.com/python/cpython "$PROJECT/repo" 4ec6eb0496922cb466a84a81f9a60253b67fcedc
# Py_Initialize imports `encodings`; there is no stdlib on the (empty) WASI fs.
git -C "$PROJECT/repo" apply ../port-freeze-encodings.patch
# wasmfuzz calls LLVMFuzzerInitialize(NULL, NULL).
git -C "$PROJECT/repo" apply ../port-fuzzer-init-without-argv.patch
# fuzz_pycompile_source: the whole input is module source (no parameter prefix).
git -C "$PROJECT/repo" apply ../fuzz-pycompile-source.patch
# Skip `site` at start-up: nothing to find without a stdlib, ~40 % of the init fuel.
git -C "$PROJECT/repo" apply ../limit-init-without-site.patch
# Parser stack overflow in an f-/t-string middle: no tokenizing with the error pending.
git -C "$PROJECT/repo" apply ../fix-pegen-no-tokenizing-after-error.patch
