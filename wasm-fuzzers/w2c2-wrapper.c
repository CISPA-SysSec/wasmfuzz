// ./build/w2c2/w2c2 -p -g /tmp/harness/x harness.c
// clang -g -fsanitize=fuzzer harness.c -I. -I w2c2/ -I wasi/ ~/_GitRepos/wasmfuzz-cispa-syssec/wasm-fuzzers/w2c2-wrapper.c ./build/wasi/libw2c2wasi.a
#include <fcntl.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <w2c2_base.h>
#include <wasi.h>

#include "harness.h"

typedef uint32_t u32;
typedef uint64_t u64;

// A bit of a hack: if there's a `wasmfuzz_malloc` export in the WASM module,
// prefer that over a `malloc` export
__attribute__((weak)) u32 harness_malloc(harnessInstance *instance, u32 size) {
  abort(); // this should never be reached
}
__attribute__((weak)) u32 harness_wasmfuzz_malloc(harnessInstance *instance,
                                                  u32 size) {
  return harness_malloc(instance, size);
}
// something simple like this would be nice, but we this doesn't work :(
#if defined(harness_wasmfuzz_malloc)
#define harness_malloc harness_wasmfuzz_malloc
#endif

void trap(Trap trap) {
  fprintf(stderr, "TRAP: %s\n", trapDescription(trap));
  abort();
}

wasmMemory *wasiMemory(void *instance) {
  return harness_memory((harnessInstance *)instance);
}

harnessInstance module;
u32 module_buf_off;
u32 module_buf_cap = 65536;
void *module_buf_ptr;

void harness_module_init() {
  char *args[] = {NULL};
  if (!wasiInit(0, args, args)) {
    fprintf(stderr, "failed to initialize WASI\n");
    abort();
  }

  harnessInstantiate(&module, NULL);
  module_buf_off = harness_wasmfuzz_malloc(&module, module_buf_cap);
  module_buf_ptr = &harness_memory(&module)->data[module_buf_off];
  // if (setjmp(wasm_rt_jmp_buf) != 0) abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  harness_module_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // if (Size >= module_buf_cap) return 0;
  Size &= module_buf_cap - 1;
  memcpy(module_buf_ptr, Data, Size);
  harness_LLVMFuzzerTestOneInput(&module, module_buf_off, Size);
  return 0;
}

#ifdef STANDALONE
int main(int argc, char **argv) {

  unsigned char buf[65536];
  ssize_t len;
  int fd = 0;
  if (argc > 1)
    fd = open(argv[1], O_RDONLY);

  if ((len = read(fd, buf, sizeof(buf))) <= 0)
    exit(0);

  LLVMFuzzerInitialize(&argc, &argv);
  LLVMFuzzerTestOneInput(buf, len);
  exit(0);
}
#endif

#ifdef __AFL_FUZZ_TESTCASE_LEN
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

/* To ensure checks are not optimized out it is recommended to disable
   code optimization for the fuzzer harness main() */
#pragma clang optimize off
#pragma GCC optimize("O0")
int main(int argc, char **argv) {
  // TODO: workaround for cmplog crash
  // LLVMFuzzerInitialize(&argc, &argv);
  harness_module_init();
  ssize_t len;
  unsigned char *buf;
  __AFL_INIT();
  buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(10000)) {
    len = __AFL_FUZZ_TESTCASE_LEN;
    LLVMFuzzerTestOneInput(buf, len);
  }
  return 0;
}
#endif
