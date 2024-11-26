// wasm2c test-u32-cmp -o wasm2c-harness.c -n harness
// clang -g -I /usr/share/wabt/wasm2c/ -o wasm2c-harness wasm2c-wrapper.c wasm2c-harness.c /usr/share/wabt/wasm2c/wasm-rt-impl.c
#include <wasm-rt.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdio.h>
#include "wasm-rt-impl.h"
#include "wasm2c-harness.h"

typedef uint32_t u32;
typedef uint64_t u64;

#if !defined(MODULE_COUNT)
#define MODULE_COUNT 1
#define IMPORT_WASI
#endif


// A bit of a hack: if there's a `wasmfuzz_malloc` export in the WASM module, prefer that over a `malloc` export
__attribute__((weak)) u32 Z_harnessZ_malloc(Z_harness_instance_t* instance, u32 size) {
  abort(); // this should never be reached
}
__attribute__((weak)) u32 Z_harnessZ_wasmfuzz_malloc(Z_harness_instance_t* instance, u32 size) {
  return Z_harnessZ_malloc(instance, size);
}
// something simple like this would be nice, but we this doesn't work :(
#if defined(Z_harnessZ_wasmfuzz_malloc)
#define Z_harnessZ_malloc Z_harnessZ_wasmfuzz_malloc
#endif


Z_harness_instance_t module;
u32 module_buf_off;
u32 module_buf_cap = 65536;
void* module_buf_ptr;

void harness_module_init() {
  wasm_rt_init();
  Z_harness_init_module();
  #if MODULE_COUNT == 0
  Z_harness_instantiate(&module);
  #elif MODULE_COUNT == 1
  Z_harness_instantiate(&module, NULL);
  #elif MODULE_COUNT == 2
  Z_harness_instantiate(&module, NULL, NULL);
  #elif MODULE_COUNT == 3
  Z_harness_instantiate(&module, NULL, NULL, NULL);
  #else
  #error "unsupported MODULE_COUNT"
  #endif
  module_buf_off = Z_harnessZ_wasmfuzz_malloc(&module, module_buf_cap);
  module_buf_ptr = &Z_harnessZ_memory(&module)->data[module_buf_off];
  if (setjmp(wasm_rt_jmp_buf) != 0) abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  harness_module_init();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  // if (Size >= module_buf_cap) return 0;
  Size &= module_buf_cap-1;
  memcpy(module_buf_ptr, Data, Size);
  Z_harnessZ_LLVMFuzzerTestOneInput(&module, module_buf_off, Size);
  return 0;
}

#ifdef IMPORT_ENV
u32 Z_envZ___main_argc_argv(struct Z_env_instance_t* _inst, u32 _a, u32 _b) { abort(); }
#endif

#ifdef IMPORT_WASI
/* import: 'wasi_snapshot_preview1' 'fd_close' */
u32 Z_wasi_snapshot_preview1Z_fd_close(struct Z_wasi_snapshot_preview1_instance_t* _inst, u32 x2) { return 0; }
/* import: 'wasi_snapshot_preview1' 'fd_seek' */
u32 Z_wasi_snapshot_preview1Z_fd_seek(struct Z_wasi_snapshot_preview1_instance_t* _inst, u32 x2, u64 x3, u32 x4, u32 x5) { return 0; }
/* import: 'wasi_snapshot_preview1' 'fd_write' */
u32 Z_wasi_snapshot_preview1Z_fd_write(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 fd, u32 iovs_ptr, u32 iovs_len, u32 nwritten_ptr) {
  // void* mem = Z_harnessZ_memory(instance)->data;
  void* mem = Z_harnessZ_memory(&module)->data;
  typedef struct __wasi_ciovec_t {
    uint32_t buf_ptr;
    uint32_t buf_len;
  } __wasi_ciovec_t;
  __wasi_ciovec_t* iovs = &mem[iovs_ptr];
  uint32_t count = 0;
  for (int i = 0; i < iovs_len; i++) {
    count += iovs[i].buf_len;
    // printf("%.*s", iovs[i].buf_len, (char*) &mem[iovs[i].buf_ptr]);
  }
  *(uint32_t*)(&mem[nwritten_ptr]) = count;
  return 0;
}

u32 Z_wasi_snapshot_preview1Z_environ_sizes_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 buf1, u32 buf2) {
  void* mem = Z_harnessZ_memory(&module)->data;
  *(uint32_t*)&mem[buf1] = 0;
  *(uint32_t*)&mem[buf2] = 0;
  return 0;
}

u32 Z_wasi_snapshot_preview1Z_fd_fdstat_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 fd, u32 buf_ptr) { return 0; }
u32 Z_wasi_snapshot_preview1Z_clock_time_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u64 _b, u32 _c) { return 0; }
u32 Z_wasi_snapshot_preview1Z_random_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { return 0; }

u32 Z_wasi_snapshot_preview1Z_fd_tell(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_fd_read(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b, u32 _c, u32 _d) { abort(); }
u32 Z_wasi_snapshot_preview1Z_environ_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_fd_fdstat_set_flags(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_path_unlink_file(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b, u32 _c) { abort(); }
u32 Z_wasi_snapshot_preview1Z_fd_filestat_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_path_open(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b, u32 _c, u32 _d, u32 _e, u64 _f, u64 _g, u32 _h, u32 _i) { abort(); }
u32 Z_wasi_snapshot_preview1Z_path_filestat_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b, u32 _c, u32 _d, u32 _e) { abort(); }
u32 Z_wasi_snapshot_preview1Z_fd_filestat_set_size(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u64 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_path_remove_directory(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b, u32 _c) { abort(); }
u32 Z_wasi_snapshot_preview1Z_fd_prestat_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_fd_prestat_dir_name(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b, u32 _c) { abort(); }
u32 Z_wasi_snapshot_preview1Z_args_sizes_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_args_get(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a, u32 _b) { abort(); }
u32 Z_wasi_snapshot_preview1Z_sched_yield(struct Z_wasi_snapshot_preview1_instance_t* instance) { abort(); }
void Z_wasi_snapshot_preview1Z_proc_exit(struct Z_wasi_snapshot_preview1_instance_t* instance, u32 _a) { abort(); }
#endif


#ifdef STANDALONE
int main(int argc, char **argv) {

  unsigned char buf[65536];
  ssize_t       len;
  int           fd = 0;
  if (argc > 1) fd = open(argv[1], O_RDONLY);

  if ((len = read(fd, buf, sizeof(buf))) <= 0) exit(0);

  LLVMFuzzerInitialize(&argc, &argv);
  LLVMFuzzerTestOneInput(buf, len);
  exit(0);
}
#endif

#ifdef __AFL_FUZZ_TESTCASE_LEN
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <limits.h>

__AFL_FUZZ_INIT();

/* To ensure checks are not optimized out it is recommended to disable
   code optimization for the fuzzer harness main() */
#pragma clang optimize off
#pragma GCC            optimize("O0")
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
