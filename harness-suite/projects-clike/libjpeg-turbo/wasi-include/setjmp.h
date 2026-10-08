/* wasm32-wasip1 has no setjmp/longjmp (without the EH proposal).
 * libjpeg-turbo (turbojpeg.c, cjpeg.c) and the fuzz harnesses only use
 * longjmp to bail out of a failed decode/encode, so we turn every longjmp into
 * the wasmfuzz `exit_testcase` import and make setjmp always return 0. */
#ifndef WASMFUZZ_SETJMP_SHIM_H
#define WASMFUZZ_SETJMP_SHIM_H

#ifdef __cplusplus
extern "C" {
#endif

void wasmfuzz_exit_testcase(void)
    __attribute__((__noreturn__))
    __attribute__((__import_module__("wasmfuzz"), __import_name__("exit_testcase")));

#ifdef __cplusplus
}
#endif

typedef int jmp_buf[1];
#define setjmp(b) ((void)(b), 0)
#define longjmp(b, v) ((void)(b), (void)(v), wasmfuzz_exit_testcase())

#endif
