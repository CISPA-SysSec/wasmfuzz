/* wasm32-wasip1 has no setjmp/longjmp (without the EH proposal).
 * libpcap only longjmps out of pcap_compile() on a filter compile/optimize
 * error, after which fuzz_both just closes the handle, so every longjmp becomes
 * the wasmfuzz `exit_testcase` import and setjmp always returns 0. */
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
