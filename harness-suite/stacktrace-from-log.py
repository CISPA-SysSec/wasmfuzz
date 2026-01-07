# log example:
# JIT-TRACE: entering _7097_ruff_python_parser::lexer::Lexer::next_token::hb3a69ba444f406c9 (Tracing(<none>, [stdout]))
# JIT-TRACE: entering _7006_core::ptr::drop_in_place<ruff_python_parser::token::TokenValue>::hb6a5c3d2fb316f79 (Tracing(<none>, [stdout]))
# JIT-TRACE: returning from _7006_core::ptr::drop_in_place<ruff_python_parser::token::TokenValue>::hb6a5c3d2fb316f79 via function end
# [...]

import sys, fileinput

stack = []
for line in fileinput.input(sys.argv[1:]):
    if line.startswith("JIT-TRACE: entering "):
        func = line.split(" ")[2]
        stack.append(func)
        # print(line.strip())
    elif line.startswith("JIT-TRACE: returning from "):
        func = line.split(" ")[3]
        ref_func = stack.pop()
        # print(line.strip())
        assert func == ref_func, f"{func} != {ref_func}"
    else:
        print(line.strip())
        for line in stack:
            print("|   ", line)

print(f"Final stack trace ({len(stack)} frames)")
for line in stack:
    print("|   ", line)
