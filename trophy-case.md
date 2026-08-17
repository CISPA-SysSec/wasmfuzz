Bugs that reproduce in native builds:
- Stack exhaustion in wgpu's WGSL parser: https://github.com/gfx-rs/wgpu/issues/5757#issuecomment-2830427879
- rust-regex validation panic for dense::DFA::from\_bytes https://github.com/rust-lang/regex/pull/1295
- comrak footnote autolink assert: https://github.com/kivikakk/comrak/issues/595
- jxl-oxide NaN crash https://github.com/tirr-c/jxl-oxide/pull/485#event-20156094711
- image-tiff crash https://github.com/image-rs/image-tiff/pull/305
- zlib-rs invalid deflate stream https://github.com/trifectatechfoundation/zlib-rs/issues/455
- libtiff assertion in `_TIFFSwab24BitData`: https://gitlab.com/libtiff/libtiff/-/work_items/669#note_3432756113
- fontations read-fonts oob panic in fvar.rs: https://github.com/googlefonts/fontations/pull/1903
- jxl-rs: multiple findings (https://github.com/libjxl/jxl-rs/pull/811, ..)

WebAssembly-only bugs:
- Memory corruption in wasi-libc: https://github.com/WebAssembly/wasi-libc/pull/511
- Panic in jxl-oxide https://github.com/tirr-c/jxl-oxide/issues/392
