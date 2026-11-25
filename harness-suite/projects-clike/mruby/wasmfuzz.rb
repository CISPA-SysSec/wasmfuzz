# Native host build: only provides mrbc for compiling the mrblib sources.
MRuby::Build.new do |conf|
  conf.toolchain :gcc
end

# wasm32-wasip1 library with the default gembox minus stdlib-io (mruby-io,
# mruby-socket, mruby-dir, ... do not build on WASI; upstream's
# build_config/wasi.rb drops them too). The FuzzBench build uses `default`.
MRuby::CrossBuild.new('wasi') do |conf|
  conf.toolchain :clang

  cflags = ENV.fetch('WASM_CFLAGS').split
  [conf.cc, conf.objc, conf.asm].each do |cc|
    cc.command = ENV.fetch('WASM_CC')
    cc.flags = [%w(-std=gnu99), cflags]
  end
  conf.cxx.command = ENV.fetch('WASM_CXX')
  conf.cxx.flags = [ENV.fetch('WASM_CXXFLAGS').split]
  conf.linker.command = ENV.fetch('WASM_CC')
  conf.linker.flags = cflags
  conf.archiver.command = "#{ENV.fetch('WASI_SDK_PREFIX')}/bin/llvm-ar"

  conf.gembox 'stdlib'
  conf.gembox 'stdlib-ext'
  conf.gembox 'math'
  conf.gembox 'metaprog'
end
