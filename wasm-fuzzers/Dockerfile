FROM ubuntu:24.04

RUN apt-get update && apt-get install -y wget software-properties-common
RUN apt-get install -y \
    autoconf \
    automake \
    build-essential \
    cmake \
    libtool \
    llvm llvm-dev clang \
    make \
    ninja-build \
    sudo \
    unzip \
    zlib1g-dev \
    patchelf \
    git sed rsync

# install wafl
# RUN git clone https://github.com/fgsect/WAFL
RUN git clone https://github.com/Mrmaxmeier/WAFL
WORKDIR /WAFL
RUN git checkout fix-symbol-overlap && git submodule update --init && \
    git submodule update --recursive --remote

# Compile and install AFL++
WORKDIR /WAFL/AFLplusplus
RUN make WAFL_MODE=1 TEST_MMAP=1 install
# RUN make install
# NOTE: wafl expects AFLplusplus instrumentation passes at /AFLplusplus/x-pass.so
RUN ln -s /WAFL/AFLplusplus /


# Compile and install the WAVM part
WORKDIR /WAFL/build
RUN cmake -G Ninja ../ -DCMAKE_BUILD_TYPE=RelWithDebInfo
RUN ninja && ninja install && \
    patchelf --add-needed /usr/local/lib/libWAVM.so /usr/local/bin/wavm


# install wizer for wasm2c pre-init
RUN wget -nv "https://github.com/bytecodealliance/wizer/releases/download/v3.0.1/wizer-v3.0.1-`uname -m`-linux.tar.xz" && \
    tar xf wizer-v3.0.1-`uname -m`-linux.tar.xz \
        -C /usr/bin/ --strip-components 1 \
        wizer-v3.0.1-`uname -m`-linux/wizer


# install up-to-date wabt (we need ~1.0.31)
# TODO: support aarch64
RUN wget -nv https://github.com/WebAssembly/wabt/releases/download/1.0.31/wabt-1.0.31-ubuntu.tar.gz && \
    tar -kxzf wabt-1.0.31-ubuntu.tar.gz --strip-components 1 -C /usr/
# NOTE: We do a silly dance here: wabt doesn't provide aarch64 binaries, and we'd like to provide multiarch images.
#       So: We install wasmtime and use their WASI build of wasm2c :)
#RUN curl https://wasmtime.dev/install.sh -sSf | bash
#RUN wget -nv https://github.com/WebAssembly/wabt/releases/download/1.0.31/wabt-1.0.31-wasi.tar.gz && \
#    tar -kxzf wabt-1.0.31-wasi.tar.gz --strip-components 1 -C /usr/

WORKDIR /
COPY wasmfuzz.sh wafl.sh libfuzzer-wasm2c.sh afl++-wasm2c.sh /usr/bin/
COPY shim-for-wafl.sh /usr/bin/
COPY wasm2c-wrapper.c /
RUN chmod +x /usr/bin/*.sh
RUN mkdir -p /seeds/ && echo -n "YELLOW SUBMARINE" > /seeds/seed && mkdir -p /corpus/
