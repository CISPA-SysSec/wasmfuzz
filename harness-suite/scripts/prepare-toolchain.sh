#!/bin/bash
set -e

WASI_VERSION=24
WASI_VERSION_FULL=${WASI_VERSION}.0
WASI_DIR="wasi-sdk-${WASI_VERSION_FULL}-$(uname -m)-linux"
wget -q "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/${WASI_DIR}.tar.gz"
tar xvf "${WASI_DIR}.tar.gz"
WASI_SDK_PATH=$(pwd)/$WASI_DIR

wget -q https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/libs%2Fzlib%2F1.2.13%2B20230623-2993864/libz-1.2.13-wasi-sdk-20.0.tar.gz
tar xvf libz-1.2.13-wasi-sdk-20.0.tar.gz --directory="${WASI_SDK_PATH}/share/wasi-sysroot/"

mv "$WASI_SDK_PATH" /wasi-sdk

wget -q "https://github.com/bytecodealliance/wizer/releases/download/v3.0.1/wizer-v3.0.1-x86_64-linux.tar.xz"
tar xf wizer-v3.0.1-x86_64-linux.tar.xz \
    -C /usr/bin/ --strip-components 1 \
    wizer-v3.0.1-x86_64-linux/wizer

wget -q https://github.com/getsentry/symbolicator/releases/download/23.11.2/wasm-split-Linux-x86_64 -O /usr/bin/wasm-split
chmod +x /usr/bin/wasm-split

wget -q https://github.com/getsentry/sentry-cli/releases/download/2.23.0/sentry-cli-Linux-x86_64 -O /usr/bin/sentry-cli
chmod +x /usr/bin/sentry-cli

# Install a pinned Rust nightly toolchain
build-rust-harness.py --init-toolchain