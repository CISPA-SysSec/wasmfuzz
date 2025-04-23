#!/bin/bash
set -e +x

WASI_VERSION=25
WASI_VERSION_FULL=${WASI_VERSION}.0
WASI_DIR="wasi-sdk-${WASI_VERSION_FULL}-$(uname -m)-linux"
wget -q "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/${WASI_DIR}.tar.gz"
tar xf "${WASI_DIR}.tar.gz"
WASI_SDK_PATH=$(pwd)/$WASI_DIR

# TODO: get rid of precompiled libz
wget -q https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/libs%2Fzlib%2F1.2.13%2B20230623-2993864/libz-1.2.13-wasi-sdk-20.0.tar.gz
tar xf libz-1.2.13-wasi-sdk-20.0.tar.gz --directory="${WASI_SDK_PATH}/share/wasi-sysroot/"

mv "$WASI_SDK_PATH" /wasi-sdk

# wget -q https://github.com/getsentry/symbolicator/releases/download/23.11.2/wasm-split-Linux-x86_64 -O /usr/bin/wasm-split
# chmod +x /usr/bin/wasm-split
# wget -q https://github.com/getsentry/sentry-cli/releases/download/2.23.0/sentry-cli-Linux-x86_64 -O /usr/bin/sentry-cli
# chmod +x /usr/bin/sentry-cli

# Install a pinned Rust nightly toolchain
build-rust-harness.py --init-toolchain
