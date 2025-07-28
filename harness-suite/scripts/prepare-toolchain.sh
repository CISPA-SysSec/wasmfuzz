#!/bin/bash
set -e +x

WASI_VERSION=27
WASI_VERSION_FULL=${WASI_VERSION}.0
WASI_DIR="wasi-sdk-${WASI_VERSION_FULL}-$(uname -m)-linux"
wget -q "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/${WASI_DIR}.tar.gz"
tar xf "${WASI_DIR}.tar.gz"
mv "$WASI_DIR" /wasi-sdk

# Install a pinned Rust nightly toolchain
build-rust-harness.py --init-toolchain
