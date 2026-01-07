# Build with `podman build . -t wasm-fuzzers-wasmfuzz`
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y rustup git clang
RUN rustup toolchain add --no-self-update 1.90
RUN mkdir /wasmfuzz
COPY Cargo.toml Cargo.lock wasmfuzz/
COPY src wasmfuzz/src/
RUN cargo install --locked --no-default-features --path /wasmfuzz && ln -s /root/.cargo/bin/wasmfuzz /usr/bin/
COPY wasm-fuzzers/wasmfuzz.sh /usr/bin/
RUN chmod +x /usr/bin/wasmfuzz.sh
RUN mkdir -p /seeds/ && echo -n "YELLOW SUBMARINE" > /seeds/seed && mkdir -p /corpus/
ENTRYPOINT [ "wasmfuzz.sh" ]
