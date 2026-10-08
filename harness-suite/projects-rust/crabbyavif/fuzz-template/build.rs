// libyuv is C++: link the wasi-sdk libc++/libc++abi into the Rust harness.
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target.starts_with("wasm32") {
        println!("cargo:rustc-link-search=native=/wasi-sdk/share/wasi-sysroot/lib/{target}/noeh");
        println!("cargo:rustc-link-lib=static=c++");
        println!("cargo:rustc-link-lib=static=c++abi");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }
}
