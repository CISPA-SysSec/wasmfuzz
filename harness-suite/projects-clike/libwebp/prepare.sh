set -e
git clone-rev.sh https://chromium.googlesource.com/webm/libwebp "$PROJECT/repo" fd7bb21c0cb56e8a82e9bfa376164b842f433f3b
git -C "$PROJECT/repo" apply ../wasm.patch
git -C "$PROJECT/repo" apply ../blub.patch

cp advanced_api_fuzzer2.c "$PROJECT/repo/tests/fuzzer/"
cp dwebp_fuzzer.c "$PROJECT/repo/tests/fuzzer/"
