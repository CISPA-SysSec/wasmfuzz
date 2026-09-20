set -e

apt-get update && apt-get install -y unzip

git clone-rev.sh https://github.com/google/bloaty.git "$PROJECT/repo" 37bf8e708398727b58d9a61e66e9ccb5db6df619 --recursive

git -C "$PROJECT/repo/third_party/zlib" checkout 5a82f71ed1dfc0bec044d9702463dbdf84ea3b71

git -C "$PROJECT/repo" apply ../port-build-and-wasi.patch
git -C "$PROJECT/repo/third_party/abseil-cpp" apply ../../../port-absl-examine-stack.patch
git -C "$PROJECT/repo/third_party/zlib" apply ../../../port-zlib-static.patch
git -C "$PROJECT/repo" apply ../port-wasi-exceptions.patch
git -C "$PROJECT/repo" apply ../fix-demumble-missing-stdlib.patch

# Build a host protoc matching the bundled protobuf; a mismatched release binary
# generates headers that are incompatible with bloaty's pinned submodule.
# protobuf v6 moved its CMakeLists.txt to the repo root (was third_party/protobuf/cmake)
# and pulls in Abseil via FetchContent when no system absl is found.
protoc_build=/tmp/bloaty-protoc-build
cmake -S "$PROJECT/repo/third_party/protobuf" -B "$protoc_build" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -Dprotobuf_BUILD_TESTS=OFF \
  -Dprotobuf_BUILD_PROTOC_BINARIES=ON \
  -Dprotobuf_BUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release
cmake --build "$protoc_build" --target protoc -j"$(nproc)"
install -m 0755 "$protoc_build/protoc" /usr/local/bin/protoc
