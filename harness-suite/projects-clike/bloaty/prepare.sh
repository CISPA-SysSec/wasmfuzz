set -e

apt-get update && apt-get install -y unzip

git clone-rev.sh https://github.com/google/bloaty.git "$PROJECT/repo" 3f36edba803388e98de51647ca0a23e174dc316f --recursive

git -C "$PROJECT/repo/third_party/zlib" checkout 5a82f71ed1dfc0bec044d9702463dbdf84ea3b71

git -C "$PROJECT/repo" apply ../bloaty.patch
git -C "$PROJECT/repo/third_party/abseil-cpp" apply ../../../third-party-absl.patch
git -C "$PROJECT/repo/third_party/zlib" apply ../../../fix-zlib-static.patch
git -C "$PROJECT/repo" apply ../fix-wasi-exceptions.patch

# Build a host protoc matching the bundled protobuf; the 3.9.0 release binary
# generates headers that are incompatible with bloaty's pinned submodule.
protoc_build=/tmp/bloaty-protoc-build
cmake -S "$PROJECT/repo/third_party/protobuf/cmake" -B "$protoc_build" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -Dprotobuf_BUILD_TESTS=OFF \
  -Dprotobuf_BUILD_PROTOC_BINARIES=ON \
  -Dprotobuf_BUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release
cmake --build "$protoc_build" --target protoc -j"$(nproc)"
install -m 0755 "$protoc_build/protoc" /usr/local/bin/protoc
