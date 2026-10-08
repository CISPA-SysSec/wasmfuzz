// Harness for third_party/zlib/google/compression_utils_portable.cc.
// Mirrors compression::GzipUncompress(span, span) from compression_utils.cc
// (which needs //base): the output buffer is sized from the gzip ISIZE trailer
// via GetGzipUncompressedSize(), then GzipUncompressHelper() inflates into it.
// The first input byte also selects the ZLIB / ZRAW wrappers of
// UncompressHelper() with a fixed-size output buffer.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "compression_utils_portable.h"

static const uint32_t kMaxOutput = 1 << 20;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1)
    return 0;
  uint8_t mode = data[0] % 3;
  data++;
  size--;

  if (mode == 0) {
    uLongf out_size = zlib_internal::GetGzipUncompressedSize(data, size);
    if (out_size > kMaxOutput)
      return 0;
    Bytef* out = static_cast<Bytef*>(malloc(out_size ? out_size : 1));
    zlib_internal::GzipUncompressHelper(out, &out_size, data, size);
    free(out);
  } else {
    static Bytef out[64 * 1024];
    uLongf out_size = sizeof(out);
    zlib_internal::UncompressHelper(
        mode == 1 ? zlib_internal::ZLIB : zlib_internal::ZRAW, out, &out_size,
        data, size);
  }
  return 0;
}
