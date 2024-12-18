#include <stddef.h>
#include <stdint.h>

#include "zlib.h"

static Bytef buffer[256 * 1024] = { 0 };

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  uLongf buffer_length = sizeof(buffer);
  if (Z_OK != uncompress(buffer, &buffer_length, data, size)) {
    return 0;
  }
  return 0;
}

