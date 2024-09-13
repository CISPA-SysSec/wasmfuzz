#include "./fuzz_utils.h"
#include "src/webp/decode.h"
#include "imageio/image_enc.h"
#include "imageio/webpdec.h"

int LLVMFuzzerTestOneInput(const uint8_t *const data, size_t size)
{
  int w, h;
  if (!WebPGetInfo(data, size, &w, &h))
    return 0;
  if ((size_t)w * h > kFuzzPxLimit)
    return 0;

  WebPDecoderConfig config;
  if (!WebPInitDecoderConfig(&config))
    return 0;

  DecodeWebP(data, size, &config);

  WebPFreeDecBuffer(&config.output);
  return 0;
}
