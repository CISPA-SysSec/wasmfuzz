// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "./fuzz_utils.h"
#include "src/utils/rescaler_utils.h"
#include "src/webp/decode.h"

struct FuzzParams
{
  bool flag_flip : 1;
  bool flag_bypass_filtering : 1;
  bool flag_no_fancy_upsampling : 1;
  bool flag_use_threads : 1;
  bool flag_use_cropping : 1;
  bool flag_use_dithering : 1;
  bool flag_use_scaling : 1;
  bool flag_incremental_decode : 1;
  bool flag_incremental_webpi_update : 1;
  uint16_t incremental_first_chunk_size;
  uint8_t colorspace;
  float factor;
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < sizeof(struct FuzzParams))
    return 0;
  struct FuzzParams params = *(struct FuzzParams *)data;
  data += sizeof(struct FuzzParams);
  size -= sizeof(struct FuzzParams);
  if (params.factor > 1 || params.factor < 0)
    return 0;
  WebPDecoderConfig config;
  if (!WebPInitDecoderConfig(&config))
    return 0;
  if (WebPGetFeatures(data, size, &config.input) != VP8_STATUS_OK)
    return 0;
  if ((size_t)config.input.width * config.input.height > kFuzzPxLimit)
    return 0;

  // Using two independent criteria ensures that all combinations of options
  // can reach each path at the decoding stage, with meaningful differences.

  config.options.flip = params.flag_flip;
  config.options.bypass_filtering = params.flag_bypass_filtering;
  config.options.no_fancy_upsampling = params.flag_no_fancy_upsampling;
  config.options.use_threads = params.flag_use_threads;
  if (params.flag_use_cropping)
  {
    config.options.use_cropping = 1;
    config.options.crop_width = (int)(config.input.width * (1 - params.factor));
    config.options.crop_height = (int)(config.input.height * (1 - params.factor));
    config.options.crop_left = config.input.width - config.options.crop_width;
    config.options.crop_top = config.input.height - config.options.crop_height;
  }
  if (params.flag_use_dithering)
  {
    int strength = (int)(params.factor * 100);
    config.options.dithering_strength = strength;
    config.options.alpha_dithering_strength = 100 - strength;
  }
  if (params.flag_use_scaling)
  {
    config.options.use_scaling = 1;
    config.options.scaled_width = (int)(config.input.width * params.factor * 2);
    config.options.scaled_height = (int)(config.input.height * params.factor * 2);
  }

#if defined(WEBP_REDUCE_CSP)
  config.output.colorspace = (params.colorspace & 1)
                                 ? ((params.colorspace & 2) ? MODE_RGBA : MODE_BGRA)
                                 : ((params.colorspace & 2) ? MODE_rgbA : MODE_bgrA);
#else
  config.output.colorspace = (WEBP_CSP_MODE)(params.colorspace % MODE_LAST);
#endif // WEBP_REDUCE_CSP

  for (int i = 0; i < 2; ++i)
  {
    if (i == 1)
    {
      // Use the bitstream data to generate extreme ranges for the options. An
      // alternative approach would be to use a custom corpus containing webp
      // files prepended with sizeof(config.options) zeroes to allow the fuzzer
      // to modify these independently.
      const int data_offset = 50;
      if (data_offset + sizeof(config.options) >= size)
        break;
      memcpy(&config.options, data + data_offset, sizeof(config.options));

      // Skip easily avoidable out-of-memory fuzzing errors.
      if (config.options.use_scaling)
      {
        int scaled_width = config.options.scaled_width;
        int scaled_height = config.options.scaled_height;
        if (WebPRescalerGetScaledDimensions(config.input.width,
                                            config.input.height, &scaled_width,
                                            &scaled_height))
        {
          size_t fuzz_px_limit = kFuzzPxLimit;
          if (scaled_width != config.input.width ||
              scaled_height != config.input.height)
          {
            // Using the WebPRescalerImport internally can significantly slow
            // down the execution. Avoid timeouts due to that.
            fuzz_px_limit /= 2;
          }
          // A big output canvas can lead to out-of-memory and timeout issues,
          // but a big internal working buffer can too. Also, rescaling from a
          // very wide input image to a very tall canvas can be as slow as
          // decoding a huge number of pixels. Avoid timeouts due to these.
          const uint64_t max_num_operations =
              (uint64_t)Max(scaled_width, config.input.width) *
              Max(scaled_height, config.input.height);
          if (max_num_operations > fuzz_px_limit)
          {
            break;
          }
        }
      }
    }
    if (params.flag_incremental_decode)
    {
      // Decodes incrementally in chunks of increasing size.
      WebPIDecoder *idec = WebPIDecode(NULL, 0, &config);
      if (!idec)
        return 0;
      VP8StatusCode status;
      if (params.flag_incremental_webpi_update)
      {
        size_t available_size = params.incremental_first_chunk_size + 1;
        while (1)
        {
          if (available_size > size)
            available_size = size;
          status = WebPIUpdate(idec, data, available_size);
          if (status != VP8_STATUS_SUSPENDED || available_size == size)
            break;
          available_size *= 2;
        }
      }
      else
      {
        // WebPIAppend expects new data and its size with each call.
        // Implemented here by simply advancing the pointer into data.
        const uint8_t *new_data = data;
        size_t new_size = params.incremental_first_chunk_size + 1;
        while (1)
        {
          if (new_data + new_size > data + size)
          {
            new_size = data + size - new_data;
          }
          status = WebPIAppend(idec, new_data, new_size);
          if (status != VP8_STATUS_SUSPENDED || new_size == 0)
            break;
          new_data += new_size;
          new_size *= 2;
        }
      }
      WebPIDelete(idec);
    }
    else
    {
      WebPDecode(data, size, &config);
    }

    WebPFreeDecBuffer(&config.output);
  }
  return 0;
}
