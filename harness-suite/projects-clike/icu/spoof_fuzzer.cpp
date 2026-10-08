// USpoofChecker harness.
//
// Mirrors Chromium's url_formatter IDNSpoofChecker
// (components/url_formatter/spoof_checks/idn_spoof_checker.cc and
// skeleton_generator.cc), which decides whether an IDN hostname from web
// content is displayed as Unicode: uspoof_open +
// uspoof_setRestrictionLevel(USPOOF_HIGHLY_RESTRICTIVE) + USPOOF_AUX_INFO,
// uspoof_check on each label and uspoof_getSkeleton for confusable lookups.
// Chromium's custom allowed-character set is not replicated.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vector>

#include "unicode/uspoof.h"
#include "unicode/utypes.h"

static USpoofChecker* gChecker;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size > 4096) return 0;
  if (!gChecker) {
    UErrorCode status = U_ZERO_ERROR;
    gChecker = uspoof_open(&status);
    if (U_FAILURE(status)) __builtin_trap();
    uspoof_setRestrictionLevel(gChecker, USPOOF_HIGHLY_RESTRICTIVE);
    int32_t checks = uspoof_getChecks(gChecker, &status) | USPOOF_AUX_INFO;
    uspoof_setChecks(gChecker, checks, &status);
    if (U_FAILURE(status)) __builtin_trap();
  }

  std::vector<UChar> s(size / 2);
  memcpy(s.data(), data, s.size() * sizeof(UChar));
  int32_t len = static_cast<int32_t>(s.size());

  UErrorCode status = U_ZERO_ERROR;
  uspoof_check(gChecker, s.data(), len, nullptr, &status);

  status = U_ZERO_ERROR;
  USpoofCheckResult* result = uspoof_openCheckResult(&status);
  uspoof_check2(gChecker, s.data(), len, result, &status);
  uspoof_closeCheckResult(result);

  status = U_ZERO_ERROR;
  std::vector<UChar> skel(s.size() * 18 + 16);
  uspoof_getSkeleton(gChecker, 0, s.data(), len, skel.data(), skel.size(), &status);

  status = U_ZERO_ERROR;
  int32_t half = len / 2;
  uspoof_areConfusable(gChecker, s.data(), half, s.data() + half, len - half, &status);

  status = U_ZERO_ERROR;
  uspoof_checkUTF8(gChecker, reinterpret_cast<const char*>(data),
                   static_cast<int32_t>(size), nullptr, &status);
  return 0;
}
