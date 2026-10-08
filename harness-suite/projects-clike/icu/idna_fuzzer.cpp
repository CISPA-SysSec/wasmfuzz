// UTS #46 IDNA (uidna_*) harness.
//
// Mirrors Chromium's url::IDNToASCII (url/url_idna_icu.cc), which runs every
// non-ASCII hostname from web content through uidna_nameToASCII with
//   UIDNA_CHECK_BIDI | UIDNA_NONTRANSITIONAL_TO_ASCII |
//   UIDNA_NONTRANSITIONAL_TO_UNICODE | UIDNA_CHECK_CONTEXTJ
// and url_formatter's IDN display path (uidna_nameToUnicode). The first input
// byte selects extra option bits and the API variant (UTF-16 vs UTF-8, name vs
// label); the remaining bytes are the domain name.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <vector>

#include "unicode/uidna.h"
#include "unicode/utypes.h"

static const uint32_t kChromiumOptions =
    UIDNA_CHECK_BIDI | UIDNA_NONTRANSITIONAL_TO_ASCII |
    UIDNA_NONTRANSITIONAL_TO_UNICODE | UIDNA_CHECK_CONTEXTJ;

static UIDNA* gIdna[4];

static UIDNA* GetIdna(unsigned idx) {
  if (!gIdna[idx]) {
    uint32_t options = kChromiumOptions;
    if (idx & 1) options |= UIDNA_USE_STD3_RULES;
    if (idx & 2) options |= UIDNA_CHECK_CONTEXTO;
    UErrorCode err = U_ZERO_ERROR;
    gIdna[idx] = uidna_openUTS46(options, &err);
    if (U_FAILURE(err)) __builtin_trap();
  }
  return gIdna[idx];
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return 0;
  const uint8_t selector = data[0];
  data++;
  size--;
  if (size > 4096) return 0;

  UIDNA* idna = GetIdna(selector & 3);
  const bool label = selector & 4;
  const bool utf8 = selector & 8;

  if (utf8) {
    const char* src = reinterpret_cast<const char*>(data);
    int32_t len = static_cast<int32_t>(size);
    std::vector<char> out(size * 4 + 64);
    std::vector<char> back(out.size() * 4 + 64);
    UErrorCode err = U_ZERO_ERROR;
    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    int32_t n = label
        ? uidna_labelToASCII_UTF8(idna, src, len, out.data(), out.size(), &info, &err)
        : uidna_nameToASCII_UTF8(idna, src, len, out.data(), out.size(), &info, &err);
    if (U_SUCCESS(err) && n > 0 && n <= static_cast<int32_t>(out.size())) {
      err = U_ZERO_ERROR;
      UIDNAInfo info2 = UIDNA_INFO_INITIALIZER;
      if (label)
        uidna_labelToUnicodeUTF8(idna, out.data(), n, back.data(), back.size(), &info2, &err);
      else
        uidna_nameToUnicodeUTF8(idna, out.data(), n, back.data(), back.size(), &info2, &err);
    }
    err = U_ZERO_ERROR;
    UIDNAInfo info3 = UIDNA_INFO_INITIALIZER;
    if (label)
      uidna_labelToUnicodeUTF8(idna, src, len, back.data(), back.size(), &info3, &err);
    else
      uidna_nameToUnicodeUTF8(idna, src, len, back.data(), back.size(), &info3, &err);
  } else {
    std::vector<UChar> src(size / 2);
    memcpy(src.data(), data, src.size() * sizeof(UChar));
    int32_t len = static_cast<int32_t>(src.size());
    std::vector<UChar> out(src.size() * 4 + 64);
    std::vector<UChar> back(out.size() * 4 + 64);
    UErrorCode err = U_ZERO_ERROR;
    UIDNAInfo info = UIDNA_INFO_INITIALIZER;
    int32_t n = label
        ? uidna_labelToASCII(idna, src.data(), len, out.data(), out.size(), &info, &err)
        : uidna_nameToASCII(idna, src.data(), len, out.data(), out.size(), &info, &err);
    if (U_SUCCESS(err) && n > 0 && n <= static_cast<int32_t>(out.size())) {
      err = U_ZERO_ERROR;
      UIDNAInfo info2 = UIDNA_INFO_INITIALIZER;
      if (label)
        uidna_labelToUnicode(idna, out.data(), n, back.data(), back.size(), &info2, &err);
      else
        uidna_nameToUnicode(idna, out.data(), n, back.data(), back.size(), &info2, &err);
    }
    err = U_ZERO_ERROR;
    UIDNAInfo info3 = UIDNA_INFO_INITIALIZER;
    if (label)
      uidna_labelToUnicode(idna, src.data(), len, back.data(), back.size(), &info3, &err);
    else
      uidna_nameToUnicode(idna, src.data(), len, back.data(), back.size(), &info3, &err);
  }
  return 0;
}
