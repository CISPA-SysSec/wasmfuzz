// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Port of chromium/src/testing/libfuzzer/fuzzers/libsrtp_fuzzer.cc for
// wasmfuzz harness-suite: identical input format and logic, with the
// //base span helpers (base::span / base::SpanReader) replaced by plain
// pointer arithmetic so it builds without Chromium's //base.
//
// Chromium ships libsrtp 2.8.0; this suite builds upstream HEAD (3.x), so the
// harness is adapted to the 3.x API while keeping the same input format:
//  - srtp_policy_t is an opaque handle (srtp_policy_create/_set_profile/
//    _add_key) instead of a struct filled with srtp_crypto_policy_set_*().
//    Key and salt are passed separately; the split comes from
//    srtp_profile_get_master_{key,salt}_length().
//  - Policies map to profiles: NONE -> null_null (no key), LIKE_WEBRTC ->
//    aes128_cm_sha1_80, LIKE_WEBRTC_SHORT_AUTH -> aes128_cm_sha1_32 (3.x uses
//    an 80-bit RTCP tag here; only RTP is unprotected, so it does not matter),
//    LIKE_WEBRTC_WITHOUT_AUTH -> aes128_cm_sha1_80 with sec_serv_conf only
//    (2.x: aes_cm_128_null_auth), AES_*_GCM -> aead_aes_*_gcm.
//  - Encrypted header extension IDs are added one by one; 3.x rejects
//    duplicates and caps the list at SRTP_MAX_NUM_ENC_HDR_XTND_IDS, so
//    rejected IDs are skipped (2.x accepted any list).
//  - srtp_unprotect(ctx, srtp, srtp_len, rtp, &rtp_len) is called in place.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <cassert>

#include "srtp.h"
#include "srtp_priv.h"
#include "rtp.h"

namespace LibSrtpFuzzer {
enum CryptoPolicy {
  NONE,
  LIKE_WEBRTC,
  LIKE_WEBRTC_SHORT_AUTH,
  LIKE_WEBRTC_WITHOUT_AUTH,
  AES_128_GCM,
  AES_256_GCM,
  NUMBER_OF_POLICIES,
};
}

static srtp_profile_t GetProfile(LibSrtpFuzzer::CryptoPolicy crypto_policy) {
  switch (crypto_policy) {
    case LibSrtpFuzzer::NUMBER_OF_POLICIES:
    case LibSrtpFuzzer::NONE:
      return srtp_profile_null_null;
    case LibSrtpFuzzer::LIKE_WEBRTC:
    case LibSrtpFuzzer::LIKE_WEBRTC_WITHOUT_AUTH:
      return srtp_profile_aes128_cm_sha1_80;
    case LibSrtpFuzzer::LIKE_WEBRTC_SHORT_AUTH:
      return srtp_profile_aes128_cm_sha1_32;
    case LibSrtpFuzzer::AES_128_GCM:
      // There was a security bug in the GCM mode in libsrtp 1.5.2.
      return srtp_profile_aead_aes_128_gcm;
    case LibSrtpFuzzer::AES_256_GCM:
      // WebRTC uses AES-256-GCM by default if GCM ciphers are enabled.
      return srtp_profile_aead_aes_256_gcm;
  }
  return srtp_profile_null_null;
}

// Minimal stand-in for base::SpanReader.
struct Reader {
  const uint8_t* p;
  size_t n;
  bool ReadU8(uint8_t& out) {
    if (n < 1) return false;
    out = *p++;
    n--;
    return true;
  }
  const uint8_t* Read(size_t len) {
    if (n < len) return nullptr;
    const uint8_t* r = p;
    p += len;
    n -= len;
    return r;
  }
  size_t remaining() const { return n; }
};

struct Environment {
  Environment() { srtp_init(); }
};

// Builds the policy the 2.x harness set up in Environment/GetCryptoPolicy:
// allow_repeat_tx, ssrc_any_inbound, window 1024, key from the input.
static srtp_policy_t CreatePolicy(LibSrtpFuzzer::CryptoPolicy crypto_policy,
                                  const uint8_t* key_bytes) {
  srtp_policy_t policy = nullptr;
  if (srtp_policy_create(&policy) != srtp_err_status_ok) {
    return nullptr;
  }
  srtp_profile_t profile = GetProfile(crypto_policy);
  srtp_ssrc_t ssrc = {ssrc_any_inbound, 0xdeadbeef};
  bool ok = srtp_policy_set_profile(policy, profile) == srtp_err_status_ok &&
            srtp_policy_set_ssrc(policy, ssrc) == srtp_err_status_ok &&
            srtp_policy_set_window_size(policy, 1024) == srtp_err_status_ok &&
            srtp_policy_set_allow_repeat_tx(policy, true) == srtp_err_status_ok;
  if (ok && crypto_policy == LibSrtpFuzzer::LIKE_WEBRTC_WITHOUT_AUTH) {
    ok = srtp_policy_set_sec_serv(policy, sec_serv_conf, sec_serv_conf) ==
         srtp_err_status_ok;
  }
  if (ok && profile != srtp_profile_null_null) {
    size_t key_len = srtp_profile_get_master_key_length(profile);
    size_t salt_len = srtp_profile_get_master_salt_length(profile);
    assert(key_len + salt_len <= SRTP_MAX_KEY_LEN);
    ok = srtp_policy_add_key(policy, key_bytes, key_len, key_bytes + key_len,
                             salt_len, nullptr, 0) == srtp_err_status_ok;
  }
  if (!ok) {
    srtp_policy_destroy(policy);
    return nullptr;
  }
  return policy;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  Reader reader{data, size};

  // Read one byte and use it to choose a crypto policy.
  uint8_t policy_byte;
  if (!reader.ReadU8(policy_byte)) {
    return 0;
  }
  LibSrtpFuzzer::CryptoPolicy policy = static_cast<LibSrtpFuzzer::CryptoPolicy>(
      policy_byte % LibSrtpFuzzer::NUMBER_OF_POLICIES);

  // Read some more bytes to use as a key.
  const uint8_t* key_bytes = reader.Read(SRTP_MAX_KEY_LEN);
  if (!key_bytes) {
    return 0;
  }
  srtp_policy_t srtp_policy = CreatePolicy(policy, key_bytes);
  if (!srtp_policy) {
    return 0;
  }

  // Read one byte and use as number of encrypted header extensions.
  uint8_t num_encrypted_headers;
  if (!reader.ReadU8(num_encrypted_headers)) {
    srtp_policy_destroy(srtp_policy);
    return 0;
  }
  if (num_encrypted_headers > 0) {
    // Use next bytes as extension ids.
    const uint8_t* headers_bytes = reader.Read(num_encrypted_headers);
    if (!headers_bytes) {
      srtp_policy_destroy(srtp_policy);
      return 0;
    }
    for (size_t i = 0; i < num_encrypted_headers; i++) {
      // Duplicates / overflow are rejected by 3.x; skip them.
      srtp_policy_add_enc_hdr_xtnd_id(srtp_policy, headers_bytes[i]);
    }
  }

  srtp_t session;
  srtp_err_status_t error = srtp_create(&session, srtp_policy);
  srtp_policy_destroy(srtp_policy);
  if (error != srtp_err_status_ok) {
    return 0;
  }

  // Read one byte as a packet length N, then feed the next N bytes
  // into srtp_unprotect. Keep doing until we run out of data.
  while (true) {
    uint8_t packet_size_byte;
    if (!reader.ReadU8(packet_size_byte)) {
      break;
    }
    size_t packet_size =
        std::min(static_cast<size_t>(packet_size_byte), reader.remaining());
    if (packet_size == 0) {
      break;
    }
    const uint8_t* packet = reader.Read(packet_size);
    if (!packet) {
      break;
    }

    size_t header_size = std::min(sizeof(srtp_hdr_t), packet_size);

    // Deliberately not initialised (as in Chromium, where MSAN checks it).
    rtp_msg_t message;
    memcpy(&message.header, packet, header_size);
    memcpy(&message.body, packet + header_size, packet_size - header_size);

    size_t out_len = packet_size;
    uint8_t* buf = reinterpret_cast<uint8_t*>(&message);
    srtp_unprotect(session, buf, packet_size, buf, &out_len);
  }

  srtp_dealloc(session);
  return 0;
}
