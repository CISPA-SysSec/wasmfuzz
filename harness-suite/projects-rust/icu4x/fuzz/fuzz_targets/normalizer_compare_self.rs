// This file is part of ICU4X. For terms of use, please see the file
// called LICENSE at the top level of the ICU4X source tree
// (online at: https://github.com/unicode-org/icu4x/blob/main/LICENSE ).

#![no_main]
use libfuzzer_sys::fuzz_target;
use icu_normalizer::ComposingNormalizerBorrowed;
use icu_normalizer::DecomposingNormalizerBorrowed;
use utf16_iter::Utf16CharsEx;
use utf8_iter::Utf8CharsEx;

// Local modification: icu_normalizer 2.2.0 (and upstream main as of 2026-09)
// `normalize_utf8()` returns `Cow::Borrowed` of *ill-formed* input via
// `split_normalized_utf8()` -> `from_utf8_unchecked`, because
// `IsNormalizedSinkUtf8::write_char` matches the U+FFFD emitted for an
// ill-formed sequence against the ill-formed bytes. That yields an invalid
// `&str` (UB). It is reported separately; to keep this harness useful the
// Cow-returning API is only used on well-formed input and the sound
// `normalize_utf8_to()` path is used otherwise. Set ICU4X_FUZZ_UNSOUND_UTF8=1
// at build time to exercise the buggy path.
const CHECK_UNSOUND: bool = option_env!("ICU4X_FUZZ_UNSOUND_UTF8").is_some();

fuzz_target!(|data: &[u8]| {
    let well_formed = String::from_utf8_lossy(data);
    let valid = matches!(well_formed, std::borrow::Cow::Borrowed(_));
    let utf16: Vec<u16> = well_formed.encode_utf16().collect();

    let nfd = DecomposingNormalizerBorrowed::new_nfd();
    let nfkd = DecomposingNormalizerBorrowed::new_nfkd();
    let nfc = ComposingNormalizerBorrowed::new_nfc();
    let nfkc = ComposingNormalizerBorrowed::new_nfkc();

    // Not macroizing these to get nice line numbers by default.

    // NFD

    let is_normalized_nfd_str = nfd.is_normalized(&well_formed);
    let is_normalized_nfd_utf8 = nfd.is_normalized_utf8(data);
    assert_eq!(is_normalized_nfd_str, is_normalized_nfd_utf8);
    let is_normalized_nfd_utf16 = nfd.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfd_utf16, is_normalized_nfd_str);

    let nfd_str = nfd.normalize(&well_formed);
    let nfd_str_iter: String = nfd.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfd_str), (&*nfd_str_iter));

    let nfd_utf8: std::borrow::Cow<str> = if valid || CHECK_UNSOUND {
        let r = nfd.normalize_utf8(data);
        assert!(core::str::from_utf8(r.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
        r
    } else {
        let mut out = String::new();
        let _ = nfd.normalize_utf8_to(data, &mut out);
        out.into()
    };
    let nfd_utf8_iter: String = nfd.normalize_iter(data.chars()).collect();
    assert_eq!((&*nfd_utf8), (&*nfd_utf8_iter));

    assert_eq!((&*nfd_str), (&*nfd_utf8));

    let nfd_utf16 = nfd.normalize_utf16(&utf16);
    let mut nfd_utf16_iter: Vec<u16> = Vec::new();
    for c in nfd.normalize_iter(utf16.chars()) {
        let mut buf = [0u16; 2];
        nfd_utf16_iter.extend_from_slice(c.encode_utf16(&mut buf));
    }
    assert_eq!((&*nfd_utf16), (&*nfd_utf16_iter));

    let nfd_from_utf16 = String::from_utf16(&nfd_utf16);
    assert!(nfd_from_utf16.is_ok());

    assert_eq!((&*nfd_str), nfd_from_utf16.unwrap().as_str());

    if is_normalized_nfd_str {
        assert_eq!((&*nfd_str), &well_formed);
        assert_eq!((&*nfd_utf8), &well_formed); // not data!
        assert_eq!((&*nfd_utf16), (&*utf16));
    }

    // NFC

    let is_normalized_nfc_str = nfc.is_normalized(&well_formed);
    let is_normalized_nfc_utf8 = nfc.is_normalized_utf8(data);
    assert_eq!(is_normalized_nfc_str, is_normalized_nfc_utf8);
    let is_normalized_nfc_utf16 = nfc.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfc_utf16, is_normalized_nfc_str);

    let nfc_str = nfc.normalize(&well_formed);
    let nfc_str_iter: String = nfc.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfc_str), (&*nfc_str_iter));

    let nfc_utf8: std::borrow::Cow<str> = if valid || CHECK_UNSOUND {
        let r = nfc.normalize_utf8(data);
        assert!(core::str::from_utf8(r.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
        r
    } else {
        let mut out = String::new();
        let _ = nfc.normalize_utf8_to(data, &mut out);
        out.into()
    };
    let nfc_utf8_iter: String = nfc.normalize_iter(data.chars()).collect();
    assert_eq!((&*nfc_utf8), (&*nfc_utf8_iter));

    assert_eq!((&*nfc_str), (&*nfc_utf8));

    let nfc_utf16 = nfc.normalize_utf16(&utf16);
    let mut nfc_utf16_iter: Vec<u16> = Vec::new();
    for c in nfc.normalize_iter(utf16.chars()) {
        let mut buf = [0u16; 2];
        nfc_utf16_iter.extend_from_slice(c.encode_utf16(&mut buf));
    }
    assert_eq!((&*nfc_utf16), (&*nfc_utf16_iter));

    let nfc_from_utf16 = String::from_utf16(&nfc_utf16);
    assert!(nfc_from_utf16.is_ok());

    assert_eq!((&*nfc_str), nfc_from_utf16.unwrap().as_str());

    if is_normalized_nfc_str {
        assert_eq!((&*nfc_str), &well_formed);
        assert_eq!((&*nfc_utf8), &well_formed); // not data!
        assert_eq!((&*nfc_utf16), (&*utf16));
    }

    // NFKD

    let is_normalized_nfkd_str = nfkd.is_normalized(&well_formed);
    let is_normalized_nfkd_utf8 = nfkd.is_normalized_utf8(data);
    assert_eq!(is_normalized_nfkd_str, is_normalized_nfkd_utf8);
    let is_normalized_nfkd_utf16 = nfkd.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfkd_utf16, is_normalized_nfkd_str);

    let nfkd_str = nfkd.normalize(&well_formed);
    let nfkd_str_iter: String = nfkd.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfkd_str), (&*nfkd_str_iter));

    let nfkd_utf8: std::borrow::Cow<str> = if valid || CHECK_UNSOUND {
        let r = nfkd.normalize_utf8(data);
        assert!(core::str::from_utf8(r.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
        r
    } else {
        let mut out = String::new();
        let _ = nfkd.normalize_utf8_to(data, &mut out);
        out.into()
    };
    let nfkd_utf8_iter: String = nfkd.normalize_iter(data.chars()).collect();
    assert_eq!((&*nfkd_utf8), (&*nfkd_utf8_iter));

    assert_eq!((&*nfkd_str), (&*nfkd_utf8));

    let nfkd_utf16 = nfkd.normalize_utf16(&utf16);
    let mut nfkd_utf16_iter: Vec<u16> = Vec::new();
    for c in nfkd.normalize_iter(utf16.chars()) {
        let mut buf = [0u16; 2];
        nfkd_utf16_iter.extend_from_slice(c.encode_utf16(&mut buf));
    }
    assert_eq!((&*nfkd_utf16), (&*nfkd_utf16_iter));

    let nfkd_from_utf16 = String::from_utf16(&nfkd_utf16);
    assert!(nfkd_from_utf16.is_ok());

    assert_eq!((&*nfkd_str), nfkd_from_utf16.unwrap().as_str());

    if is_normalized_nfkd_str {
        assert_eq!((&*nfkd_str), &well_formed);
        assert_eq!((&*nfkd_utf8), &well_formed); // not data!
        assert_eq!((&*nfkd_utf16), (&*utf16));
    }

    // NFKC

    let is_normalized_nfkc_str = nfkc.is_normalized(&well_formed);
    let is_normalized_nfkc_utf8 = nfkc.is_normalized_utf8(data);
    assert_eq!(is_normalized_nfkc_str, is_normalized_nfkc_utf8);
    let is_normalized_nfkc_utf16 = nfkc.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfkc_utf16, is_normalized_nfkc_str);

    let nfkc_str = nfkc.normalize(&well_formed);
    let nfkc_str_iter: String = nfkc.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfkc_str), (&*nfkc_str_iter));

    let nfkc_utf8: std::borrow::Cow<str> = if valid || CHECK_UNSOUND {
        let r = nfkc.normalize_utf8(data);
        assert!(core::str::from_utf8(r.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
        r
    } else {
        let mut out = String::new();
        let _ = nfkc.normalize_utf8_to(data, &mut out);
        out.into()
    };
    let nfkc_utf8_iter: String = nfkc.normalize_iter(data.chars()).collect();
    assert_eq!((&*nfkc_utf8), (&*nfkc_utf8_iter));

    assert_eq!((&*nfkc_str), (&*nfkc_utf8));

    let nfkc_utf16 = nfkc.normalize_utf16(&utf16);
    let mut nfkc_utf16_iter: Vec<u16> = Vec::new();
    for c in nfkc.normalize_iter(utf16.chars()) {
        let mut buf = [0u16; 2];
        nfkc_utf16_iter.extend_from_slice(c.encode_utf16(&mut buf));
    }
    assert_eq!((&*nfkc_utf16), (&*nfkc_utf16_iter));

    let nfkc_from_utf16 = String::from_utf16(&nfkc_utf16);
    assert!(nfkc_from_utf16.is_ok());

    assert_eq!((&*nfkc_str), nfkc_from_utf16.unwrap().as_str());

    if is_normalized_nfkc_str {
        assert_eq!((&*nfkc_str), &well_formed);
        assert_eq!((&*nfkc_utf8), &well_formed); // not data!
        assert_eq!((&*nfkc_utf16), (&*utf16));
    }
});
