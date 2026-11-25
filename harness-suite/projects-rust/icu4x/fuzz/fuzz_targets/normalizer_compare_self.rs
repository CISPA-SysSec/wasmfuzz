// This file is part of ICU4X. For terms of use, please see the file
// called LICENSE at the top level of the ICU4X source tree
// (online at: https://github.com/unicode-org/icu4x/blob/main/LICENSE ).

#![no_main]
use libfuzzer_sys::fuzz_target;
use icu_normalizer::ComposingNormalizerBorrowed;
use icu_normalizer::DecomposingNormalizerBorrowed;
use utf16_iter::Utf16CharsEx;
use utf8_iter::Utf8CharsEx;

// Local modification: is_normalized_utf8() returns false for ill-formed input since
// upstream 5600ae1 (the U+FFFD of an ill-formed sequence no longer counts as normalized),
// so compare it against is_normalized() of the lossy string only for well-formed input.
// normalize_utf8() also became sound there; keep a check that it returns well-formed UTF-8.

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
    assert_eq!(is_normalized_nfd_str && valid, is_normalized_nfd_utf8);
    let is_normalized_nfd_utf16 = nfd.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfd_utf16, is_normalized_nfd_str);

    let nfd_str = nfd.normalize(&well_formed);
    let nfd_str_iter: String = nfd.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfd_str), (&*nfd_str_iter));

    let nfd_utf8 = nfd.normalize_utf8(data);
    assert!(core::str::from_utf8(nfd_utf8.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
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
    assert_eq!(is_normalized_nfc_str && valid, is_normalized_nfc_utf8);
    let is_normalized_nfc_utf16 = nfc.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfc_utf16, is_normalized_nfc_str);

    let nfc_str = nfc.normalize(&well_formed);
    let nfc_str_iter: String = nfc.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfc_str), (&*nfc_str_iter));

    let nfc_utf8 = nfc.normalize_utf8(data);
    assert!(core::str::from_utf8(nfc_utf8.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
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
    assert_eq!(is_normalized_nfkd_str && valid, is_normalized_nfkd_utf8);
    let is_normalized_nfkd_utf16 = nfkd.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfkd_utf16, is_normalized_nfkd_str);

    let nfkd_str = nfkd.normalize(&well_formed);
    let nfkd_str_iter: String = nfkd.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfkd_str), (&*nfkd_str_iter));

    let nfkd_utf8 = nfkd.normalize_utf8(data);
    assert!(core::str::from_utf8(nfkd_utf8.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
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
    assert_eq!(is_normalized_nfkc_str && valid, is_normalized_nfkc_utf8);
    let is_normalized_nfkc_utf16 = nfkc.is_normalized_utf16(&utf16);
    assert_eq!(is_normalized_nfkc_utf16, is_normalized_nfkc_str);

    let nfkc_str = nfkc.normalize(&well_formed);
    let nfkc_str_iter: String = nfkc.normalize_iter(well_formed.chars()).collect();
    assert_eq!((&*nfkc_str), (&*nfkc_str_iter));

    let nfkc_utf8 = nfkc.normalize_utf8(data);
    assert!(core::str::from_utf8(nfkc_utf8.as_bytes()).is_ok(), "normalize_utf8 returned ill-formed str");
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
