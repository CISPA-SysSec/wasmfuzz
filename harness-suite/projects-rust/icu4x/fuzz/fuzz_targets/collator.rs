// Collator (Intl.Collator / String.prototype.localeCompare in SpiderMonkey via
// js/src/builtin/intl/collator_glue, which enables the `latin1` feature).
//
// Input: [flags: u8] [locale bytes] 0x00 [left] 0x00 [right]
// The locale may carry -u-co / -u-kf / -u-kn keywords, which feed
// CollatorPreferences just like Intl.Collator does.
#![no_main]
use core::cmp::Ordering;
use icu_collator::options::{AlternateHandling, CaseLevel, CollatorOptions, MaxVariable, Strength};
use icu_collator::{CollatorBorrowed, CollatorPreferences};
use icu_locale_core::Locale;
use libfuzzer_sys::fuzz_target;

fn split3(data: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let mut it = data.splitn(3, |b| *b == 0);
    Some((it.next()?, it.next()?, it.next()?))
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else { return };
    let Some((loc, left, right)) = split3(rest) else { return };
    let locale = Locale::try_from_utf8(loc).unwrap_or(Locale::UNKNOWN);

    let mut options = CollatorOptions::default();
    options.strength = match flags & 7 {
        0 => None,
        1 => Some(Strength::Primary),
        2 => Some(Strength::Secondary),
        3 => Some(Strength::Tertiary),
        4 => Some(Strength::Quaternary),
        _ => Some(Strength::Identical),
    };
    options.alternate_handling = match (flags >> 3) & 3 {
        0 => None,
        1 => Some(AlternateHandling::NonIgnorable),
        _ => Some(AlternateHandling::Shifted),
    };
    options.max_variable = match (flags >> 5) & 3 {
        0 => None,
        1 => Some(MaxVariable::Punctuation),
        2 => Some(MaxVariable::Symbol),
        _ => Some(MaxVariable::Currency),
    };
    options.case_level = if flags & 0x80 != 0 { Some(CaseLevel::On) } else { None };

    let prefs = CollatorPreferences::from(&locale);
    let Ok(collator) = CollatorBorrowed::try_new(prefs, options) else { return };
    let _ = collator.resolved_options();

    let left_s = String::from_utf8_lossy(left);
    let right_s = String::from_utf8_lossy(right);
    let left16: Vec<u16> = left_s.encode_utf16().collect();
    let right16: Vec<u16> = right_s.encode_utf16().collect();

    let ord = collator.compare(&left_s, &right_s);
    assert_eq!(collator.compare(&right_s, &left_s), ord.reverse());
    assert_eq!(collator.compare(&left_s, &left_s), Ordering::Equal);
    // compare_utf8() on *ill-formed* UTF-8 can disagree with comparing the
    // U+FFFD-replaced strings (seen with strength=identical, alternate=shifted;
    // reported separately), so the equivalence is only asserted for valid UTF-8.
    let ord8 = collator.compare_utf8(left, right);
    if core::str::from_utf8(left).is_ok() && core::str::from_utf8(right).is_ok() {
        assert_eq!(ord8, ord);
    }
    assert_eq!(collator.compare_utf16(&left16, &right16), ord);

    // Latin-1 paths (SpiderMonkey passes Latin-1 JSStrings directly).
    let left_l1: String = left.iter().map(|b| char::from(*b)).collect();
    let right_l1: String = right.iter().map(|b| char::from(*b)).collect();
    let right_l1_16: Vec<u16> = right.iter().map(|b| u16::from(*b)).collect();
    let ord_l1 = collator.compare(&left_l1, &right_l1);
    assert_eq!(collator.compare_latin1(left, right), ord_l1);
    assert_eq!(collator.compare_latin1_utf16(left, &right_l1_16), ord_l1);

    // Sort keys.
    let mut k1 = Vec::new();
    let mut k2 = Vec::new();
    let Ok(()) = collator.write_sort_key_utf8_to(left, &mut k1);
    let Ok(()) = collator.write_sort_key_utf16_to(&right16, &mut k2);
    let _ = k1.cmp(&k2);
});
