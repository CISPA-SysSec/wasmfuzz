// BCP-47 / Unicode locale identifier parsing (Intl.Locale, Intl.* locale
// arguments; Chromium base/i18n/language_tag_matcher.cc, SpiderMonkey locale_glue)
// plus the data-driven transforms applied to parsed locales.
//
// Input: [selector: u8] [locale string...]
#![no_main]
use icu_locale::fallback::{LocaleFallbackConfig, LocaleFallbackPriority};
use icu_locale::{
    LocaleCanonicalizer, LocaleDirectionality, LocaleExpander, LocaleFallbacker,
};
use icu_locale_core::{DataLocale, LanguageIdentifier, Locale};
use libfuzzer_sys::fuzz_target;
use writeable::Writeable;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, input)) = data.split_first() else { return };

    // LanguageIdentifier
    if let Ok(langid) = LanguageIdentifier::try_from_utf8(input) {
        let s = langid.write_to_string();
        assert_eq!(langid.strict_cmp(s.as_bytes()), core::cmp::Ordering::Equal);
        let reparsed = LanguageIdentifier::try_from_str(&s).expect("langid roundtrip");
        assert_eq!(reparsed, langid);
        if let Ok(norm) = LanguageIdentifier::normalize_utf8(input) {
            assert_eq!(norm, s);
        }
        // normalizing_eq() does not canonicalize variant order
        // ("sl-rozaj-biske-1994" parses, but normalizing_eq() on the input is
        // false), so only check it on already-normalized input.
        if input == s.as_bytes() {
            assert!(langid.normalizing_eq(&s));
        }
    } else {
        assert!(LanguageIdentifier::normalize_utf8(input).is_err());
    }

    let Ok(mut locale) = Locale::try_from_utf8(input) else {
        assert!(Locale::normalize_utf8(input).is_err());
        return;
    };
    let s = locale.write_to_string();
    assert_eq!(locale.strict_cmp(s.as_bytes()), core::cmp::Ordering::Equal);
    let reparsed = Locale::try_from_str(&s).expect("locale roundtrip");
    assert_eq!(reparsed, locale);
    assert_eq!(reparsed.total_cmp(&locale), core::cmp::Ordering::Equal);
    if let Ok(norm) = Locale::normalize_utf8(input) {
        assert_eq!(norm, s);
    }
    if input == s.as_bytes() {
        assert!(locale.normalizing_eq(&s));
    }
    let _ = locale.extensions.unicode.keywords.write_to_string();

    // Locale fallback (Chromium LanguageTagMatcher uses Language priority).
    let mut config = LocaleFallbackConfig::default();
    config.priority = if sel & 1 == 0 {
        LocaleFallbackPriority::Language
    } else {
        LocaleFallbackPriority::Script
    };
    let fallbacker = LocaleFallbacker::new().for_config(config);
    let mut iter = fallbacker.fallback_for(DataLocale::from(&locale));
    let mut steps = 0;
    while !iter.get().is_unknown() {
        let _ = iter.get().write_to_string();
        iter.step();
        steps += 1;
        assert!(steps < 64, "locale fallback does not terminate");
    }

    // Data-driven transforms.
    let expander = if sel & 2 == 0 {
        LocaleExpander::new_common()
    } else {
        LocaleExpander::new_extended()
    };
    let mut max = locale.id.clone();
    let _ = expander.maximize(&mut max);
    let mut min = locale.id.clone();
    let _ = expander.minimize(&mut min);
    let mut min2 = locale.id.clone();
    let _ = expander.minimize_favor_script(&mut min2);
    let _ = LocaleDirectionality::new_extended().get(&locale.id);

    let canonicalizer = if sel & 4 == 0 {
        LocaleCanonicalizer::new_common()
    } else {
        LocaleCanonicalizer::new_extended()
    };
    let _ = canonicalizer.canonicalize(&mut locale);
    let s2 = locale.write_to_string();
    let reparsed2 = Locale::try_from_str(&s2).expect("canonicalized locale roundtrip");
    assert_eq!(reparsed2, locale);
});
