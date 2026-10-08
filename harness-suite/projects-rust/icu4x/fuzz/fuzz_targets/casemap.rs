// Case mapping (String.prototype.toLocale{Upper,Lower}Case, case folding).
// Chromium ships icu_casemap with compiled_data; SpiderMonkey uses it for
// RegExp case closure.
//
// Input: [flags: u8] [text...]
#![no_main]
use icu_casemap::options::{LeadingAdjustment, TitlecaseOptions, TrailingCase};
use icu_casemap::{CaseMapCloser, CaseMapper, TitlecaseMapper};
use icu_collections::codepointinvlist::CodePointInversionListBuilder;
use icu_locale_core::{langid, LanguageIdentifier};
use libfuzzer_sys::fuzz_target;
use writeable::Writeable;

static LANGS: [LanguageIdentifier; 7] = [
    langid!("und"),
    langid!("tr"),
    langid!("az"),
    langid!("lt"),
    langid!("el"),
    langid!("nl"),
    langid!("hy"),
];

fn check_writeable<W: Writeable>(w: W, expected: &str) {
    let s = w.write_to_string();
    assert_eq!(s, expected);
    let hint = w.writeable_length_hint();
    // Not checked: the lower bound is `at_least(src.len())` in icu_casemap 2.2.0
    // although mappings can shrink ("ﬁ" -> "FI", Turkish "İ" -> "i").
    let _ = hint.0;
    if let Some(upper) = hint.1 {
        assert!(s.len() <= upper, "length hint upper bound {} < {}", upper, s.len());
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, input)) = data.split_first() else { return };
    let s = String::from_utf8_lossy(input);
    let lang = &LANGS[(flags as usize & 7) % LANGS.len()];
    let cm = CaseMapper::new();

    let lower = cm.lowercase_to_string(&s, lang);
    check_writeable(cm.lowercase(&s, lang), &lower);
    let upper = cm.uppercase_to_string(&s, lang);
    check_writeable(cm.uppercase(&s, lang), &upper);
    let fold = cm.fold_string(&s);
    check_writeable(cm.fold(&s), &fold);
    let fold_t = cm.fold_turkic_string(&s);
    check_writeable(cm.fold_turkic(&s), &fold_t);
    // Folding is idempotent.
    assert_eq!(cm.fold_string(&fold), fold);

    let mut opts = TitlecaseOptions::default();
    opts.leading_adjustment = match (flags >> 3) & 3 {
        0 => None,
        1 => Some(LeadingAdjustment::None),
        2 => Some(LeadingAdjustment::Auto),
        _ => Some(LeadingAdjustment::ToCased),
    };
    opts.trailing_case = match (flags >> 5) & 3 {
        0 => None,
        1 => Some(TrailingCase::Lower),
        _ => Some(TrailingCase::Unchanged),
    };
    let tc = TitlecaseMapper::new();
    let title = tc.titlecase_segment_to_string(&s, lang, opts);
    check_writeable(tc.titlecase_segment(&s, lang, opts), &title);
    let title2 = cm.titlecase_segment_with_only_case_data_to_string(&s, lang, opts);
    check_writeable(cm.titlecase_segment_with_only_case_data(&s, lang, opts), &title2);

    let mut builder = CodePointInversionListBuilder::new();
    for c in s.chars().take(64) {
        let _ = cm.simple_lowercase(c);
        let _ = cm.simple_uppercase(c);
        let _ = cm.simple_titlecase(c);
        let _ = cm.simple_fold(c);
        let _ = cm.simple_fold_turkic(c);
        cm.add_case_closure_to(c, &mut builder);
    }
    if flags & 0x80 != 0 {
        let closer = CaseMapCloser::new();
        let _ = closer.add_string_case_closure_to(&s, &mut builder);
    }
    let _ = builder.build().size();
});
