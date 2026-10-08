// Text segmentation as used by Firefox (intl/lwbrk: Line/Word/Grapheme/Sentence
// segmenters over UTF-16 and Latin-1 text) and Intl.Segmenter.
//
// Input: [selector: u8] [text...]
#![no_main]
use icu_locale_core::{langid, LanguageIdentifier};
use icu_segmenter::options::{
    LineBreakOptions, LineBreakStrictness, LineBreakWordOption, SentenceBreakInvariantOptions,
    WordBreakInvariantOptions,
};
use icu_segmenter::{
    GraphemeClusterSegmenter, LineSegmenter, SentenceSegmenter, WordSegmenter,
};
use libfuzzer_sys::fuzz_target;

fn check<I: Iterator<Item = usize>>(iter: I, len: usize) {
    let mut prev = None;
    let mut count = 0usize;
    for b in iter {
        assert!(b <= len, "breakpoint {b} out of bounds {len}");
        if let Some(p) = prev {
            assert!(b > p, "breakpoints not increasing: {p} then {b}");
        } else {
            assert_eq!(b, 0, "first breakpoint must be 0");
        }
        prev = Some(b);
        count += 1;
        assert!(count <= len + 2);
    }
    if len > 0 {
        assert_eq!(prev, Some(len), "last breakpoint must be the end");
    }
}

static JA: LanguageIdentifier = langid!("ja");
static ZH: LanguageIdentifier = langid!("zh");

fuzz_target!(|data: &[u8]| {
    let Some((&sel, text)) = data.split_first() else { return };
    let s = String::from_utf8_lossy(text);
    let u16s: Vec<u16> = s.encode_utf16().collect();

    match sel & 3 {
        0 => {
            let mut opts = LineBreakOptions::default();
            opts.strictness = match (sel >> 2) & 3 {
                0 => None,
                1 => Some(LineBreakStrictness::Loose),
                2 => Some(LineBreakStrictness::Normal),
                _ => Some(LineBreakStrictness::Anywhere),
            };
            opts.word_option = match (sel >> 4) & 3 {
                0 => None,
                1 => Some(LineBreakWordOption::BreakAll),
                2 => Some(LineBreakWordOption::KeepAll),
                _ => Some(LineBreakWordOption::Normal),
            };
            opts.content_locale = match (sel >> 6) & 1 {
                0 => None,
                _ => Some(if sel & 0x80 != 0 { &JA } else { &ZH }),
            };
            let seg = if sel & 0x80 != 0 {
                LineSegmenter::new_lstm(opts)
            } else {
                LineSegmenter::new_auto(opts)
            };
            check(seg.segment_str(&s), s.len());
            check(seg.segment_utf8(text), text.len());
            check(seg.segment_utf16(&u16s), u16s.len());
            check(seg.segment_latin1(text), text.len());
        }
        1 => {
            let seg = if sel & 4 != 0 {
                WordSegmenter::new_lstm(WordBreakInvariantOptions::default())
            } else if sel & 8 != 0 {
                WordSegmenter::new_dictionary(WordBreakInvariantOptions::default())
            } else {
                WordSegmenter::new_auto(WordBreakInvariantOptions::default())
            };
            let mut it = seg.segment_str(&s);
            let mut prev = 0;
            while let Some(b) = it.next() {
                assert!(b >= prev && b <= s.len());
                prev = b;
                let _ = it.word_type();
                let _ = it.is_word_like();
            }
            check(seg.segment_utf8(text), text.len());
            check(seg.segment_utf16(&u16s), u16s.len());
            check(seg.segment_latin1(text), text.len());
        }
        2 => {
            let seg = GraphemeClusterSegmenter::new();
            check(seg.segment_str(&s), s.len());
            check(seg.segment_utf8(text), text.len());
            check(seg.segment_utf16(&u16s), u16s.len());
            check(seg.segment_latin1(text), text.len());
        }
        _ => {
            let seg = SentenceSegmenter::new(SentenceBreakInvariantOptions::default());
            check(seg.segment_str(&s), s.len());
            check(seg.segment_utf8(text), text.len());
            check(seg.segment_utf16(&u16s), u16s.len());
            check(seg.segment_latin1(text), text.len());
        }
    }
});
