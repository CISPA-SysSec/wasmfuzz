// IXDTF / RFC 9557 / ISO 8601 parser (Temporal string parsing in V8 via
// temporal_rs, icu_calendar / icu_time string constructors).
//
// Input: [selector: u8] [string...]
// Every parse entry point is run on the UTF-8 input and, for valid UTF-8, on
// its UTF-16 encoding; the two must agree.
#![no_main]
use ixdtf::encoding::{Utf16, Utf8};
use ixdtf::parsers::{IsoDurationParser, IxdtfParser, TimeZoneParser};
use ixdtf::records::{Annotation, IxdtfParseRecord, TimeZoneRecord, UtcOffsetRecordOrZ};
use libfuzzer_sys::fuzz_target;

fn touch_offset(o: &UtcOffsetRecordOrZ) {
    let r = o.resolve_rfc_9557();
    let _ = (r.is_minute_precision(), r.sign(), r.hour(), r.minute(), r.second());
    if let Some(f) = r.fraction() {
        let _ = f.to_nanoseconds();
        // Not called: Fraction::to_truncated_nanoseconds() in ixdtf 0.6.6
        // computes 10u64.pow(digits - 9), which overflows for >= 29 fraction
        // digits (divide-by-zero panic for >= 73). Reported separately; no
        // browser caller (temporal_rs only uses to_nanoseconds()).
    }
}

fn touch8(rec: &IxdtfParseRecord<'_, Utf8>) {
    if let Some(o) = &rec.offset {
        touch_offset(o);
    }
    if let Some(t) = &rec.time {
        let _ = t.fraction.map(|f| f.to_nanoseconds());
    }
}

fn same(a: &IxdtfParseRecord<'_, Utf8>, b: &IxdtfParseRecord<'_, Utf16>) {
    assert_eq!(a.date, b.date);
    assert_eq!(a.time, b.time);
    assert_eq!(a.offset, b.offset);
    assert_eq!(a.calendar.map(|c| c.len()), b.calendar.map(|c| c.len()));
    assert_eq!(a.tz.is_some(), b.tz.is_some());
}

fn handler8<'a>(sel: u8) -> impl FnMut(Annotation<'a, Utf8>) -> Option<Annotation<'a, Utf8>> {
    move |a| if sel & 0x80 != 0 && !a.critical { None } else { Some(a) }
}
fn handler16<'a>(sel: u8) -> impl FnMut(Annotation<'a, Utf16>) -> Option<Annotation<'a, Utf16>> {
    move |a| if sel & 0x80 != 0 && !a.critical { None } else { Some(a) }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, input)) = data.split_first() else { return };
    // The UTF-16 cursor rejects U+0000 / U+007F on *peek* (NonAsciiCodePoint)
    // while the UTF-8 one treats them as ordinary non-matching bytes. Combined
    // with ixdtf 0.6.6 never validating the last char of an IANA name
    // ("[UTC!]" is accepted; reported separately), inputs containing them
    // legitimately diverge (likewise for non-ASCII input), so the
    // differential check only runs on printable-ASCII-range input.
    let utf16: Option<Vec<u16>> = core::str::from_utf8(input)
        .ok()
        .filter(|s| s.bytes().all(|b| (0x01..0x7f).contains(&b)))
        .map(|s| s.encode_utf16().collect());

    match sel & 7 {
        0..=3 => {
            let kind = sel & 3;
            let r8 = {
                let mut p = IxdtfParser::from_utf8(input);
                match kind {
                    0 => p.parse_with_annotation_handler(handler8(sel)),
                    1 => p.parse_year_month_with_annotation_handler(handler8(sel)),
                    2 => p.parse_month_day_with_annotation_handler(handler8(sel)),
                    _ => p.parse_time_with_annotation_handler(handler8(sel)),
                }
            };
            if let Ok(rec) = &r8 {
                touch8(rec);
            }
            if let Some(u) = &utf16 {
                let mut p = IxdtfParser::from_utf16(u);
                let r16 = match kind {
                    0 => p.parse_with_annotation_handler(handler16(sel)),
                    1 => p.parse_year_month_with_annotation_handler(handler16(sel)),
                    2 => p.parse_month_day_with_annotation_handler(handler16(sel)),
                    _ => p.parse_time_with_annotation_handler(handler16(sel)),
                };
                assert_eq!(r8.is_ok(), r16.is_ok(), "utf8 {r8:?} vs utf16 {r16:?}");
                if let (Ok(a), Ok(b)) = (&r8, &r16) {
                    same(a, b);
                }
            }
        }
        4 | 5 => {
            let r8 = IsoDurationParser::<Utf8>::new(input).parse();
            if let Ok(d) = &r8 {
                if let Some(dd) = d.date {
                    let _ = (dd.years, dd.months, dd.weeks, dd.days);
                }
                let _ = d.time;
            }
            if let Some(u) = &utf16 {
                let r16 = IsoDurationParser::<Utf16>::new(u).parse();
                // Error kinds may differ between encodings; compare successes.
                assert_eq!(r8.ok(), r16.ok());
            }
        }
        _ => {
            let r8 = match sel & 0x18 {
                0 => TimeZoneParser::from_utf8(input).parse_identifier().map(|r| match r {
                    TimeZoneRecord::Name(n) => n.len() as i64,
                    TimeZoneRecord::Offset(o) => o.hour as i64,
                    _ => -1,
                }),
                0x08 => TimeZoneParser::from_utf8(input).parse_offset().map(|o| {
                    let _ = o.fraction().map(|f| f.to_nanoseconds());
                    o.minute() as i64
                }),
                _ => TimeZoneParser::from_utf8(input).parse_iana_identifier().map(|n| n.len() as i64),
            };
            if let Some(u) = &utf16 {
                let r16 = match sel & 0x18 {
                    0 => TimeZoneParser::from_utf16(u).parse_identifier().map(|r| match r {
                        TimeZoneRecord::Name(n) => n.len() as i64,
                        TimeZoneRecord::Offset(o) => o.hour as i64,
                        _ => -1,
                    }),
                    0x08 => TimeZoneParser::from_utf16(u).parse_offset().map(|o| o.minute() as i64),
                    _ => TimeZoneParser::from_utf16(u).parse_iana_identifier().map(|n| n.len() as i64),
                };
                assert_eq!(r8.is_ok(), r16.is_ok());
                // Error kinds may differ (the UTF-16 path reports DEL as
                // NonAsciiCodePoint), so only successful results are compared.
                if input.is_ascii() {
                    assert_eq!(r8.ok(), r16.ok());
                }
            }
        }
    }
});
