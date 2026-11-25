// Temporal string parsing as performed by V8 (Temporal.*.from(string),
// relativeTo / timeZone / calendar string arguments), via the temporal_rs APIs
// that temporal_capi wraps. Successfully parsed values are serialized again and
// the result must re-parse to the same value.
//
// Input: [selector: u8] [string...]
#![no_main]
mod common;

use core::str::FromStr;
use libfuzzer_sys::fuzz_target;
use temporal_rs::error::ErrorKind;
use temporal_rs::options::{
    Disambiguation, DisplayCalendar, DisplayOffset, DisplayTimeZone, OffsetDisambiguation,
    RelativeTo, ToStringRoundingOptions,
};
use temporal_rs::provider::TransitionDirection;
use temporal_rs::{
    Calendar, Duration, Instant, PlainDate, PlainDateTime, PlainMonthDay, PlainTime,
    PlainYearMonth, TimeZone, ZonedDateTime,
};

fn display_calendar(sel: u8) -> DisplayCalendar {
    match sel & 3 {
        0 => DisplayCalendar::Auto,
        1 => DisplayCalendar::Always,
        2 => DisplayCalendar::Never,
        _ => DisplayCalendar::Critical,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (ISODateToEpochDays).
fn iso_epoch_days(year: i32, month: u8, day: u8) -> i64 {
    let (m, d) = (i64::from(month), i64::from(day));
    let y = i64::from(year) - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn touch_date(d: &PlainDate) {
    let _ = (d.year(), d.month(), d.month_code(), d.day(), d.day_of_week(), d.day_of_year());
    let _ = (d.week_of_year(), d.year_of_week(), d.days_in_week(), d.days_in_month());
    let _ = (d.days_in_year(), d.months_in_year(), d.in_leap_year(), d.era(), d.era_year());
    let _ = d.to_plain_year_month();
    let _ = d.to_plain_month_day();
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, input)) = data.split_first() else { return };
    let p = common::provider();
    let dc = display_calendar(sel >> 4);

    match sel & 15 {
        0 => {
            let Ok(v) = PlainDate::from_utf8(input) else { return };
            touch_date(&v);
            let s = v.to_ixdtf_string(dc);
            let r = PlainDate::from_utf8(s.as_bytes()).expect("PlainDate reparse");
            if dc != DisplayCalendar::Never || v.calendar().identifier() == "iso8601" {
                assert_eq!(r.to_ixdtf_string(dc), s);
            }
        }
        1 => {
            let Ok(v) = PlainDateTime::from_utf8(input) else { return };
            touch_date(&v.to_plain_date());
            let s = v
                .to_ixdtf_string(ToStringRoundingOptions::default(), dc)
                .expect("PlainDateTime to_string");
            let r = PlainDateTime::from_utf8(s.as_bytes()).expect("PlainDateTime reparse");
            if dc != DisplayCalendar::Never || v.calendar().identifier() == "iso8601" {
                assert_eq!(r.to_ixdtf_string(ToStringRoundingOptions::default(), dc).unwrap(), s);
            }
        }
        2 => {
            let Ok(v) = PlainTime::from_utf8(input) else { return };
            let s = v
                .to_ixdtf_string(ToStringRoundingOptions::default())
                .expect("PlainTime to_string");
            let r = PlainTime::from_utf8(s.as_bytes()).expect("PlainTime reparse");
            assert_eq!(r, v);
        }
        3 => {
            let Ok(v) = PlainYearMonth::from_utf8(input) else { return };
            let _ = (v.year(), v.month(), v.month_code(), v.days_in_month(), v.in_leap_year());
            let s = v.to_ixdtf_string(dc);
            let _ = PlainYearMonth::from_utf8(s.as_bytes());
        }
        4 => {
            let Ok(v) = PlainMonthDay::from_utf8(input) else { return };
            let _ = (v.month_code(), v.day());
            let s = v.to_ixdtf_string(dc);
            let _ = PlainMonthDay::from_utf8(s.as_bytes());
        }
        5 => {
            let Ok(v) = Instant::from_utf8(input) else { return };
            let s = v
                .to_ixdtf_string_with_provider(None, ToStringRoundingOptions::default(), p)
                .expect("Instant to_string");
            let r = Instant::from_utf8(s.as_bytes()).expect("Instant reparse");
            assert_eq!(r, v);
            let _ = v.to_zoned_date_time_iso_with_provider(TimeZone::utc_with_provider(p), p);
        }
        6 => {
            let Ok(v) = Duration::from_utf8(input) else { return };
            let _ = v.sign();
            let s = v
                .as_temporal_string(ToStringRoundingOptions::default())
                .expect("Duration to_string");
            let r = Duration::from_utf8(s.as_bytes()).expect("Duration reparse");
            assert_eq!(r.as_temporal_string(ToStringRoundingOptions::default()).unwrap(), s);
        }
        7 | 8 => {
            let dis = match (sel >> 4) & 3 {
                0 => Disambiguation::Compatible,
                1 => Disambiguation::Earlier,
                2 => Disambiguation::Later,
                _ => Disambiguation::Reject,
            };
            let off = match (sel >> 6) & 3 {
                0 => OffsetDisambiguation::Use,
                1 => OffsetDisambiguation::Prefer,
                2 => OffsetDisambiguation::Ignore,
                _ => OffsetDisambiguation::Reject,
            };
            let Ok(v) = ZonedDateTime::from_utf8_with_provider(input, dis, off, p) else { return };
            let _ = (v.offset(), v.offset_nanoseconds(), v.hours_in_day_with_provider(p));
            let _ = v.start_of_day_with_provider(p);
            let _ = v.get_time_zone_transition_with_provider(TransitionDirection::Next, p);
            let _ = v.get_time_zone_transition_with_provider(TransitionDirection::Previous, p);
            touch_date(&v.to_plain_date());
            let s = v
                .to_ixdtf_string_with_provider(
                    DisplayOffset::Auto,
                    DisplayTimeZone::Auto,
                    DisplayCalendar::Auto,
                    ToStringRoundingOptions::default(),
                    p,
                )
                .expect("ZonedDateTime to_string");
            let reparse = |dis, off| {
                ZonedDateTime::from_utf8_with_provider(s.as_bytes(), dis, off, p)
            };
            match reparse(Disambiguation::Compatible, OffsetDisambiguation::Reject) {
                Ok(r) => assert!(r.equals_with_provider(&v, p).expect("equals")),
                Err(e) => {
                    // offset: "reject" runs CheckISODaysRange on the wall-clock date
                    // (InterpretISODateTimeOffset step 7), so a valid instant whose local date
                    // lies outside +-10^8 epoch days (-271821-04-19T23:59[-16:09]) prints a
                    // string the spec requires to throw a RangeError. offset: "use" does not
                    // round-trip either (the printed offset is rounded to minutes, LMT offsets
                    // are not). What the spec does guarantee: the wall-clock time in the zone
                    // (offset: "ignore") names v as one of its possible instants.
                    let d = v.with_calendar(Calendar::ISO).to_plain_date();
                    assert!(
                        e.kind() == ErrorKind::Range
                            && iso_epoch_days(d.year(), d.month(), d.day()).abs() > 100_000_000,
                        "ZonedDateTime reparse: {e:?}"
                    );
                    let found = [Disambiguation::Earlier, Disambiguation::Later].into_iter().any(|dis| {
                        reparse(dis, OffsetDisambiguation::Ignore)
                            .expect("ZonedDateTime reparse (offset: ignore)")
                            .equals_with_provider(&v, p)
                            .expect("equals")
                    });
                    assert!(found, "ZonedDateTime reparse (offset: ignore) lost the instant");
                }
            }
        }
        9 => {
            let Ok(s) = core::str::from_utf8(input) else { return };
            if let Ok(tz) = TimeZone::try_from_str_with_provider(s, p) {
                let _ = tz.identifier_with_provider(p);
            }
            let _ = TimeZone::try_from_identifier_str_with_provider(s, p);
        }
        10 => {
            let Ok(s) = core::str::from_utf8(input) else { return };
            let _ = RelativeTo::try_from_str_with_provider(s, p);
        }
        11 => {
            let Ok(s) = core::str::from_utf8(input) else { return };
            if let Ok(c) = Calendar::from_str(s) {
                let _ = c.identifier();
            }
        }
        _ => {
            let _ = temporal_rs::parsers::intermediates::ParsedDate::from_utf8(input);
            let _ = temporal_rs::parsers::intermediates::ParsedDateTime::from_utf8(input);
            let _ = temporal_rs::parsers::intermediates::ParsedZonedDateTime::from_utf8_with_provider(input, p);
        }
    }
});
