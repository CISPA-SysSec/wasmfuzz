// Temporal arithmetic as exposed by V8: add/subtract/since/until/round/compare
// on parsed Temporal values, Duration.round/total/compare with relativeTo.
//
// Input: [op] [largest] [smallest] [mode] [increment] a 0x00 b 0x00 c
// where a/b are values of the kind selected by `op` and c is a Duration
// (or, for Duration ops, a relativeTo string).
#![no_main]
mod common;

use core::cmp::Ordering;
use libfuzzer_sys::fuzz_target;
use temporal_rs::options::{
    DifferenceSettings, Disambiguation, OffsetDisambiguation, Overflow, RelativeTo,
    RoundingIncrement, RoundingMode, RoundingOptions, Unit,
};
use temporal_rs::{
    Duration, Instant, PlainDate, PlainDateTime, PlainTime, PlainYearMonth, ZonedDateTime,
};

const UNITS: [Unit; 11] = [
    Unit::Auto,
    Unit::Nanosecond,
    Unit::Microsecond,
    Unit::Millisecond,
    Unit::Second,
    Unit::Minute,
    Unit::Hour,
    Unit::Day,
    Unit::Week,
    Unit::Month,
    Unit::Year,
];
const MODES: [RoundingMode; 9] = [
    RoundingMode::Ceil,
    RoundingMode::Floor,
    RoundingMode::Expand,
    RoundingMode::Trunc,
    RoundingMode::HalfCeil,
    RoundingMode::HalfFloor,
    RoundingMode::HalfExpand,
    RoundingMode::HalfTrunc,
    RoundingMode::HalfEven,
];

fn unit(b: u8) -> Option<Unit> {
    // 0 => not specified
    (b % 12).checked_sub(1).map(|i| UNITS[i as usize])
}

struct Opts {
    largest: Option<Unit>,
    smallest: Option<Unit>,
    mode: Option<RoundingMode>,
    increment: Option<RoundingIncrement>,
    overflow: Option<Overflow>,
}

impl Opts {
    fn diff(&self) -> DifferenceSettings {
        let mut s = DifferenceSettings::default();
        s.largest_unit = self.largest;
        s.smallest_unit = self.smallest;
        s.rounding_mode = self.mode;
        s.increment = self.increment;
        s
    }
    fn round(&self) -> RoundingOptions {
        let mut r = RoundingOptions::default();
        r.largest_unit = self.largest;
        r.smallest_unit = self.smallest;
        r.rounding_mode = self.mode;
        r.increment = self.increment;
        r
    }
}

fn split3(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let mut it = data.splitn(3, |b| *b == 0);
    (
        it.next().unwrap_or(&[]),
        it.next().unwrap_or(&[]),
        it.next().unwrap_or(&[]),
    )
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let (hdr, rest) = data.split_at(5);
    let op = hdr[0];
    let opts = Opts {
        largest: unit(hdr[1]),
        smallest: unit(hdr[2]),
        mode: (hdr[3] % 10).checked_sub(1).map(|i| MODES[i as usize]),
        increment: match hdr[4] {
            0 => None,
            n => RoundingIncrement::try_new(u32::from(n)).ok(),
        },
        overflow: match (hdr[3] / 10) % 3 {
            0 => None,
            1 => Some(Overflow::Constrain),
            _ => Some(Overflow::Reject),
        },
    };
    let (a, b, c) = split3(rest);
    let p = common::provider();

    match op % 7 {
        0 => {
            let (Ok(a), Ok(b)) = (PlainDate::from_utf8(a), PlainDate::from_utf8(b)) else { return };
            let _ = PlainDate::compare_iso(&a, &b);
            if let Ok(d) = Duration::from_utf8(c) {
                let _ = a.add(&d, opts.overflow);
                let _ = a.subtract(&d, opts.overflow);
            }
            let _ = a.until(&b, opts.diff());
            let _ = a.since(&b, opts.diff());
            // With default settings (largestUnit = day) the difference is exact.
            if let Ok(d) = a.until(&b, DifferenceSettings::default()) {
                if a.calendar() == b.calendar() {
                    let back = a.add(&d, Some(Overflow::Reject)).expect("date + (b - a)");
                    assert_eq!(back.compare_iso(&b), Ordering::Equal);
                }
            }
        }
        1 => {
            let (Ok(a), Ok(b)) = (PlainDateTime::from_utf8(a), PlainDateTime::from_utf8(b)) else {
                return;
            };
            let _ = PlainDateTime::compare_iso(&a, &b);
            if let Ok(d) = Duration::from_utf8(c) {
                let _ = a.add(&d, opts.overflow);
                let _ = a.subtract(&d, opts.overflow);
            }
            let _ = a.until(&b, opts.diff());
            let _ = a.since(&b, opts.diff());
            let _ = a.round(opts.round());
        }
        2 => {
            let (Ok(a), Ok(b)) = (PlainTime::from_utf8(a), PlainTime::from_utf8(b)) else { return };
            if let Ok(d) = Duration::from_utf8(c) {
                let _ = a.add(&d);
                let _ = a.subtract(&d);
            }
            let _ = a.until(&b, opts.diff());
            let _ = a.since(&b, opts.diff());
            let _ = a.round(opts.round());
        }
        3 => {
            let (Ok(a), Ok(b)) = (PlainYearMonth::from_utf8(a), PlainYearMonth::from_utf8(b)) else {
                return;
            };
            let _ = a.compare_iso(&b);
            if let Ok(d) = Duration::from_utf8(c) {
                let ov = opts.overflow.unwrap_or(Overflow::Constrain);
                let _ = a.add(&d, ov);
                let _ = a.subtract(&d, ov);
            }
            let _ = a.until(&b, opts.diff());
            let _ = a.since(&b, opts.diff());
        }
        4 => {
            let (Ok(a), Ok(b)) = (Instant::from_utf8(a), Instant::from_utf8(b)) else { return };
            if let Ok(d) = Duration::from_utf8(c) {
                let _ = a.add(&d);
                let _ = a.subtract(&d);
            }
            let _ = a.until(&b, opts.diff());
            let _ = a.since(&b, opts.diff());
            let _ = a.round(opts.round());
            if let Ok(d) = a.until(&b, DifferenceSettings::default()) {
                let back = a.add(&d).expect("instant + (b - a)");
                assert_eq!(back, b);
            }
        }
        5 => {
            let parse = |s: &[u8]| {
                ZonedDateTime::from_utf8_with_provider(
                    s,
                    Disambiguation::Compatible,
                    OffsetDisambiguation::Reject,
                    p,
                )
            };
            let (Ok(a), Ok(b)) = (parse(a), parse(b)) else { return };
            let _ = a.compare_instant(&b);
            if let Ok(d) = Duration::from_utf8(c) {
                let _ = a.add_with_provider(&d, opts.overflow, p);
                let _ = a.subtract_with_provider(&d, opts.overflow, p);
            }
            let _ = a.until_with_provider(&b, opts.diff(), p);
            let _ = a.since_with_provider(&b, opts.diff(), p);
            let _ = a.round_with_provider(opts.round(), p);
            let _ = a.with_time_zone_with_provider(b.time_zone().clone(), p);
        }
        _ => {
            let (Ok(a), Ok(b)) = (Duration::from_utf8(a), Duration::from_utf8(b)) else { return };
            let rel = core::str::from_utf8(c)
                .ok()
                .filter(|s| !s.is_empty())
                .and_then(|s| RelativeTo::try_from_str_with_provider(s, p).ok());
            let _ = a.add(&b);
            let _ = a.subtract(&b);
            let _ = a.negated();
            let _ = a.abs();
            let _ = a.round_with_provider(opts.round(), rel.clone(), p);
            if let Some(u) = opts.smallest {
                let _ = a.total_with_provider(u, rel.clone(), p);
            }
            let _ = a.compare_with_provider(&b, rel, p);
        }
    }
});
