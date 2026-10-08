#![no_main]
//! CSS color parsing via cssparser-color (`Color::parse`) plus cssparser's own
//! color helpers (`parse_hash_color`, `parse_named_color`,
//! `PredefinedColorSpace`). Parsed colors are serialized and re-parsed.
//! Note: Firefox does not ship cssparser-color itself (Stylo has its own color
//! parser on top of cssparser), but it exercises the same cssparser primitives.

use cssparser::color::{PredefinedColorSpace, parse_hash_color, parse_named_color};
use cssparser::*;
use cssparser_color::Color;

fn parse_all(data: &str) -> Vec<Color> {
    let mut input = Parser::new(data);
    input.parse_comma_separated_ignoring_errors(|i| Color::parse(i))
}

libfuzzer_sys::fuzz_target!(|data: &str| {
    let mut input = Parser::new(data);
    if let Ok(c) = input.parse_entirely(Color::parse) {
        let s = c.to_css_string();
        let mut again = Parser::new(&s);
        if let Ok(c2) = again.parse_entirely(Color::parse) {
            std::hint::black_box(c2.to_css_string());
        }
    }
    for c in parse_all(data) {
        std::hint::black_box(c.to_css_string());
    }
    let _ = std::hint::black_box(parse_hash_color(data.as_bytes()));
    let _ = std::hint::black_box(parse_named_color(data));
    let mut input = Parser::new(data);
    if let Ok(cs) = input.try_parse(PredefinedColorSpace::parse) {
        std::hint::black_box(cs.to_css_string());
    }
});
