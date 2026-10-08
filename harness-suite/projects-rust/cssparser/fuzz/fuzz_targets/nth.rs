#![no_main]
//! `parse_nth` (An+B microsyntax, used by :nth-child() & co.), both on the whole
//! input and on each comma-separated piece, followed by an optional `of <...>`.

use cssparser::*;

fn one(input: &mut Parser) -> Result<(i32, i32), ParseError<()>> {
    let (a, b) = parse_nth(input)?;
    // Like selectors' :nth-child(An+B of S): optionally followed by `of`.
    if input.try_parse(|i| i.expect_ident_matching("of")).is_ok() {
        while input.next().is_ok() {}
    }
    Ok((a, b))
}

libfuzzer_sys::fuzz_target!(|data: &str| {
    let mut input = Parser::new(data);
    if let Ok((a, b)) = input.parse_entirely(parse_nth_entirely) {
        // Evaluating the formula the way selector matching does must not overflow-panic.
        for idx in 1..8i32 {
            let _ = std::hint::black_box(idx.checked_sub(b).map(|d| a != 0 && d % a == 0));
        }
    }
    let mut input = Parser::new(data);
    let _ = std::hint::black_box(input.parse_comma_separated(one));
    let mut input = Parser::new(data);
    let _ = std::hint::black_box(input.parse_comma_separated_ignoring_errors(one));
});

fn parse_nth_entirely(input: &mut Parser) -> Result<(i32, i32), ParseError<()>> {
    Ok(parse_nth(input)?)
}
