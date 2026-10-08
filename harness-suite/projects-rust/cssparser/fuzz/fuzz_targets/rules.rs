#![no_main]
//! Stylesheet / rule-list / declaration-list parsing with a generic parser.
//!
//! Mirrors how Stylo drives cssparser: a `StyleSheetParser` at the top level,
//! `RuleBodyParser` for style rule bodies (with CSS nesting), group at-rules
//! (`@media`, `@supports`, ...) containing nested rules, declaration-only
//! at-rules (`@font-face`, `@page`, ...), `!important` handling, and a few
//! typed value parsers (`expect_*`, `UnicodeRange`, comma-separated lists).
//! The same input is also parsed as a style attribute (declaration list) and
//! through `parse_one_rule` / `parse_one_declaration`.

use cssparser::*;

#[derive(Debug)]
#[allow(dead_code)]
enum Item {
    Decl(String, String, bool),
    Qualified(String, Vec<Item>),
    AtRule(String, String, Option<Vec<Item>>),
}

#[derive(Clone, Copy, PartialEq)]
enum Ctx {
    TopLevel,
    StyleRule,
    GroupRule,
    Declarations,
}

struct P {
    ctx: Ctx,
    depth: u32,
}

const MAX_DEPTH: u32 = 32;

fn serialize_component_values(
    input: &mut Parser,
    out: &mut String,
) -> Result<(), ParseError<()>> {
    let mut prev = TokenSerializationType::Nothing;
    loop {
        let token = match input.next_including_whitespace_and_comments() {
            Ok(t) => t.clone(),
            Err(_) => return Ok(()),
        };
        let ty = token.serialization_type();
        if prev.needs_separator_when_before(ty) {
            out.push_str("/**/");
        }
        prev = ty;
        let _ = token.to_css(out);
        let close = match token {
            Token::Function(_) | Token::ParenthesisBlock => ")",
            Token::SquareBracketBlock => "]",
            Token::CurlyBracketBlock => "}",
            _ => continue,
        };
        input
            .parse_nested_block(|i| -> Result<(), ParseError<()>> {
                let _ = serialize_component_values(i, out);
                Ok(())
            })
            .map_err(|_| ParseError::custom(()))?;
        out.push_str(close);
    }
}

/// Exercise some typed value parsers the way property parsers would.
fn typed_values<'i>(name: &str, input: &mut Parser<'i>) {
    let start = input.state();
    let _ = input.try_parse(|i| i.expect_number());
    let _ = input.try_parse(|i| i.expect_integer());
    let _ = input.try_parse(|i| i.expect_percentage());
    let _ = input.try_parse(|i| i.expect_url_or_string().map(|s| s.len()));
    let _ = input.try_parse(|i| i.expect_ident_or_string().map(|s| s.len()));
    let _ = input.try_parse(|i| {
        i.expect_function().map(|_| ())?;
        i.parse_nested_block(|i| {
            i.parse_comma_separated(|i| {
                let t = i.next()?.clone();
                Ok::<_, ParseError<()>>(t)
            })
        })
    });
    input.reset(&start);
    if name.eq_ignore_ascii_case("unicode-range") {
        let _ = input.try_parse(|i| {
            i.parse_comma_separated(|i| UnicodeRange::parse(i).map_err(ParseError::<()>::from))
                .map(|v: Vec<UnicodeRange>| {
                    let mut s = String::new();
                    for r in v {
                        let _ = r.to_css(&mut s);
                    }
                    s
                })
        });
        input.reset(&start);
    }
    let _ = input.try_parse(|i| {
        let v = i.parse_comma_separated_ignoring_errors(|i| {
            let loc = i.current_source_location();
            let t = i.next()?.clone();
            let _ = loc;
            Ok::<_, ParseError<()>>(t)
        });
        Ok::<_, ()>(v.len())
    });
    input.reset(&start);
}

impl<'i> DeclarationParser<'i> for P {
    type Declaration = Item;
    type Error = ();

    fn parse_value(
        &mut self,
        name: CowRcStr<'i>,
        input: &mut Parser<'i>,
        _start: &ParserState,
    ) -> Result<Item, ParseError<()>> {
        typed_values(&name, input);
        let mut value = String::new();
        let mut important = false;
        loop {
            let before = input.state();
            let tok = match input.next_including_whitespace() {
                Ok(t) => t.clone(),
                Err(_) => break,
            };
            if tok == Token::Delim('!') {
                input.reset(&before);
                if input.try_parse(parse_important).is_ok() && input.is_exhausted() {
                    important = true;
                    break;
                }
                input.reset(&before);
                input.next_including_whitespace()?;
                value.push('!');
                continue;
            }
            input.reset(&before);
            let _ = input.slice_from(before.position());
            input.next_including_whitespace()?;
            let _ = tok.to_css(&mut value);
            match tok {
                Token::Function(_)
                | Token::ParenthesisBlock
                | Token::SquareBracketBlock
                | Token::CurlyBracketBlock => {
                    input.parse_nested_block(|i| -> Result<(), ParseError<()>> {
                        let _ = serialize_component_values(i, &mut value);
                        Ok(())
                    })?;
                }
                _ => {}
            }
        }
        let mut n = String::new();
        let _ = serialize_identifier(&name, &mut n);
        Ok(Item::Decl(n, value, important))
    }
}

fn is_group_rule(name: &str) -> bool {
    match_ignore_ascii_case! { name,
        "media" | "supports" | "layer" | "container" | "scope" | "document"
            | "-moz-document" | "starting-style" | "keyframes" | "-webkit-keyframes" => true,
        _ => false,
    }
}

impl<'i> AtRuleParser<'i> for P {
    type Prelude = (String, String);
    type AtRule = Item;
    type Error = ();

    fn parse_prelude(
        &mut self,
        name: CowRcStr<'i>,
        input: &mut Parser<'i>,
    ) -> Result<(String, String), ParseError<()>> {
        match_ignore_ascii_case! { &*name,
            "charset" => return Err(ParseError::from_basic_kind(BasicParseErrorKind::AtRuleInvalid)),
            "import" | "namespace" => {
                let _ = input.try_parse(|i| i.expect_ident().map(|s| s.len()));
                let _ = input.expect_url_or_string()?;
            },
            _ => {},
        }
        let mut prelude = String::new();
        let _ = input.parse_until_before(Delimiter::CurlyBracketBlock, |i| {
            let _ = i.parse_comma_separated_ignoring_errors(|i| {
                let mut s = String::new();
                serialize_component_values(i, &mut s).map_err(|_| ParseError::custom(()))?;
                Ok::<_, ParseError<()>>(s)
            });
            Ok::<_, ParseError<()>>(())
        });
        let _ = serialize_component_values(input, &mut prelude);
        Ok((name.to_string(), prelude))
    }

    fn rule_without_block(
        &mut self,
        (name, prelude): (String, String),
        _start: &ParserState,
    ) -> Result<Item, ()> {
        Ok(Item::AtRule(name, prelude, None))
    }

    fn parse_block(
        &mut self,
        (name, prelude): (String, String),
        _start: &ParserState,
        input: &mut Parser<'i>,
    ) -> Result<Item, ParseError<()>> {
        if self.depth >= MAX_DEPTH {
            return Err(ParseError::custom(()));
        }
        let ctx = if is_group_rule(&name) {
            if self.ctx == Ctx::StyleRule {
                Ctx::StyleRule
            } else {
                Ctx::GroupRule
            }
        } else {
            Ctx::Declarations
        };
        let mut nested = P {
            ctx,
            depth: self.depth + 1,
        };
        let items = RuleBodyParser::new(input, &mut nested)
            .filter_map(|r| r.map_err(|(e, slice, loc)| (e.kind, slice.len(), loc.line)).ok())
            .collect();
        Ok(Item::AtRule(name, prelude, Some(items)))
    }
}

impl<'i> QualifiedRuleParser<'i> for P {
    type Prelude = String;
    type QualifiedRule = Item;
    type Error = ();

    fn parse_prelude(&mut self, input: &mut Parser<'i>) -> Result<String, ParseError<()>> {
        let mut s = String::new();
        // Selector lists are comma separated.
        let parts = input.parse_comma_separated(|i| {
            let mut part = String::new();
            serialize_component_values(i, &mut part).map_err(|_| ParseError::custom(()))?;
            if part.trim().is_empty() {
                return Err(ParseError::custom(()));
            }
            Ok(part)
        })?;
        for p in parts {
            s.push_str(&p);
            s.push(',');
        }
        Ok(s)
    }

    fn parse_block(
        &mut self,
        prelude: String,
        _start: &ParserState,
        input: &mut Parser<'i>,
    ) -> Result<Item, ParseError<()>> {
        if self.depth >= MAX_DEPTH {
            return Err(ParseError::custom(()));
        }
        let mut nested = P {
            ctx: Ctx::StyleRule,
            depth: self.depth + 1,
        };
        let items = RuleBodyParser::new(input, &mut nested)
            .filter_map(|r| r.ok())
            .collect();
        Ok(Item::Qualified(prelude, items))
    }
}

impl<'i> RuleBodyItemParser<'i, Item, ()> for P {
    fn parse_declarations(&self) -> bool {
        matches!(self.ctx, Ctx::StyleRule | Ctx::Declarations)
    }
    fn parse_qualified(&self) -> bool {
        matches!(self.ctx, Ctx::TopLevel | Ctx::StyleRule | Ctx::GroupRule)
    }
}

libfuzzer_sys::fuzz_target!(|data: &str| {
    // Stylesheet.
    {
        let mut input = Parser::new(data);
        let mut p = P {
            ctx: Ctx::TopLevel,
            depth: 0,
        };
        let mut n = 0usize;
        for r in StyleSheetParser::new(&mut input, &mut p) {
            match r {
                Ok(item) => n += format!("{:?}", item).len(),
                Err((e, slice, loc)) => {
                    n += slice.len() + loc.line as usize + loc.column as usize;
                    n += format!("{:?}", e.kind).len();
                }
            }
        }
        std::hint::black_box(n);
    }
    // Style attribute (declaration list, e.g. `style="..."`).
    {
        let mut input = Parser::new(data);
        let mut p = P {
            ctx: Ctx::StyleRule,
            depth: 0,
        };
        let items: Vec<_> = RuleBodyParser::new(&mut input, &mut p).collect();
        std::hint::black_box(items.len());
    }
    // Single rule / declaration (CSSOM insertRule / setProperty-like entry points).
    {
        let mut input = Parser::new(data);
        let mut p = P {
            ctx: Ctx::TopLevel,
            depth: 0,
        };
        let _ = std::hint::black_box(parse_one_rule(&mut input, &mut p).is_ok());
    }
    {
        let mut input = Parser::new(data);
        let mut p = P {
            ctx: Ctx::Declarations,
            depth: 0,
        };
        let _ = std::hint::black_box(parse_one_declaration(&mut input, &mut p).is_ok());
    }
});
