#![no_main]
//! Selector list parsing with Firefox's in-tree `selectors` crate
//! (servo/components/selectors), using a minimal `SelectorImpl` modelled on the
//! crate's own test `DummySelectorImpl`.
//!
//! Input: first byte = flags (parse variant, ParseRelative mode, which optional
//! syntax the embedder enables, default namespace), rest = selector text.
//! Parsed lists are serialized, re-parsed, and nested into a parent list via
//! `replace_parent_selector` (CSS nesting `&`).

use cssparser::{
    ParseError, Parser as CssParser, ToCss, match_ignore_ascii_case,
    serialize_identifier,
};
use precomputed_hash::PrecomputedHash;
use selectors::parser::{
    self, ParseRelative, SelectorImpl, SelectorList, SelectorParseError, SelectorParseErrorKind,
};
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
enum PseudoClass {
    Hover,
    Active,
    Focus,
    Checked,
    Lang(String),
    Dir(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PseudoElement {
    Before,
    After,
    Marker,
    Placeholder,
    DetailsContent,
    Highlight(String),
}

impl parser::PseudoElement for PseudoElement {
    fn accepts_state_pseudo_classes(&self) -> bool {
        true
    }
    fn valid_after_slotted(&self) -> bool {
        matches!(self, Self::Before | Self::After | Self::Marker | Self::Placeholder)
    }
    fn valid_after_before_or_after(&self) -> bool {
        matches!(self, Self::Marker)
    }
    fn is_before_or_after(&self) -> bool {
        matches!(self, Self::Before | Self::After)
    }
    fn parses_as_element_backed(&self) -> bool {
        matches!(self, Self::DetailsContent)
    }
}

impl parser::NonTSPseudoClass for PseudoClass {
    fn is_active_or_hover(&self) -> bool {
        matches!(self, Self::Active | Self::Hover)
    }
    fn is_user_action_state(&self) -> bool {
        matches!(self, Self::Active | Self::Hover | Self::Focus)
    }
}

impl ToCss for PseudoClass {
    fn to_css<W: fmt::Write>(&self, dest: &mut W) -> fmt::Result {
        match self {
            Self::Hover => dest.write_str(":hover"),
            Self::Active => dest.write_str(":active"),
            Self::Focus => dest.write_str(":focus"),
            Self::Checked => dest.write_str(":checked"),
            Self::Lang(l) => {
                dest.write_str(":lang(")?;
                serialize_identifier(l, dest)?;
                dest.write_char(')')
            }
            Self::Dir(d) => {
                dest.write_str(":dir(")?;
                serialize_identifier(d, dest)?;
                dest.write_char(')')
            }
        }
    }
}

impl ToCss for PseudoElement {
    fn to_css<W: fmt::Write>(&self, dest: &mut W) -> fmt::Result {
        match self {
            Self::Before => dest.write_str("::before"),
            Self::After => dest.write_str("::after"),
            Self::Marker => dest.write_str("::marker"),
            Self::Placeholder => dest.write_str("::placeholder"),
            Self::DetailsContent => dest.write_str("::details-content"),
            Self::Highlight(n) => {
                dest.write_str("::highlight(")?;
                serialize_identifier(n, dest)?;
                dest.write_char(')')
            }
        }
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct Atom(String);

impl ToCss for Atom {
    fn to_css<W: fmt::Write>(&self, dest: &mut W) -> fmt::Result {
        serialize_identifier(&self.0, dest)
    }
}
impl From<&str> for Atom {
    fn from(s: &str) -> Self {
        Atom(s.into())
    }
}
impl PrecomputedHash for Atom {
    fn precomputed_hash(&self) -> u32 {
        // FNV-1a; deterministic (unlike the pointer-based hash in the upstream test impl).
        let mut h: u32 = 0x811c9dc5;
        for b in self.0.bytes() {
            h ^= b as u32;
            h = h.wrapping_mul(0x01000193);
        }
        h
    }
}

#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct AttrValue(String);

impl ToCss for AttrValue {
    fn to_css<W: fmt::Write>(&self, dest: &mut W) -> fmt::Result {
        use std::fmt::Write;
        dest.write_char('"')?;
        write!(cssparser::CssStringWriter::new(dest), "{}", &self.0)?;
        dest.write_char('"')
    }
}
impl From<&str> for AttrValue {
    fn from(s: &str) -> Self {
        AttrValue(s.into())
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Impl;

impl SelectorImpl for Impl {
    type ExtraMatchingData<'a> = std::marker::PhantomData<&'a ()>;
    type AttrValue = AttrValue;
    type Identifier = Atom;
    type LocalName = Atom;
    type NamespaceUrl = Atom;
    type NamespacePrefix = Atom;
    type BorrowedLocalName = Atom;
    type BorrowedNamespaceUrl = Atom;
    type NonTSPseudoClass = PseudoClass;
    type PseudoElement = PseudoElement;
}

struct P {
    flags: u8,
}

impl<'i> parser::Parser<'i> for P {
    type Impl = Impl;
    type Error = SelectorParseErrorKind;

    fn parse_slotted(&self) -> bool {
        self.flags & 0x10 == 0
    }
    fn parse_part(&self) -> bool {
        self.flags & 0x10 == 0
    }
    fn parse_nth_child_of(&self) -> bool {
        true
    }
    fn parse_is_and_where(&self) -> bool {
        true
    }
    fn parse_has(&self) -> bool {
        self.flags & 0x20 == 0
    }
    fn parse_parent_selector(&self) -> bool {
        true
    }
    fn parse_host(&self) -> bool {
        self.flags & 0x10 == 0
    }

    fn parse_non_ts_pseudo_class(
        &self,
        name: &str,
    ) -> Result<PseudoClass, SelectorParseError> {
        match_ignore_ascii_case! { name,
            "hover" => return Ok(PseudoClass::Hover),
            "active" => return Ok(PseudoClass::Active),
            "focus" => return Ok(PseudoClass::Focus),
            "checked" => return Ok(PseudoClass::Checked),
            _ => {}
        }
        Err(ParseError::custom(
            SelectorParseErrorKind::UnsupportedPseudoClassOrElement,
        ))
    }

    fn parse_non_ts_functional_pseudo_class(
        &self,
        name: &str,
        parser: &mut CssParser<'i>,
        after_part: bool,
    ) -> Result<PseudoClass, SelectorParseError> {
        match_ignore_ascii_case! { name,
            "lang" if !after_part => {
                let lang = parser.expect_ident_or_string()?.as_ref().to_owned();
                return Ok(PseudoClass::Lang(lang));
            },
            "dir" => {
                let d = parser.expect_ident()?.as_ref().to_owned();
                return Ok(PseudoClass::Dir(d));
            },
            _ => {}
        }
        Err(ParseError::custom(
            SelectorParseErrorKind::UnsupportedPseudoClassOrElement,
        ))
    }

    fn parse_pseudo_element(
        &self,
        name: &str,
    ) -> Result<PseudoElement, SelectorParseError> {
        match_ignore_ascii_case! { name,
            "before" => return Ok(PseudoElement::Before),
            "after" => return Ok(PseudoElement::After),
            "marker" => return Ok(PseudoElement::Marker),
            "placeholder" => return Ok(PseudoElement::Placeholder),
            "details-content" => return Ok(PseudoElement::DetailsContent),
            _ => {}
        }
        Err(ParseError::custom(
            SelectorParseErrorKind::UnsupportedPseudoClassOrElement,
        ))
    }

    fn parse_functional_pseudo_element(
        &self,
        name: &str,
        parser: &mut CssParser<'i>,
    ) -> Result<PseudoElement, SelectorParseError> {
        match_ignore_ascii_case! { name,
            "highlight" => return Ok(PseudoElement::Highlight(parser.expect_ident()?.as_ref().to_owned())),
            _ => {}
        }
        Err(ParseError::custom(
            SelectorParseErrorKind::UnsupportedPseudoClassOrElement,
        ))
    }

    fn default_namespace(&self) -> Option<Atom> {
        if self.flags & 0x40 != 0 {
            Some(Atom("http://www.w3.org/1999/xhtml".into()))
        } else {
            None
        }
    }

    fn namespace_for_prefix(&self, prefix: &Atom) -> Option<Atom> {
        match &*prefix.0 {
            "svg" => Some(Atom("http://www.w3.org/2000/svg".into())),
            "html" => Some(Atom("http://www.w3.org/1999/xhtml".into())),
            "empty" => Some(Atom(String::new())),
            _ => None,
        }
    }
}

fn parse_list(p: &P, flags: u8, text: &str) -> Option<SelectorList<Impl>> {
    let relative = match flags & 3 {
        0 => ParseRelative::No,
        1 => ParseRelative::ForNesting,
        2 => ParseRelative::ForScope,
        _ => ParseRelative::ForHas,
    };
    let mut input = CssParser::new(text);
    let r = match (flags >> 2) & 3 {
        0 | 1 => SelectorList::parse(p, &mut input, relative),
        2 => SelectorList::parse_forgiving(p, &mut input, relative),
        _ => SelectorList::parse_disallow_pseudo(p, &mut input, relative),
    };
    r.ok()
}

fn inspect(list: &SelectorList<Impl>) -> usize {
    let mut n = 0usize;
    for sel in list.slice() {
        n = n
            .wrapping_add(sel.specificity() as usize)
            .wrapping_add(sel.len())
            .wrapping_add(sel.has_pseudo_element() as usize)
            .wrapping_add(sel.has_parent_selector() as usize)
            .wrapping_add(sel.is_universal() as usize);
        n = n.wrapping_add(sel.iter_raw_match_order().count());
        let mut it = sel.iter();
        loop {
            for c in &mut it {
                n = n.wrapping_add(c.is_combinator() as usize);
            }
            if it.next_sequence().is_none() {
                break;
            }
        }
    }
    n
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    let p = P { flags };
    let Some(list) = parse_list(&p, flags, text) else {
        return;
    };
    let mut n = inspect(&list);
    let css = list.to_css_string();

    // Re-parse the serialization (not asserted to be identical: e.g. forgiving
    // parsing and namespace handling legitimately change the text).
    if let Some(again) = parse_list(&p, flags, &css) {
        n = n.wrapping_add(inspect(&again));
        std::hint::black_box(again.to_css_string());
    }

    // CSS nesting: substitute `&` with a parent list, and nest the list in itself.
    if flags & 0x80 != 0 {
        let parent = parse_list(&P { flags: 0 }, 0, ".p > #q, svg|a:hover").unwrap();
        let nested = list.replace_parent_selector(&parent);
        n = n.wrapping_add(inspect(&nested));
        std::hint::black_box(nested.to_css_string());
        let nested = list.replace_parent_selector(&list);
        n = n.wrapping_add(inspect(&nested));
    }
    std::hint::black_box(n);
});
