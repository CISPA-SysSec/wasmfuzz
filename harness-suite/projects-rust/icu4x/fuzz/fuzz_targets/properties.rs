// Unicode property lookup by name, as done for RegExp `\p{...}` escapes
// (SpiderMonkey js/src/irregexp/properties_glue: CodePointSetData::new_for_ecma262
// plus case closure via icu_casemap for /iu and /iv regexps).
//
// Input: [flags: u8] "name" | "name=value"
#![no_main]
use icu_casemap::CaseMapper;
use icu_collections::codepointinvlist::CodePointInversionListBuilder;
use icu_properties::props::{GeneralCategory, GeneralCategoryGroup, Script};
use icu_properties::{
    CodePointMapData, CodePointSetData, CodePointSetDataBorrowed, PropertyNamesLong,
    PropertyNamesShort, PropertyParser,
};
use libfuzzer_sys::fuzz_target;

const MAX_CLOSURE_CHARS: u32 = 4096;

fn emit(set: CodePointSetDataBorrowed<'static>, negate: bool, fold: bool) {
    if fold {
        let mut builder = CodePointInversionListBuilder::new();
        let mapper = CaseMapper::new();
        let mut budget = MAX_CLOSURE_CHARS;
        for range in set.iter_ranges() {
            builder.add_range32(range.clone());
            for u in range {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                if let Some(c) = char::from_u32(u) {
                    mapper.add_case_closure_to(c, &mut builder);
                }
            }
        }
        if negate {
            builder.complement();
        }
        let list = builder.build();
        let _ = list.size();
    } else if negate {
        let _ = set.iter_ranges_complemented().count();
    } else {
        let _ = set.iter_ranges().count();
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&flags, input)) = data.split_first() else { return };
    let negate = flags & 1 != 0;
    let fold = flags & 2 != 0;
    let loose = flags & 4 != 0;

    if let Some(eq) = input.iter().position(|b| *b == b'=') {
        let (name, value) = (&input[..eq], &input[eq + 1..]);
        match name {
            b"General_Category" | b"gc" => {
                let p = PropertyParser::<GeneralCategoryGroup>::new();
                let v = if loose { p.get_loose_utf8(value) } else { p.get_strict_utf8(value) };
                if let Some(g) = v {
                    let map = CodePointMapData::<GeneralCategory>::new();
                    let _ = map.iter_ranges_for_group(g).count();
                }
                let p = PropertyParser::<GeneralCategory>::new();
                if let Some(gc) = p.get_strict_utf8(value) {
                    assert!(PropertyNamesLong::<GeneralCategory>::new().get(gc).is_some());
                    let _ = PropertyNamesShort::<GeneralCategory>::new().get(gc);
                }
            }
            b"Script" | b"sc" | b"Script_Extensions" | b"scx" => {
                let p = PropertyParser::<Script>::new();
                let v = if loose { p.get_loose_utf8(value) } else { p.get_strict_utf8(value) };
                if let Some(sc) = v {
                    let _ = PropertyNamesLong::<Script>::new().get(sc);
                    let _ = PropertyNamesShort::<Script>::new().get(sc);
                    let map = CodePointMapData::<Script>::new();
                    let _ = map.iter_ranges_for_value(sc).count();
                    let scx = icu_properties::script::ScriptWithExtensions::new();
                    let _ = scx.get_script_extensions_ranges(sc).count();
                }
            }
            _ => {}
        }
        return;
    }

    if let Some(set) = CodePointSetData::new_for_ecma262(input) {
        emit(set, negate, fold);
    }
    // Lone General_Category values are also valid `\p{Lu}` escapes.
    let p = PropertyParser::<GeneralCategoryGroup>::new();
    if let Some(g) = p.get_strict_utf8(input) {
        let map = CodePointMapData::<GeneralCategory>::new();
        let _ = map.iter_ranges_for_group(g).count();
    }
});
