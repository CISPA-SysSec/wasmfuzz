use wasmparser::ValType::I32;

use super::FuncSpec;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub(crate) enum Libfunc {
    Memcmp,
    Strncmp,
    Strncasecmp,
    Strcmp,
    Strcasecmp,
}

pub(crate) fn recognize_libfunc(func: &FuncSpec) -> Option<Libfunc> {
    let symbol = func._symbol.as_ref()?;
    if symbol == "memcmp" && *func.ty.params() == [I32, I32, I32] && *func.ty.results() == [I32] {
        return Some(Libfunc::Memcmp);
    }
    if symbol == "strncmp" && *func.ty.params() == [I32, I32, I32] && *func.ty.results() == [I32] {
        return Some(Libfunc::Strncmp);
    }
    if symbol == "strncasecmp"
        && *func.ty.params() == [I32, I32, I32]
        && *func.ty.results() == [I32]
    {
        return Some(Libfunc::Strncasecmp);
    }
    if symbol == "strcmp" && *func.ty.params() == [I32, I32] && *func.ty.results() == [I32] {
        return Some(Libfunc::Strcmp);
    }
    if symbol == "strcasecmp" && *func.ty.params() == [I32, I32] && *func.ty.results() == [I32] {
        return Some(Libfunc::Strcasecmp);
    }
    None
}
