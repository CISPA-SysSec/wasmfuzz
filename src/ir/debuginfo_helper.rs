// TODO(refactor): move somewhere, consolidate with coverage output code
use std::cell::RefCell;

use symbolic::{
    debuginfo::Object,
    symcache::{SourceLocations, SymCache, SymCacheConverter},
};

use super::{ModuleSpec, parse::ModuleId};
use crate::HashMap;

#[ouroboros::self_referencing]
struct OwnedSymCache {
    buf: Vec<u8>,
    #[borrows(buf)]
    #[not_covariant]
    symcache: SymCache<'this>,
}

thread_local! {
    // Keyed by module: a thread can be handed several `ModuleSpec`s (a report
    // covering more than one harness, say), and a cache that only remembers the
    // one it was first asked about would answer for the wrong binary.
    // `None` means "this module has no usable debug info", which is worth
    // remembering too -- building the symcache isn't cheap.
    static SYM_CACHES: RefCell<HashMap<ModuleId, Option<OwnedSymCache>>> =
        RefCell::new(HashMap::default());
}

fn open_sym_cache(spec: &ModuleSpec) -> Option<OwnedSymCache> {
    // let view: ByteView<'static> = ByteView::from_vec(spec.wasm_binary.clone());
    let Ok(object) = Object::parse(&spec.wasm_binary) else {
        return None;
    };
    if !object.has_debug_info() {
        return None;
    }

    let mut conv = SymCacheConverter::new();
    conv.process_object(&object).unwrap();
    let mut buf = Vec::new();
    conv.serialize(&mut buf).unwrap();

    Some(
        OwnedSymCacheBuilder {
            buf,
            symcache_builder: |buf: &Vec<u8>| SymCache::parse(buf).unwrap(),
        }
        .build(),
    )
}

pub(crate) fn resolve_source_location<R, F: FnOnce(SourceLocations) -> R>(
    spec: &ModuleSpec,
    addr: u64,
    func: F,
) -> Option<R> {
    SYM_CACHES.with_borrow_mut(|caches| {
        let symcache = caches
            .entry(spec.id)
            .or_insert_with(|| open_sym_cache(spec));
        symcache
            .as_mut()
            .map(|x| x.with_symcache(|symcache| func(symcache.lookup(addr))))
    })
}
