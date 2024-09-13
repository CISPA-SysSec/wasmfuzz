// TODO(refactor): move somewhere, consolidate with coverage output code
use std::cell::RefCell;

use symbolic::{
    debuginfo::Object,
    symcache::{SourceLocations, SymCache, SymCacheConverter},
};

use super::ModuleSpec;

#[ouroboros::self_referencing]
struct OwnedSymCache {
    buf: Vec<u8>,
    #[borrows(buf)]
    #[not_covariant]
    symcache: SymCache<'this>,
}

thread_local! {
    pub static SYM_CACHE: RefCell<Option<Option<OwnedSymCache>>> = const { RefCell::new(None) };
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
    SYM_CACHE.with_borrow_mut(|f| {
        // f.take_if(|x| !Arc::ptr_eq(spec, &x.0));
        // if !f.as_mut().map_or(false, |x| Arc::ptr_eq(spec, &x.0)) {
        //     f.take();
        // }
        let symcache = f.get_or_insert_with(|| open_sym_cache(spec));
        symcache
            .as_mut()
            .map(|x| x.with_symcache(|symcache| func(symcache.lookup(addr))))
    })
}
