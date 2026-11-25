use std::sync::OnceLock;
use timezone_provider::zoneinfo64::ZoneInfo64TzdbProvider;

/// V8 builds its temporal_rs provider from ICU4C's zoneinfo64.res
/// (v8/src/objects/js-temporal-zoneinfo64.cc). Use the copy bundled with the
/// zoneinfo64 crate.
pub fn provider() -> &'static ZoneInfo64TzdbProvider<'static> {
    static P: OnceLock<ZoneInfo64TzdbProvider<'static>> = OnceLock::new();
    P.get_or_init(|| {
        ZoneInfo64TzdbProvider::zoneinfo64_provider_for_testing().expect("zoneinfo64 data")
    })
}

/// Build the provider from a static constructor. wasmfuzz runs `_initialize` (and with it
/// `__wasm_call_ctors`) once per instance with its own fuel budget before the per-execution
/// instruction limit applies, so the zoneinfo64 setup no longer counts against every
/// execution (where it exceeded small instruction limits, and a trap resets the instance, so
/// the OnceLock never stayed initialised). On native targets this runs before main.
#[used]
#[link_section = ".init_array"]
static INIT_PROVIDER: extern "C" fn() = {
    extern "C" fn init_provider() {
        let _ = provider();
    }
    init_provider
};
