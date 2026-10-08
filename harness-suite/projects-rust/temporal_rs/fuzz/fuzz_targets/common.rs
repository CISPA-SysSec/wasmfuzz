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
