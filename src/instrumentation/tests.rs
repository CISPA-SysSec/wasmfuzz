use super::*;
use feedback_lattice::ValueRange;

#[test]
fn dirty_scan_matches_full_scan() {
    // Empty arrays, partial/full chunks and partial/full 32-byte dirty blocks.
    for len in [0, 1, 63, 64, 65, 2047, 2048, 2049, 4097] {
        let keys: Vec<_> = (0..len).collect();
        let mut array = AssociatedCoverageArray::<_, ValueRange>::new(&keys);
        let mut saved = vec![ValueRange::bottom(); len];
        for round in 0..100 {
            if round % 17 == 0 {
                array.reset();
                saved.fill(ValueRange::bottom());
            } else if round % 3 == 0 {
                array.reset_keep_saved();
            }
            for write in 0..7 {
                if len == 0 {
                    break;
                }
                let index = (round * 67 + write * 31) % len;
                array.entries[index] = array.entries[index].unify(&ValueRange {
                    low: round as u64,
                    high: round as u64,
                });
                array.dirty[index / DIRTY_CHUNK] = 1;
            }
            let mut novel = false;
            for (entry, old) in array.entries.iter().zip(&mut saved) {
                novel |= old.is_extended_by(entry);
                *old = old.unify(entry);
            }
            assert_eq!(array.update_and_scan(), novel, "len={len}, round={round}");
            assert_eq!(&*array.saved, saved);
            assert!(array.dirty.iter().all(|&byte| byte == 0));
            assert!(!array.update_and_scan());
        }
    }
}

#[test]
fn reset_discards_pending_dirty_entries() {
    let mut array = AssociatedCoverageArray::<_, bool>::new(&[0]);
    array.entries[0] = true;
    array.dirty[0] = 1;
    array.reset_keep_saved();
    assert!(!array.update_and_scan());
    assert!(!array.saved_val(&0));
    array.entries[0] = true;
    array.dirty[0] = 1;
    assert!(array.update_and_scan());
    array.reset_keep_saved();
    assert!(array.saved_val(&0));
    array.reset();
    assert!(!array.saved_val(&0));
    assert!(!array.update_and_scan());
}

#[test]
fn slot_and_dirty_pointers_follow_sorted_keys() {
    let keys: Vec<_> = (0..130).rev().collect();
    let array = AssociatedCoverageArray::<_, bool>::new(&keys);
    assert_eq!(array.keys.len(), 130);
    for index in [0, 63, 64, 127, 128, 129] {
        let (slot, dirty) = array.val_ptr(&index).unwrap();
        assert_eq!(slot, &array.entries[index] as *const _);
        assert_eq!(dirty, &array.dirty[index / DIRTY_CHUNK] as *const _);
    }
    assert!(array.val_ptr(&130).is_none());
}
