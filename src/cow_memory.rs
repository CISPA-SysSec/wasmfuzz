use std::io::{Read, Seek, SeekFrom};
use std::{ffi::c_void, fs::File, io::Write, ptr};

use rustix::ioctl;
use rustix::{
    fd::{FromRawFd, IntoRawFd},
    fs::MemfdFlags,
    mm::{MapFlags, MprotectFlags, ProtFlags},
};

/*
napkin math:
- .1us: 4k copy
- 5us: 128kb copy
- ~.5us syscall overhead
- ~15us for whole MADV_DONTNEED impl (256kb)
=> plain copy is fast-ish
=> dirty-restore-lkm should be faster than plain copy, but there's syscall overhead.

with userfaultfd / soft-dirty bit: keep dirty bit dirty, but don't touch pages that have never been touched?
=> saves at least a few (15 pages) with 64k input alloc and 2k size limit..

thresholds:
- dirty-restore-lkm at size >= 32kb?
- (MADV_DONTNEED at size >= 128kb?)

most pages for large allocations are never touched (!)
=> stack area is large by default
=> we allocate 64kb for input but only use around 4kb

MADV_DONTNEED doesn't scale well to many-core systems. Changing page tables requires shooting down TLB entries for all cores that may have cached the page table.
=> mitigate by pinning to cores explicitly? Is mm_cpumask ever cleared?
*/

// TODO: explicit dirty-page-logging / kernel module?
//       macOS support?
//       NT support?
pub trait ResettableMapping {
    fn accessible_size(&self) -> usize;
    fn mapping_size(&self) -> usize;

    // note: depending on the implementation, the slice might point to memory with
    // posterior guard pages of size mapping_size-accessible_size
    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];
    fn snapshot_as_mut_slice(&mut self) -> &mut [u8];

    fn snapshot(&mut self);
    fn restore(&mut self);
    // potential new pages are zeroed, accessible_size fit in mapping's size
    fn resize(&mut self, accessible_size: usize);

    fn count_modified_pages(&mut self, page_size: usize) -> usize {
        let mut res = 0;
        let mut page_ref = vec![0; page_size];
        for i in (0..self.accessible_size()).step_by(page_size) {
            page_ref.copy_from_slice(&self.snapshot_as_mut_slice()[i..i + page_size]);
            let page = &self.as_slice()[i..i + page_size];
            res += (page_ref == page) as usize;
        }
        res
    }
}

pub struct DummyMapping {
    mapping_size: usize,
    backing: Vec<u8>,
    reference: Vec<u8>,
}

impl DummyMapping {
    pub fn new(accessible_size: usize, mapping_size: usize) -> Self {
        Self {
            mapping_size,
            backing: vec![0; accessible_size],
            reference: vec![0; accessible_size],
        }
    }
}

impl ResettableMapping for DummyMapping {
    fn accessible_size(&self) -> usize {
        self.backing.len()
    }

    fn mapping_size(&self) -> usize {
        self.mapping_size
    }

    fn as_slice(&self) -> &[u8] {
        self.backing.as_slice()
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.backing.as_mut_slice()
    }

    fn snapshot_as_mut_slice(&mut self) -> &mut [u8] {
        self.reference.as_mut_slice()
    }

    fn snapshot(&mut self) {
        self.reference.clear();
        self.reference.extend_from_slice(&self.backing);
    }

    fn restore(&mut self) {
        self.backing.clear();
        self.backing.extend_from_slice(&self.reference);
    }

    fn resize(&mut self, accessible_size: usize) {
        assert!(accessible_size <= self.mapping_size);
        self.backing.resize(accessible_size, 0)
    }
}

pub struct CowResetMapping {
    pub memfd: File,
    accessible_size: usize,
    mapping_size: usize,
    ptr: *mut c_void,
    ref_ptr: *mut c_void,
}

impl CowResetMapping {
    pub fn new(accessible_size: usize, mapping_size: usize) -> Self {
        tracy_full::zone!("CowResetMapping::new");
        let page_size = rustix::param::page_size();
        assert!(accessible_size <= mapping_size);
        assert_eq!(mapping_size & (page_size - 1), 0);
        assert_eq!(accessible_size & (page_size - 1), 0);
        assert_ne!(mapping_size, 0);

        let memfd = rustix::fs::memfd_create("cow-mapping", MemfdFlags::empty()).unwrap();
        // Reserve the mappings
        let ptr = unsafe {
            rustix::mm::mmap(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
                &memfd,
                0,
            )
            .expect("failed to allocate mapping")
        };
        let ref_ptr = unsafe {
            rustix::mm::mmap(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::SHARED,
                &memfd,
                0,
            )
            .expect("failed to allocate mapping")
        };

        let memfd = unsafe { File::from_raw_fd(memfd.into_raw_fd()) };
        let mut res = Self {
            memfd,
            ptr,
            ref_ptr,
            accessible_size: 0,
            mapping_size,
        };
        if accessible_size != 0 {
            res.resize(accessible_size);
        }
        res
    }
}

impl Drop for CowResetMapping {
    fn drop(&mut self) {
        tracy_full::zone!("CowResetMapping::drop");
        unsafe { rustix::mm::munmap(self.ptr, self.mapping_size) }
            .expect("failed to deallocate mapping");
        unsafe { rustix::mm::munmap(self.ref_ptr, self.mapping_size) }
            .expect("failed to deallocate mapping");
    }
}

impl ResettableMapping for CowResetMapping {
    fn accessible_size(&self) -> usize {
        self.accessible_size
    }

    fn mapping_size(&self) -> usize {
        self.mapping_size
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.accessible_size) }
    }

    fn snapshot_as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ref_ptr.cast(), self.accessible_size) }
    }

    fn snapshot(&mut self) {
        tracy_full::zone!("CowResetMapping::snapshot");
        // NOTE: this is incredibly perfn't, but there doesn't seem to be an API to commit dirty pages only?
        // might need to use a second non-private mapping for the (persistent) writes?
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) };
        self.memfd.rewind().unwrap();
        self.memfd.write_all(slice).unwrap();
    }

    fn restore(&mut self) {
        // prefer straight memcpy for small-ish restores
        if self.accessible_size <= 128 << 10 {
            tracy_full::zone!("CowResetMapping::restore memcpy");
            unsafe { self.ptr.copy_from(self.ref_ptr, self.accessible_size) };
        } else {
            tracy_full::zone!("CowResetMapping::restore madvise");
            unsafe {
                rustix::mm::madvise(
                    self.ptr,
                    self.accessible_size,
                    rustix::mm::Advice::LinuxDontNeed,
                )
                .unwrap();
            }
        }
    }

    fn resize(&mut self, accessible_size: usize) {
        tracy_full::zone!("CowResetMapping::resize");
        // eprintln!("CowResetMapping::resize {} -> {} pages", self.accessible_size / 4096, accessible_size / 4096);
        assert!(accessible_size <= self.mapping_size);
        // Commit the accessible size.
        unsafe {
            rustix::mm::mprotect(
                self.ptr,
                accessible_size,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .expect("failed to make memory accessible");
        }
        unsafe {
            rustix::mm::mprotect(
                self.ref_ptr,
                accessible_size,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .expect("failed to make memory accessible");
        }
        self.memfd.set_len(accessible_size as u64).unwrap();
        self.accessible_size = accessible_size;
    }

    fn count_modified_pages(&mut self, page_size: usize) -> usize {
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) };
        let ref_slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ref_ptr.cast(), self.accessible_size) };
        slice
            .chunks(page_size)
            .zip(ref_slice.chunks(page_size))
            .filter(|(a, b)| a != b)
            .count()
    }
}

// Implements fast snapshot restore via soft-dirty PTE bits
// => https://www.kernel.org/doc/html/latest/admin-guide/mm/soft-dirty.html
// NOTE: This is not fast in practice unfortunately, as we're switching to the
// kernel for each page table dirty bit that we need to access.
pub struct CriuMapping {
    accessible_size: usize,
    mapping_size: usize,
    page_size: usize,
    ptr: *mut c_void,
    ref_ptr: *mut c_void,
}

use std::cell::RefCell;
thread_local! {
    static THREAD_HAS_CRIU_MAPPING: RefCell<bool> = const { RefCell::new(false) };
}

impl CriuMapping {
    pub fn new(accessible_size: usize, mapping_size: usize) -> Self {
        let page_size = rustix::param::page_size();
        assert!(accessible_size <= mapping_size);
        assert_eq!(mapping_size & (page_size - 1), 0);
        assert_eq!(accessible_size & (page_size - 1), 0);
        assert_ne!(mapping_size, 0);

        assert!(
            !THREAD_HAS_CRIU_MAPPING.replace(true),
            "can't have two CriuMapping's in a single thread"
        );

        // Reserve the mappings
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::SHARED,
            )
            .expect("failed to allocate mapping")
        };
        let ref_ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::SHARED,
            )
            .expect("failed to allocate mapping")
        };

        let mut res = Self {
            ptr,
            ref_ptr,
            page_size,
            accessible_size: 0,
            mapping_size,
        };
        if accessible_size != 0 {
            res.resize(accessible_size);
        }
        res.clear_soft_dirties();
        res
    }

    fn iter_dirty_page_offsets(&self) -> impl Iterator<Item = usize> + '_ {
        let mut f = File::open("/proc/self/pagemap").unwrap();
        // TODO: buffered / single read?
        (0..self.accessible_size)
            .step_by(self.page_size)
            .filter_map(move |offset| {
                let vpn = (self.ptr as usize + offset) / self.page_size;
                f.seek(SeekFrom::Start((vpn * 8) as u64)).unwrap();
                let mut buf = [0; 8];
                // load-bearing try operation: if the page is not available or
                // paged in, the read will fail
                f.read_exact(&mut buf).ok()?;
                let flags = u64::from_ne_bytes(buf);
                (((flags >> 55) & 1) != 0).then_some(offset)
            })
    }

    fn clear_soft_dirties(&self) {
        let mut f = File::options()
            .write(true)
            .open("/proc/self/clear_refs")
            .unwrap();
        f.write_all(b"4").unwrap();
    }

    // pub(crate) fn count_modified_pages(&self, page_size: usize) -> usize {
    //     let pages = self.iter_dirty_page_offsets().count();
    //     (pages * self.page_size) / page_size
    // }
}

impl Drop for CriuMapping {
    fn drop(&mut self) {
        unsafe {
            rustix::mm::munmap(self.ptr, self.mapping_size).expect("failed to deallocate mapping");
            rustix::mm::munmap(self.ref_ptr, self.mapping_size)
                .expect("failed to deallocate mapping");
        };
        THREAD_HAS_CRIU_MAPPING.set(false);
    }
}

impl ResettableMapping for CriuMapping {
    fn accessible_size(&self) -> usize {
        self.accessible_size
    }

    fn mapping_size(&self) -> usize {
        self.mapping_size
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.accessible_size) }
    }

    fn snapshot_as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ref_ptr.cast(), self.accessible_size) }
    }

    fn snapshot(&mut self) {
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) };
        let ref_slice =
            unsafe { std::slice::from_raw_parts_mut(self.ref_ptr.cast(), self.accessible_size) };
        for offset in self.iter_dirty_page_offsets() {
            ref_slice[offset..offset + self.page_size]
                .copy_from_slice(&slice[offset..offset + self.page_size]);
        }
        self.clear_soft_dirties()
    }

    fn restore(&mut self) {
        let slice: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.accessible_size) };
        let ref_slice =
            unsafe { std::slice::from_raw_parts(self.ref_ptr.cast(), self.accessible_size) };
        for offset in self.iter_dirty_page_offsets() {
            slice[offset..offset + self.page_size]
                .copy_from_slice(&ref_slice[offset..offset + self.page_size]);
        }
        self.clear_soft_dirties()
    }

    fn resize(&mut self, accessible_size: usize) {
        // eprintln!("CowResetMapping::resize {} -> {} pages", self.accessible_size / 4096, accessible_size / 4096);
        assert!(accessible_size <= self.mapping_size);
        // Commit the accessible size.
        unsafe {
            rustix::mm::mprotect(
                self.ptr,
                accessible_size,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .expect("failed to make memory accessible");
        }
        unsafe {
            rustix::mm::mprotect(
                self.ref_ptr,
                accessible_size,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .expect("failed to make memory accessible");
        }

        self.accessible_size = accessible_size;

        // Make sure the PTEs for each page exist.
        // let page_size = self.page_size;
        // let slice = self.as_mut_slice();
        // for offset in (0..accessible_size).step_by(page_size) {
        //     slice[offset] = std::hint::black_box(slice[offset]);
        // }
    }
}

// Restores each dirty page in-kernel using a small custom module
// (/dev/restore-dirty). This should be the fastest option, as it doesn't
// require any bigger page table updates or frequent context switches.
pub struct RestoreDirtyLKMMapping {
    dev_fd: File,
    accessible_size: usize,
    mapping_size: usize,
    ptr: *mut c_void,
    ref_ptr: *mut c_void,
    resize_ctr: usize,
}

impl RestoreDirtyLKMMapping {
    pub fn is_available() -> bool {
        std::path::Path::new("/dev/restore-dirty").exists()
    }
    pub fn new(accessible_size: usize, mapping_size: usize) -> Self {
        let page_size = rustix::param::page_size();
        assert!(accessible_size <= mapping_size);
        assert_eq!(mapping_size & (page_size - 1), 0);
        assert_eq!(accessible_size & (page_size - 1), 0);
        assert_ne!(mapping_size, 0);

        let dev_fd = File::open("/dev/restore-dirty").unwrap();
        // Reserve the mappings
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::SHARED,
            )
            .expect("failed to allocate mapping")
        };
        let ref_ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::SHARED,
            )
            .expect("failed to allocate mapping")
        };

        let mut res = Self {
            dev_fd,
            ptr,
            ref_ptr,
            accessible_size: 0,
            mapping_size,
            resize_ctr: 0,
        };
        if accessible_size != 0 {
            res.resize(accessible_size);
        }
        res
    }
}

impl Drop for RestoreDirtyLKMMapping {
    fn drop(&mut self) {
        unsafe {
            rustix::mm::munmap(self.ptr, self.mapping_size).expect("failed to deallocate mapping");
            rustix::mm::munmap(self.ref_ptr, self.mapping_size)
                .expect("failed to deallocate mapping");
        }
    }
}

impl ResettableMapping for RestoreDirtyLKMMapping {
    fn accessible_size(&self) -> usize {
        self.accessible_size
    }

    fn mapping_size(&self) -> usize {
        self.mapping_size
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.accessible_size) }
    }

    fn snapshot_as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ref_ptr.cast(), self.accessible_size) }
    }

    fn snapshot(&mut self) {
        // TODO: accelerate via lkm?
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) };
        let ref_slice =
            unsafe { std::slice::from_raw_parts_mut(self.ref_ptr.cast(), self.accessible_size) };
        ref_slice.copy_from_slice(slice)
    }

    fn restore(&mut self) {
        unsafe {
            let ctl = ioctl::NoArg::<{ ioctl::opcode::none(0xaa, 2) }>::new();
            ioctl::ioctl(&self.dev_fd, ctl).unwrap();
        }
    }

    fn resize(&mut self, mut accessible_size: usize) {
        if accessible_size <= self.accessible_size {
            return;
        }
        assert!(accessible_size <= self.mapping_size);
        // eprintln!("RestoreDirtyLKMMapping::resize {} -> {} pages", self.accessible_size / 4096, accessible_size / 4096);
        if self.resize_ctr > 10 {
            // eprintln!("RestoreDirtyLKMMapping::resize resize_ctr={} -> overprovisioning allocation size", self.resize_ctr);
            accessible_size = (accessible_size * 2).min(self.mapping_size);
            // eprintln!("RestoreDirtyLKMMapping::resize {} -> {} pages", self.accessible_size / 4096, accessible_size / 4096);
        }
        // Commit the accessible size.
        unsafe {
            rustix::mm::mprotect(
                self.ptr,
                accessible_size,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .expect("failed to make memory accessible");
        }
        unsafe {
            rustix::mm::mprotect(
                self.ref_ptr,
                accessible_size,
                MprotectFlags::READ | MprotectFlags::WRITE,
            )
            .expect("failed to make memory accessible");
        }
        self.accessible_size = accessible_size;

        self.resize_ctr += 1;

        unsafe {
            #[repr(C)]
            struct RestoreDirtyParams {
                target_mapping: usize,
                reference_mapping: usize,
                size: usize,
            }
            let ctl = ioctl::Setter::<
                { ioctl::opcode::read::<RestoreDirtyParams>(0xaa, 1) },
                RestoreDirtyParams,
            >::new(RestoreDirtyParams {
                target_mapping: self.ptr as _,
                reference_mapping: self.ref_ptr as _,
                size: self.accessible_size,
            });
            ioctl::ioctl(&self.dev_fd, ctl).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test(buf: &mut dyn ResettableMapping) {
        assert_eq!(
            buf.as_slice()[..16],
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"[..]
        );
        buf.as_mut_slice()[..16].copy_from_slice(b"YELLOW SUBMARINE");
        assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);
        buf.snapshot();

        for i in 0u32..7331 {
            buf.as_mut_slice()[7..16].copy_from_slice(b"RACECARS!");
            assert_eq!(buf.as_slice()[..16], b"YELLOW RACECARS!"[..]);
            buf.restore();
            // std::thread::yield_now();
            assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);
            if i.is_power_of_two() {
                println!("{i:#08x}: {i}");
            }
        }

        buf.restore();
        buf.resize(1 << 20);

        buf.as_mut_slice()[0x1000..0x1003].copy_from_slice(b"foo");
        buf.restore();
        assert_eq!(buf.as_slice()[0x1000..0x1003], b"\0\0\0"[..]);

        buf.as_mut_slice()[7..16].copy_from_slice(b"RACECARS!");
        assert_eq!(buf.as_slice()[..16], b"YELLOW RACECARS!"[..]);
        buf.restore();
        assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);
    }

    #[test]
    fn test_dummy() {
        test(&mut DummyMapping::new(1 << 16, 1 << 32));
    }

    #[test]
    fn test_cow_reset() {
        test(&mut CowResetMapping::new(1 << 16, 1 << 32));
    }

    #[test]
    fn test_criu_reset() {
        test(&mut CriuMapping::new(1 << 16, 1 << 32));
    }

    #[test]
    fn test_lkm_reset() {
        if !RestoreDirtyLKMMapping::is_available() {
            return;
        }
        test(&mut RestoreDirtyLKMMapping::new(1 << 16, 1 << 32));
    }

    #[test]
    fn test_cow_no_leak() {
        // make sure it doesn't leak memory
        for i in 0u32..42
        /*1337*/
        {
            let mut buf = CowResetMapping::new(((i + 1) as usize) << 16, 1 << 32);
            // dbg!(buf.as_slice().as_ptr());
            buf.as_mut_slice()[..16].copy_from_slice(b"YELLOW SUBMARINE");
            assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);
            buf.snapshot();
            buf.as_mut_slice()[7..16].copy_from_slice(b"RACECARS!");
            buf.restore();
            drop(buf);
        }
    }
}
