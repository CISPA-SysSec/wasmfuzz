use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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

    // Announce a write that the mapping's own tracking can't observe.
    //
    // Only `SoftwareDirtyMapping` tracks writes in software and therefore
    // cares: every write to the mapping that doesn't come from JIT-emitted
    // (and thus instrumented) code has to be reported here. For the
    // kernel-backed providers the hardware/kernel already saw the write and
    // this is a no-op.
    fn mark_dirty(&mut self, offset: usize, len: usize) {
        let _ = (offset, len);
    }

    // Declare the mapping identical to its reference, dropping the dirty set.
    // Only valid right after both sides have been written identically (the
    // memory-initializer paths do this).
    fn mark_clean(&mut self) {}

    // Base of the byte-per-page dirty map that JIT-emitted store
    // instrumentation writes into, or null if this provider tracks writes
    // itself and needs no help. The address is stable for the mapping's
    // lifetime, including across `resize`.
    fn dirty_map_ptr(&self) -> *mut u8 {
        ptr::null_mut()
    }

    fn count_modified_pages(&mut self, page_size: usize) -> usize {
        let mut res = 0;
        let mut page_ref = vec![0; page_size];
        for i in (0..self.accessible_size()).step_by(page_size) {
            page_ref.copy_from_slice(&self.snapshot_as_mut_slice()[i..i + page_size]);
            let page = &self.as_slice()[i..i + page_size];
            res += (page_ref != page) as usize;
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
        // the reference has to grow too: `restore` rebuilds `backing` from it,
        // so leaving it short would shrink the mapping back on the next restore
        self.backing.resize(accessible_size, 0);
        self.reference.resize(accessible_size, 0);
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
        /*eprintln!(
            "CowResetMapping::resize {} -> {}",
            humansize::format_size(self.accessible_size, humansize::DECIMAL),
            humansize::format_size(accessible_size, humansize::DECIMAL)
        );*/
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

// Tracks dirty pages via userfaultfd's async write-protect mode and queries
// them with the PAGEMAP_SCAN ioctl (both Linux 6.7+).
// => https://docs.kernel.org/admin-guide/mm/userfaultfd.html#async-writeprotect
//
// This is the "soft-dirty done right" variant of `CriuMapping`: instead of
// poking at /proc/self/pagemap once per page and clobbering the soft-dirty
// state of the whole process via /proc/self/clear_refs, we get all dirty
// ranges of our mapping with a single ioctl.
//
// Unlike regular userfaultfd-WP, async mode never sends a message to
// userspace: the write fault is resolved in-kernel by clearing the uffd-wp
// bit, which leaves a "has been written" mark behind for PAGEMAP_SCAN to
// pick up. No fault-handling thread is involved, and there's no roundtrip
// on the fuzzing target's write path.
pub struct UffdWpAsyncMapping {
    uffd: OwnedFd,
    pagemap: File,
    accessible_size: usize,
    mapping_size: usize,
    ptr: *mut c_void,
    ref_ptr: *mut c_void,
    // scratch space for the dirty range lists, kept around to avoid allocating
    dirty: Vec<PageRegion>,
    dirty_scratch: Vec<PageRegion>,
    opts: UffdWpAsyncOptions,
}

#[derive(Clone, Copy, Debug)]
pub struct UffdWpAsyncOptions {
    // Place uffd-wp markers on pages that have never been faulted in
    // (UFFD_FEATURE_WP_UNPOPULATED), so that they show up as clean.
    //
    // Turning this off means never-touched pages keep their empty page table
    // entries, so the idea was that the scan could skip them wholesale and
    // instead tell "never written" from PAGE_IS_PRESENT / PAGE_IS_SWAPPED /
    // PAGE_IS_PFNZERO. Measured: consistently *slower* (~1.5-2x per ioctl),
    // even for a fully unpopulated mapping. Kept around as an experiment.
    pub track_unpopulated: bool,
    // Re-arm write tracking with a second PAGEMAP_SCAN (PM_SCAN_WP_MATCHING)
    // instead of one UFFDIO_WRITEPROTECT ioctl per dirty range: constant
    // syscall count, but it walks the whole accessible range a second time.
    // Measured: slower than the per-range ioctls even with ~70 dirty ranges.
    pub rearm_via_scan: bool,
}

impl Default for UffdWpAsyncOptions {
    fn default() -> Self {
        Self {
            track_unpopulated: true,
            rearm_via_scan: false,
        }
    }
}

const UFFD_API: u64 = 0xAA;
const UFFD_FEATURE_WP_UNPOPULATED: u64 = 1 << 13;
const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;
const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1 << 0;
const UFFD_USER_MODE_ONLY: libc::c_int = 1;

const PAGE_IS_WRITTEN: u64 = 1 << 1;
const PAGE_IS_PRESENT: u64 = 1 << 3;
const PAGE_IS_SWAPPED: u64 = 1 << 4;
const PAGE_IS_PFNZERO: u64 = 1 << 5;
const PM_SCAN_WP_MATCHING: u64 = 1 << 0;
const PM_SCAN_CHECK_WPASYNC: u64 = 1 << 1;

const fn ioc_readwrite<T>(ty: u64, nr: u64) -> u64 {
    (3 << 30) | ((size_of::<T>() as u64) << 16) | (ty << 8) | nr
}

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}
#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}
#[repr(C)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}
#[repr(C)]
struct UffdioWriteprotect {
    range: UffdioRange,
    mode: u64,
}

#[repr(C)]
struct PmScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

#[derive(Clone, Copy, Default, Debug)]
#[repr(C)]
struct PageRegion {
    start: u64,
    end: u64,
    categories: u64,
}

impl UffdWpAsyncMapping {
    pub fn is_available() -> bool {
        static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *AVAILABLE.get_or_init(|| Self::self_test(Default::default()).is_ok())
    }

    // Note: this is a functional test on purpose. Whether the kernel supports
    // the required features is easy to probe, but whether we're allowed to use
    // them (vm.unprivileged_userfaultfd) and whether kernel-mode writes still
    // work (UFFD_USER_MODE_ONLY) is not.
    fn self_test(opts: UffdWpAsyncOptions) -> Result<(), String> {
        let page_size = rustix::param::page_size();
        let mut map = Self::try_new(4 * page_size, 4 * page_size, opts)?;
        map.as_mut_slice()[page_size] = 0x42;
        // sanity check: a kernel-mode write (via read(2)) must go through, too
        const MSG: &[u8] = b"kernel-mode write";
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(format!("pipe: {}", std::io::Error::last_os_error()));
        }
        let (rx, tx) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        let written =
            unsafe { libc::write(tx.as_raw_fd(), MSG.as_ptr().cast(), MSG.len()) as isize };
        let dst = map.as_mut_slice()[3 * page_size..].as_mut_ptr();
        let read = unsafe { libc::read(rx.as_raw_fd(), dst.cast(), MSG.len()) as isize };
        if written != MSG.len() as isize || read != MSG.len() as isize {
            return Err(format!(
                "kernel-mode write to write-protected page failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let mut dirty_ranges = Vec::new();
        map.scan_dirty_into(&mut dirty_ranges, false);
        let dirty = dirty_ranges
            .iter()
            .flat_map(|r| (r.start..r.end).step_by(page_size))
            .map(|addr| (addr as usize - map.ptr as usize) / page_size)
            .collect::<Vec<_>>();
        if dirty != [1, 3] {
            return Err(format!("unexpected dirty page set: {dirty:?}"));
        }
        map.restore();
        if map.as_slice().iter().any(|&x| x != 0) {
            return Err("restore didn't reset the mapping".to_string());
        }
        Ok(())
    }

    fn open_uffd(opts: &UffdWpAsyncOptions) -> Result<OwnedFd, String> {
        // UFFD_USER_MODE_ONLY lets us pass the vm.unprivileged_userfaultfd=0
        // check without CAP_SYS_PTRACE, but restricts fault handling to
        // user-mode faults. Prefer the unrestricted fd if we're allowed to.
        let mut last_err = None;
        for flags in [libc::O_CLOEXEC, libc::O_CLOEXEC | UFFD_USER_MODE_ONLY] {
            let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, flags) };
            if fd < 0 {
                last_err = Some(std::io::Error::last_os_error());
                continue;
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
            let mut features = UFFD_FEATURE_WP_ASYNC;
            if opts.track_unpopulated {
                features |= UFFD_FEATURE_WP_UNPOPULATED;
            }
            let mut api = UffdioApi {
                api: UFFD_API,
                features,
                ioctls: 0,
            };
            // note: _UFFDIO_API is 0x3f so that it doesn't clash with the
            // region ioctls (_UFFDIO_REGISTER is 0x00)
            const UFFDIO_API: u64 = ioc_readwrite::<UffdioApi>(0xAA, 0x3f);
            if unsafe { libc::ioctl(fd.as_raw_fd(), UFFDIO_API as _, &mut api) } != 0 {
                return Err(format!(
                    "UFFDIO_API (features={features:#x}) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            return Ok(fd);
        }
        Err(format!(
            "userfaultfd() failed: {}",
            last_err.expect("no error?")
        ))
    }

    pub fn new(accessible_size: usize, mapping_size: usize) -> Self {
        Self::new_with_options(accessible_size, mapping_size, Default::default())
    }

    pub fn new_with_options(
        accessible_size: usize,
        mapping_size: usize,
        opts: UffdWpAsyncOptions,
    ) -> Self {
        Self::try_new(accessible_size, mapping_size, opts)
            .expect("failed to set up UffdWpAsyncMapping")
    }

    fn try_new(
        accessible_size: usize,
        mapping_size: usize,
        opts: UffdWpAsyncOptions,
    ) -> Result<Self, String> {
        let page_size = rustix::param::page_size();
        assert!(accessible_size <= mapping_size);
        assert_eq!(mapping_size & (page_size - 1), 0);
        assert_eq!(accessible_size & (page_size - 1), 0);
        assert_ne!(mapping_size, 0);

        let uffd = Self::open_uffd(&opts)?;
        let pagemap = File::open("/proc/self/pagemap").map_err(|e| format!("pagemap: {e}"))?;

        // Reserve the mappings. Private anon is what WP_UNPOPULATED is for:
        // it makes never-faulted pages participate in write tracking.
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
            .expect("failed to allocate mapping")
        };
        let ref_ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
            .expect("failed to allocate mapping")
        };

        // Registration only marks the vma; it doesn't touch any page tables.
        let mut register = UffdioRegister {
            range: UffdioRange {
                start: ptr as u64,
                len: mapping_size as u64,
            },
            mode: UFFDIO_REGISTER_MODE_WP,
            ioctls: 0,
        };
        const UFFDIO_REGISTER: u64 = ioc_readwrite::<UffdioRegister>(0xAA, 0x00);
        if unsafe { libc::ioctl(uffd.as_raw_fd(), UFFDIO_REGISTER as _, &mut register) } != 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                rustix::mm::munmap(ptr, mapping_size).unwrap();
                rustix::mm::munmap(ref_ptr, mapping_size).unwrap();
            }
            return Err(format!("UFFDIO_REGISTER failed: {err}"));
        }

        let mut res = Self {
            uffd,
            pagemap,
            ptr,
            ref_ptr,
            accessible_size: 0,
            mapping_size,
            dirty: Vec::new(),
            dirty_scratch: Vec::new(),
            opts,
        };
        if accessible_size != 0 {
            res.resize(accessible_size);
        }
        Ok(res)
    }

    // (Re-)arm write tracking for the given range.
    fn write_protect(&self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let mut arg = UffdioWriteprotect {
            range: UffdioRange { start, len },
            mode: UFFDIO_WRITEPROTECT_MODE_WP,
        };
        const UFFDIO_WRITEPROTECT: u64 = ioc_readwrite::<UffdioWriteprotect>(0xAA, 0x06);
        let ret = unsafe { libc::ioctl(self.uffd.as_raw_fd(), UFFDIO_WRITEPROTECT as _, &mut arg) };
        assert_eq!(
            ret,
            0,
            "UFFDIO_WRITEPROTECT failed: {}",
            std::io::Error::last_os_error()
        );
    }

    // Collect the ranges that have been written to since they were last armed.
    // With `rearm`, the kernel re-arms the reported pages in the same ioctl.
    fn scan_dirty_into(&self, out: &mut Vec<PageRegion>, rearm: bool) {
        tracy_full::zone!("UffdWpAsyncMapping::scan_dirty");
        out.clear();
        let mut buf = [PageRegion::default(); 256];
        let end = self.ptr as u64 + self.accessible_size as u64;
        let mut start = self.ptr as u64;
        // Without markers on unpopulated pages, "not write-protected" isn't
        // enough to tell "written" from "never faulted in": ask for pages that
        // have a page frame of their own (or are swapped out) instead.
        let (category_mask, category_inverted, category_anyof_mask) = if self.opts.track_unpopulated
        {
            (PAGE_IS_WRITTEN, 0, 0)
        } else {
            (
                PAGE_IS_WRITTEN | PAGE_IS_PFNZERO,
                PAGE_IS_PFNZERO,
                PAGE_IS_PRESENT | PAGE_IS_SWAPPED,
            )
        };
        const PAGEMAP_SCAN: u64 = ioc_readwrite::<PmScanArg>(b'f' as u64, 16);
        while start < end {
            let mut arg = PmScanArg {
                size: size_of::<PmScanArg>() as u64,
                flags: PM_SCAN_CHECK_WPASYNC | if rearm { PM_SCAN_WP_MATCHING } else { 0 },
                start,
                end,
                walk_end: 0,
                vec: buf.as_mut_ptr() as u64,
                vec_len: buf.len() as u64,
                max_pages: 0,
                category_inverted,
                category_mask,
                category_anyof_mask,
                return_mask: PAGE_IS_WRITTEN,
            };
            let ret = unsafe { libc::ioctl(self.pagemap.as_raw_fd(), PAGEMAP_SCAN as _, &mut arg) };
            assert!(
                ret >= 0,
                "PAGEMAP_SCAN failed: {}",
                std::io::Error::last_os_error()
            );
            out.extend_from_slice(&buf[..ret as usize]);
            // the walk stops early when the output buffer is full
            if arg.walk_end <= start {
                break;
            }
            start = arg.walk_end;
        }
    }

    // Copies all dirty pages between the mapping and its reference copy and
    // re-arms write tracking for them.
    fn sync_dirty_pages(&mut self, to_reference: bool) {
        let mut dirty = std::mem::take(&mut self.dirty);
        self.scan_dirty_into(&mut dirty, self.opts.rearm_via_scan);
        for region in &dirty {
            let offset = region.start as usize - self.ptr as usize;
            let len = (region.end - region.start) as usize;
            debug_assert!(offset + len <= self.accessible_size);
            let (dst, src) = if to_reference {
                (self.ref_ptr, self.ptr)
            } else {
                (self.ptr, self.ref_ptr)
            };
            unsafe { dst.byte_add(offset).copy_from(src.byte_add(offset), len) };
        }
        // Note: re-arming has to happen after the copy, otherwise our own
        // writes would immediately dirty the pages again and the dirty set
        // could only ever grow.
        if self.opts.rearm_via_scan {
            let mut scratch = std::mem::take(&mut self.dirty_scratch);
            self.scan_dirty_into(&mut scratch, true);
            self.dirty_scratch = scratch;
        } else {
            for region in &dirty {
                self.write_protect(region.start, region.end - region.start);
            }
        }
        self.dirty = dirty;
    }
}

impl Drop for UffdWpAsyncMapping {
    fn drop(&mut self) {
        unsafe {
            rustix::mm::munmap(self.ptr, self.mapping_size).expect("failed to deallocate mapping");
            rustix::mm::munmap(self.ref_ptr, self.mapping_size)
                .expect("failed to deallocate mapping");
        }
    }
}

impl ResettableMapping for UffdWpAsyncMapping {
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
        tracy_full::zone!("UffdWpAsyncMapping::snapshot");
        self.sync_dirty_pages(true);
    }

    fn restore(&mut self) {
        tracy_full::zone!("UffdWpAsyncMapping::restore");
        self.sync_dirty_pages(false);
    }

    fn resize(&mut self, accessible_size: usize) {
        tracy_full::zone!("UffdWpAsyncMapping::resize");
        assert!(accessible_size <= self.mapping_size);
        if accessible_size <= self.accessible_size {
            return;
        }
        for ptr in [self.ptr, self.ref_ptr] {
            unsafe {
                rustix::mm::mprotect(
                    ptr,
                    accessible_size,
                    MprotectFlags::READ | MprotectFlags::WRITE,
                )
                .expect("failed to make memory accessible");
            }
        }
        // Arm the pages we just made accessible. This populates page tables
        // for the whole range (uffd-wp markers for not-yet-faulted pages), so
        // it's the one expensive operation here.
        let old_size = self.accessible_size;
        self.accessible_size = accessible_size;
        self.write_protect(
            self.ptr as u64 + old_size as u64,
            (accessible_size - old_size) as u64,
        );
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

// Tracks dirty pages in software instead of asking the kernel about them.
//
// Every mechanism that keeps the kernel in the loop pays for write tracking
// either with a fault on the first write to each page (uffd-wp, soft-dirty,
// mprotect+SIGSEGV) or with an O(accessible size) page table walk
// (`RestoreDirtyLKMMapping`). The hardware dirty bit is the only free write
// record on the machine, and no syscall exposes it -- that's the whole reason
// the LKM exists.
//
// But we compile the guest ourselves, so we can keep our own write record:
// every wasm store goes through `translate_store`, so the JIT can mark the
// touched page as part of the store. That makes the mark as cheap as the
// hardware dirty bit (a couple of always-hit-in-L1 instructions) while leaving
// restore a plain userspace memcpy over an exact dirty set -- no page table
// updates, no TLB shootdowns, no syscalls at all.
//
// The catch is that the write record is only as complete as the
// instrumentation: any write that doesn't come from JIT-emitted code (host
// writes from builtins, the input copy, memory initializers) has to call
// `mark_dirty` explicitly.
pub struct SoftwareDirtyMapping {
    accessible_size: usize,
    mapping_size: usize,
    page_shift: u32,
    ptr: *mut c_void,
    ref_ptr: *mut c_void,
    // one byte per page: 1 if the page may differ from the reference
    seen: Vec<u8>,
    // page indices with `seen[idx] == 1`, only maintained in `Log` mode
    log: Vec<u32>,
    mode: DirtyTrackMode,
    // verify on every restore that no page differs from the reference without
    // having been marked, i.e. that the instrumentation isn't missing a write
    paranoid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirtyTrackMode {
    // Branch-free mark (`seen[page] = 1`), restore scans the byte map.
    // Cheapest possible store instrumentation, but restore is
    // O(accessible size / page size) even when nothing was written.
    Bitmap,
    // Mark appends the page to a log the first time it's written. Restore is
    // O(dirty pages), but the mark carries a branch. The branch is very well
    // predicted (not-taken for every store after the first to a page), so this
    // mostly costs a compare and a rarely-taken side path.
    Log,
}

impl SoftwareDirtyMapping {
    pub fn new(accessible_size: usize, mapping_size: usize) -> Self {
        Self::new_with_mode(accessible_size, mapping_size, DirtyTrackMode::Log)
    }

    pub fn new_with_mode(
        accessible_size: usize,
        mapping_size: usize,
        mode: DirtyTrackMode,
    ) -> Self {
        let page_size = rustix::param::page_size();
        assert!(accessible_size <= mapping_size);
        assert_eq!(mapping_size & (page_size - 1), 0);
        assert_eq!(accessible_size & (page_size - 1), 0);
        assert_ne!(mapping_size, 0);

        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
            .expect("failed to allocate mapping")
        };
        let ref_ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                mapping_size,
                ProtFlags::empty(),
                MapFlags::PRIVATE,
            )
            .expect("failed to allocate mapping")
        };

        // Sized for the whole reservation so that the base address stays put:
        // the JIT bakes it into the store instrumentation. It's virtual
        // address space (one byte per page of a 8 GiB reservation is 2 MiB),
        // and only the pages we actually mark get faulted in.
        let max_pages = mapping_size >> page_size.trailing_zeros();
        let mut res = Self {
            ptr,
            ref_ptr,
            page_shift: page_size.trailing_zeros(),
            seen: vec![0u8; max_pages],
            log: Vec::with_capacity(1024),
            accessible_size: 0,
            mapping_size,
            mode,
            paranoid: false,
        };
        if accessible_size != 0 {
            res.resize(accessible_size);
        }
        res
    }

    pub fn page_shift(&self) -> u32 {
        self.page_shift
    }

    pub fn mode(&self) -> DirtyTrackMode {
        self.mode
    }

    // Turn on the missing-instrumentation check. Makes every restore O(size)
    // with a full comparison, so it's a debugging aid, not a mode to fuzz in.
    pub fn set_paranoid(&mut self, paranoid: bool) {
        self.paranoid = paranoid;
    }

    // Panics if any page differs from the reference without being marked --
    // i.e. if some write to guest memory bypassed the instrumentation. That's
    // the failure mode software tracking has and the kernel-backed providers
    // don't, and it otherwise shows up only as fuzzing nondeterminism.
    fn check_no_unmarked_writes(&self) {
        let page_size = 1usize << self.page_shift;
        let slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.accessible_size) };
        let ref_slice: &[u8] =
            unsafe { std::slice::from_raw_parts(self.ref_ptr.cast(), self.accessible_size) };
        for (page, (a, b)) in slice
            .chunks(page_size)
            .zip(ref_slice.chunks(page_size))
            .enumerate()
        {
            if a != b && self.seen[page] == 0 {
                let off = a.iter().zip(b).position(|(x, y)| x != y).unwrap();
                panic!(
                    "unmarked write to guest page {page} (offset {:#x}): {:#04x} != {:#04x}. \
                     some write to the heap is missing a mark_dirty call",
                    (page << self.page_shift) + off,
                    a[off],
                    b[off],
                );
            }
        }
    }

    // Copies every page marked dirty and clears the marks.
    fn sync_dirty_pages(&mut self, to_reference: bool) {
        let (dst, src) = if to_reference {
            (self.ref_ptr, self.ptr)
        } else {
            (self.ptr, self.ref_ptr)
        };
        let page_shift = self.page_shift;
        let page_size = 1usize << page_shift;
        let accessible_size = self.accessible_size;
        let copy_page = |page: usize| {
            let offset = page << page_shift;
            debug_assert!(offset + page_size <= accessible_size);
            unsafe {
                ptr::copy_nonoverlapping(
                    src.byte_add(offset).cast::<u8>(),
                    dst.byte_add(offset).cast::<u8>(),
                    page_size,
                )
            };
        };

        match self.mode {
            DirtyTrackMode::Log => {
                for &page in &self.log {
                    copy_page(page as usize);
                    self.seen[page as usize] = 0;
                }
                self.log.clear();
            }
            DirtyTrackMode::Bitmap => {
                // Scan a word at a time: the dirty map is tiny (one byte per
                // page) and almost always sparse, so this is a handful of
                // loads per restore rather than a page table walk.
                let pages = self.accessible_size >> self.page_shift;
                let (prefix, words, suffix) = unsafe { self.seen[..pages].align_to_mut::<u64>() };
                let mut page = 0;
                for byte in prefix.iter_mut() {
                    if *byte != 0 {
                        copy_page(page);
                        *byte = 0;
                    }
                    page += 1;
                }
                for word in words.iter_mut() {
                    if *word != 0 {
                        for i in 0..8 {
                            if (*word >> (i * 8)) as u8 != 0 {
                                copy_page(page + i);
                            }
                        }
                        *word = 0;
                    }
                    page += 8;
                }
                for byte in suffix.iter_mut() {
                    if *byte != 0 {
                        copy_page(page);
                        *byte = 0;
                    }
                    page += 1;
                }
            }
        }
    }
}

impl Drop for SoftwareDirtyMapping {
    fn drop(&mut self) {
        unsafe {
            rustix::mm::munmap(self.ptr, self.mapping_size).expect("failed to deallocate mapping");
            rustix::mm::munmap(self.ref_ptr, self.mapping_size)
                .expect("failed to deallocate mapping");
        }
    }
}

impl ResettableMapping for SoftwareDirtyMapping {
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

    fn mark_dirty(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        debug_assert!(offset + len <= self.accessible_size);
        let first = offset >> self.page_shift;
        let last = (offset + len - 1) >> self.page_shift;
        for page in first..=last {
            match self.mode {
                DirtyTrackMode::Bitmap => self.seen[page] = 1,
                DirtyTrackMode::Log => {
                    if self.seen[page] == 0 {
                        self.seen[page] = 1;
                        self.log.push(page as u32);
                    }
                }
            }
        }
    }

    fn mark_clean(&mut self) {
        for &page in &self.log {
            self.seen[page as usize] = 0;
        }
        self.log.clear();
        if self.mode == DirtyTrackMode::Bitmap {
            self.seen[..self.accessible_size >> self.page_shift].fill(0);
        }
    }

    fn dirty_map_ptr(&self) -> *mut u8 {
        self.seen.as_ptr() as *mut u8
    }

    fn snapshot(&mut self) {
        tracy_full::zone!("SoftwareDirtyMapping::snapshot");
        if self.paranoid {
            self.check_no_unmarked_writes();
        }
        self.sync_dirty_pages(true);
    }

    fn restore(&mut self) {
        tracy_full::zone!("SoftwareDirtyMapping::restore");
        if self.paranoid {
            self.check_no_unmarked_writes();
        }
        self.sync_dirty_pages(false);
    }

    fn resize(&mut self, accessible_size: usize) {
        tracy_full::zone!("SoftwareDirtyMapping::resize");
        assert!(accessible_size <= self.mapping_size);
        if accessible_size <= self.accessible_size {
            return;
        }
        // Newly accessible pages are zero in both mappings, so they start
        // clean and don't need to be marked.
        for ptr in [self.ptr, self.ref_ptr] {
            unsafe {
                rustix::mm::mprotect(
                    ptr,
                    accessible_size,
                    MprotectFlags::READ | MprotectFlags::WRITE,
                )
                .expect("failed to make memory accessible");
            }
        }
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
    fn test_uffd_wp_async_reset() {
        if !UffdWpAsyncMapping::is_available() {
            eprintln!(
                "skipping: {:?}",
                UffdWpAsyncMapping::self_test(Default::default())
            );
            return;
        }
        for opts in [
            UffdWpAsyncOptions::default(),
            UffdWpAsyncOptions {
                rearm_via_scan: true,
                ..Default::default()
            },
            UffdWpAsyncOptions {
                track_unpopulated: false,
                ..Default::default()
            },
            UffdWpAsyncOptions {
                track_unpopulated: false,
                rearm_via_scan: true,
            },
        ] {
            println!("testing {opts:?}");
            UffdWpAsyncMapping::self_test(opts).expect("self test failed");
            test(&mut UffdWpAsyncMapping::new_with_options(
                1 << 16,
                1 << 32,
                opts,
            ));
        }
    }

    #[test]
    fn test_lkm_reset() {
        if !RestoreDirtyLKMMapping::is_available() {
            return;
        }
        test(&mut RestoreDirtyLKMMapping::new(1 << 16, 1 << 32));
    }

    // Same as `test`, but every write is announced via `mark_dirty` -- the
    // software-tracked mapping can't see them otherwise. This mirrors what the
    // JIT would emit for each store.
    fn test_tracked(buf: &mut dyn ResettableMapping) {
        fn write(buf: &mut dyn ResettableMapping, offset: usize, data: &[u8]) {
            buf.as_mut_slice()[offset..offset + data.len()].copy_from_slice(data);
            buf.mark_dirty(offset, data.len());
        }

        assert_eq!(buf.as_slice()[..16], [0; 16][..]);
        write(buf, 0, b"YELLOW SUBMARINE");
        assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);
        buf.snapshot();

        for _ in 0u32..1337 {
            write(buf, 7, b"RACECARS!");
            assert_eq!(buf.as_slice()[..16], b"YELLOW RACECARS!"[..]);
            buf.restore();
            assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);
        }

        buf.restore();
        buf.resize(1 << 20);

        // a write spanning a page boundary has to dirty both pages
        write(buf, 0x1000 - 2, b"foobar");
        buf.restore();
        assert_eq!(buf.as_slice()[0x1000 - 2..0x1000 + 4], [0; 6][..]);

        // ...and so does a write to freshly resized-in space
        write(buf, (1 << 20) - 4, b"tail");
        buf.restore();
        assert_eq!(buf.as_slice()[(1 << 20) - 4..], [0; 4][..]);

        write(buf, 7, b"RACECARS!");
        assert_eq!(buf.as_slice()[..16], b"YELLOW RACECARS!"[..]);
        buf.restore();
        assert_eq!(buf.as_slice()[..16], b"YELLOW SUBMARINE"[..]);

        // snapshot has to pick up dirty pages and clear the dirty set, so that
        // a later restore doesn't roll back past it
        write(buf, 0x2000, b"committed");
        buf.snapshot();
        write(buf, 0x2000, b"scribbled");
        buf.restore();
        assert_eq!(buf.as_slice()[0x2000..0x2000 + 9], b"committed"[..]);
    }

    #[test]
    fn test_software_dirty_reset() {
        for mode in [DirtyTrackMode::Log, DirtyTrackMode::Bitmap] {
            println!("testing {mode:?}");
            test_tracked(&mut SoftwareDirtyMapping::new_with_mode(
                1 << 16,
                1 << 32,
                mode,
            ));
        }
    }

    // The kernel-backed providers observe writes on their own, so they have to
    // pass the tracked test too (`mark_dirty` is a no-op for them).
    #[test]
    fn test_tracked_agrees_with_kernel_providers() {
        test_tracked(&mut DummyMapping::new(1 << 16, 1 << 32));
        test_tracked(&mut CowResetMapping::new(1 << 16, 1 << 32));
        if RestoreDirtyLKMMapping::is_available() {
            test_tracked(&mut RestoreDirtyLKMMapping::new(1 << 16, 1 << 32));
        }
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
