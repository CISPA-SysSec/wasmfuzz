use cranelift::codegen::ir::types::{I32, I64};
use cranelift::prelude::*;

use crate::concolic::SymValRef;

use super::signals::{TrapReason, raise_trap};
use super::{CompilationKind, FuncTranslator, vmcontext::VMContext};

// wasi_snapshot_preview1 errno values
const ERRNO_SUCCESS: u32 = 0;
const ERRNO_BADF: u32 = 8;
const ERRNO_EXIST: u32 = 20;
const ERRNO_INVAL: u32 = 28;
const ERRNO_ISDIR: u32 = 31;
const ERRNO_NOENT: u32 = 44;
const ERRNO_NOSPC: u32 = 51;
const ERRNO_NOTDIR: u32 = 54;

const OFLAGS_CREAT: u32 = 1 << 0;
const OFLAGS_DIRECTORY: u32 = 1 << 1;
const OFLAGS_EXCL: u32 = 1 << 2;
const OFLAGS_TRUNC: u32 = 1 << 3;

const FDFLAGS_APPEND: u32 = 1 << 0;

const RIGHTS_FD_READ: u64 = 1 << 1;
const RIGHTS_FD_SEEK: u64 = 1 << 2;
const RIGHTS_FD_WRITE: u64 = 1 << 6;

const FILETYPE_DIRECTORY: u8 = 3;
const FILETYPE_REGULAR_FILE: u8 = 4;

const PREOPEN_DIR_FD: u32 = 3;
const FIRST_FILE_FD: u32 = 4;

// Bound on the sum of all file sizes. Everything in a file was written from
// guest memory in the same execution, but a loop can write the same bytes
// over and over, so cap it like a tiny tmpfs. Beyond this, writes get ENOSPC.
const MEMFS_TOTAL_BYTES_LIMIT: usize = 8 << 20;

// Whether an `fd_write` to stdout/stderr is dropped, printed to the host's
// stderr (`STDOUTDEBUG=1`) or captured into the feedback context.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum StdoutMode {
    Ignore = 0,
    Debug = 1,
    Capture = 2,
}

struct MemFile {
    path: String,
    data: Vec<u8>,
    // Concolic shadow labels, one per byte of `data`. Empty unless concolic
    // tracing is active.
    shadow: Vec<SymValRef>,
    // Whether this file has been unlinked. Open fds keep working on the data,
    // but the path no longer resolves.
    unlinked: bool,
}

struct OpenFd {
    file: usize,
    cursor: u64,
    append: bool,
    readable: bool,
    writable: bool,
}

#[derive(Default)]
pub(crate) struct MemFs {
    files: Vec<MemFile>,
    fds: Vec<Option<OpenFd>>,
    total_bytes: usize,
}

impl MemFs {
    pub(crate) fn reset(&mut self) {
        self.files.clear();
        self.fds.clear();
        self.total_bytes = 0;
    }

    fn normalize(path: &[u8]) -> Option<String> {
        let path = std::str::from_utf8(path).ok()?;
        let mut parts = Vec::new();
        for comp in path.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    parts.pop()?;
                }
                c => parts.push(c),
            }
        }
        Some(parts.join("/"))
    }

    fn lookup(&self, path: &str) -> Option<usize> {
        self.files
            .iter()
            .position(|f| !f.unlinked && f.path == path)
    }

    fn fd(&self, fd: u32) -> Option<&OpenFd> {
        let idx = fd.checked_sub(FIRST_FILE_FD)? as usize;
        self.fds.get(idx)?.as_ref()
    }

    fn fd_mut(&mut self, fd: u32) -> Option<&mut OpenFd> {
        let idx = fd.checked_sub(FIRST_FILE_FD)? as usize;
        self.fds.get_mut(idx)?.as_mut()
    }

    fn alloc_fd(&mut self, ofd: OpenFd) -> u32 {
        if let Some(idx) = self.fds.iter().position(Option::is_none) {
            self.fds[idx] = Some(ofd);
            FIRST_FILE_FD + idx as u32
        } else {
            self.fds.push(Some(ofd));
            FIRST_FILE_FD + (self.fds.len() - 1) as u32
        }
    }

    pub(crate) fn open(
        &mut self,
        path: &[u8],
        oflags: u32,
        rights: u64,
        fdflags: u32,
    ) -> Result<u32, u32> {
        let path = Self::normalize(path).ok_or(ERRNO_INVAL)?;
        if oflags & OFLAGS_DIRECTORY != 0 {
            // Only the root directory exists. Opening it is only meaningful
            // for `fd_readdir`, which we don't support, so refuse.
            return Err(if path.is_empty() {
                ERRNO_ISDIR
            } else {
                ERRNO_NOTDIR
            });
        }
        if path.is_empty() {
            return Err(ERRNO_ISDIR);
        }
        let file = match self.lookup(&path) {
            Some(_) if oflags & OFLAGS_EXCL != 0 && oflags & OFLAGS_CREAT != 0 => {
                return Err(ERRNO_EXIST);
            }
            Some(idx) => {
                if oflags & OFLAGS_TRUNC != 0 {
                    let f = &mut self.files[idx];
                    self.total_bytes -= f.data.len();
                    f.data.clear();
                    f.shadow.clear();
                }
                idx
            }
            None if oflags & OFLAGS_CREAT != 0 => {
                self.files.push(MemFile {
                    path,
                    data: Vec::new(),
                    shadow: Vec::new(),
                    unlinked: false,
                });
                self.files.len() - 1
            }
            None => return Err(ERRNO_NOENT),
        };
        // wasi-libc requests exactly the rights it needs; a zero rights mask
        // (e.g. from a hand-rolled harness) is treated as read+write.
        let (readable, writable) = if rights & (RIGHTS_FD_READ | RIGHTS_FD_WRITE) == 0 {
            (true, true)
        } else {
            (rights & RIGHTS_FD_READ != 0, rights & RIGHTS_FD_WRITE != 0)
        };
        Ok(self.alloc_fd(OpenFd {
            file,
            cursor: 0,
            append: fdflags & FDFLAGS_APPEND != 0,
            readable,
            writable,
        }))
    }

    pub(crate) fn close(&mut self, fd: u32) -> Result<(), u32> {
        let idx = fd.checked_sub(FIRST_FILE_FD).ok_or(ERRNO_BADF)? as usize;
        match self.fds.get_mut(idx) {
            Some(slot @ Some(_)) => {
                *slot = None;
                Ok(())
            }
            _ => Err(ERRNO_BADF),
        }
    }

    pub(crate) fn unlink(&mut self, path: &[u8]) -> Result<(), u32> {
        let path = Self::normalize(path).ok_or(ERRNO_INVAL)?;
        let idx = self.lookup(&path).ok_or(ERRNO_NOENT)?;
        self.files[idx].unlinked = true;
        if !self.fds.iter().flatten().any(|f| f.file == idx) {
            self.total_bytes -= self.files[idx].data.len();
            self.files[idx].data = Vec::new();
            self.files[idx].shadow = Vec::new();
        }
        Ok(())
    }

    // Returns (file index, offset) for a write of `len` bytes on `fd`, grows
    // the file as needed and advances the cursor, or an errno.
    fn write_pos(&mut self, fd: u32, len: usize) -> Result<(usize, usize), u32> {
        let ofd = self.fd(fd).ok_or(ERRNO_BADF)?;
        if !ofd.writable {
            return Err(ERRNO_BADF);
        }
        let file = ofd.file;
        let file_len = self.files[file].data.len();
        let pos = if ofd.append {
            file_len
        } else {
            ofd.cursor as usize
        };
        let end = pos.checked_add(len).ok_or(ERRNO_INVAL)?;
        let growth = end.saturating_sub(file_len);
        if self.total_bytes + growth > MEMFS_TOTAL_BYTES_LIMIT {
            return Err(ERRNO_NOSPC);
        }
        let f = &mut self.files[file];
        if f.data.len() < end {
            f.data.resize(end, 0);
            if !f.shadow.is_empty() {
                f.shadow.resize(end, SymValRef::concrete());
            }
        }
        self.total_bytes += growth;
        self.fd_mut(fd).unwrap().cursor = end as u64;
        Ok((file, pos))
    }

    pub(crate) fn seek(&mut self, fd: u32, offset: i64, whence: u8) -> Result<u64, u32> {
        let file_len = {
            let ofd = self.fd(fd).ok_or(ERRNO_BADF)?;
            self.files[ofd.file].data.len() as i64
        };
        let ofd = self.fd_mut(fd).unwrap();
        let base = match whence {
            0 => 0,
            1 => ofd.cursor as i64,
            2 => file_len,
            _ => return Err(ERRNO_INVAL),
        };
        let new = base.checked_add(offset).ok_or(ERRNO_INVAL)?;
        if new < 0 {
            return Err(ERRNO_INVAL);
        }
        ofd.cursor = new as u64;
        Ok(ofd.cursor)
    }

    fn set_size(&mut self, fd: u32, size: u64) -> Result<(), u32> {
        let file = self.fd(fd).ok_or(ERRNO_BADF)?.file;
        let size = size as usize;
        let f = &mut self.files[file];
        let growth = size.saturating_sub(f.data.len());
        if self.total_bytes + growth > MEMFS_TOTAL_BYTES_LIMIT {
            return Err(ERRNO_NOSPC);
        }
        self.total_bytes = self.total_bytes + growth - f.data.len().saturating_sub(size);
        f.data.resize(size, 0);
        if !f.shadow.is_empty() {
            f.shadow.resize(size, SymValRef::concrete());
        }
        Ok(())
    }
}

fn heap_read(vmctx: &mut VMContext, ptr: u32, len: u32) -> Vec<u8> {
    match vmctx.heap_ref(ptr as usize, len as usize) {
        Some(buf) => buf.to_vec(),
        None => unsafe { raise_trap(TrapReason::MemoryOutOfBounds) },
    }
}

fn heap_write(vmctx: &mut VMContext, ptr: u32, data: &[u8]) {
    match vmctx.heap_mut(ptr as usize, data.len()) {
        Some(buf) => buf.copy_from_slice(data),
        None => unsafe { raise_trap(TrapReason::MemoryOutOfBounds) },
    }
}

fn write_u32(vmctx: &mut VMContext, ptr: u32, val: u32) {
    heap_write(vmctx, ptr, &val.to_le_bytes());
}

fn write_u64(vmctx: &mut VMContext, ptr: u32, val: u64) {
    heap_write(vmctx, ptr, &val.to_le_bytes());
}

fn read_u32(vmctx: &mut VMContext, ptr: u32) -> u32 {
    u32::from_le_bytes(heap_read(vmctx, ptr, 4).try_into().unwrap())
}

// Iterates `(buf, len)` pairs of a `__wasi_iovec_t` array.
fn read_iovs(vmctx: &mut VMContext, iovs: u32, iovs_len: u32) -> Vec<(u32, u32)> {
    (0..iovs_len)
        .map(|i| {
            let base = iovs.wrapping_add(i.wrapping_mul(8));
            (read_u32(vmctx, base), read_u32(vmctx, base.wrapping_add(4)))
        })
        .collect()
}

unsafe extern "C" fn builtin_wasi_fd_prestat_get(fd: u32, buf: u32, vmctx: *mut VMContext) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    if fd != PREOPEN_DIR_FD {
        return ERRNO_BADF;
    }
    // __wasi_prestat_t { u8 tag = PREOPENTYPE_DIR; u32 pr_name_len; }
    write_u32(vmctx, buf, 0);
    write_u32(vmctx, buf.wrapping_add(4), 1);
    ERRNO_SUCCESS
}

unsafe extern "C" fn builtin_wasi_fd_prestat_dir_name(
    fd: u32,
    path: u32,
    path_len: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    if fd != PREOPEN_DIR_FD {
        return ERRNO_BADF;
    }
    if path_len < 1 {
        return ERRNO_INVAL;
    }
    heap_write(vmctx, path, b"/");
    ERRNO_SUCCESS
}

unsafe extern "C" fn builtin_wasi_path_open(
    dirfd: u32,
    path: u32,
    path_len: u32,
    oflags: u32,
    rights_base: u64,
    fdflags: u32,
    fd_out: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(16 + path_len as u64);
    if dirfd != PREOPEN_DIR_FD {
        return ERRNO_BADF;
    }
    let path = heap_read(vmctx, path, path_len);
    match vmctx.memfs.open(&path, oflags, rights_base, fdflags) {
        Ok(fd) => {
            write_u32(vmctx, fd_out, fd);
            ERRNO_SUCCESS
        }
        Err(errno) => errno,
    }
}

unsafe extern "C" fn builtin_wasi_fd_close(fd: u32, vmctx: *mut VMContext) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    match vmctx.memfs.close(fd) {
        Ok(()) => ERRNO_SUCCESS,
        Err(e) => e,
    }
}

unsafe extern "C" fn builtin_wasi_fd_read(
    fd: u32,
    iovs: u32,
    iovs_len: u32,
    nread_out: u32,
    concolic: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(4 + iovs_len as u64);
    let (file, cursor, readable) = match vmctx.memfs.fd(fd) {
        Some(ofd) => (ofd.file, ofd.cursor as usize, ofd.readable),
        None => return ERRNO_BADF,
    };
    if !readable {
        return ERRNO_BADF;
    }
    let iovs = read_iovs(vmctx, iovs, iovs_len);
    let mut total = 0usize;
    for (buf, len) in iovs {
        let pos = cursor + total;
        let file_data = &vmctx.memfs.files[file].data;
        let avail = file_data.len().saturating_sub(pos).min(len as usize);
        if avail == 0 {
            break;
        }
        let chunk = file_data[pos..pos + avail].to_vec();
        vmctx.builtin_consume_fuel(avail as u64);
        heap_write(vmctx, buf, &chunk);
        if concolic != 0 {
            let shadow = &vmctx.memfs.files[file].shadow;
            if shadow.is_empty() {
                vmctx
                    .concolic
                    .memory_fill(buf, SymValRef::concrete(), avail as u32);
            } else {
                let labels = shadow[pos..pos + avail].to_vec();
                vmctx.concolic.heap_shadow_write(buf, &labels);
            }
        }
        total += avail;
        if avail < len as usize {
            break;
        }
    }
    vmctx.memfs.fd_mut(fd).unwrap().cursor = (cursor + total) as u64;
    write_u32(vmctx, nread_out, total as u32);
    ERRNO_SUCCESS
}

unsafe extern "C" fn builtin_wasi_fd_write(
    fd: u32,
    iovs: u32,
    iovs_len: u32,
    nwritten_out: u32,
    stdout_mode: u32,
    concolic: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(4 + iovs_len as u64);
    let iovs = read_iovs(vmctx, iovs, iovs_len);
    let mut total = 0u32;
    if fd == 1 || fd == 2 {
        for (buf, len) in iovs {
            vmctx.builtin_consume_fuel(len as u64);
            if stdout_mode != StdoutMode::Ignore as u32 {
                let chunk = heap_read(vmctx, buf, len);
                if !chunk.is_empty() {
                    if stdout_mode == StdoutMode::Debug as u32 {
                        eprintln!("[STDOUT] {:?}", String::from_utf8_lossy(&chunk));
                    } else {
                        vmctx.feedback.stdout.extend_from_slice(&chunk);
                    }
                }
            }
            total = total.wrapping_add(len);
        }
        write_u32(vmctx, nwritten_out, total);
        return ERRNO_SUCCESS;
    }
    if vmctx.memfs.fd(fd).is_none() {
        return ERRNO_BADF;
    }
    for (buf, len) in iovs {
        vmctx.builtin_consume_fuel(len as u64);
        let chunk = heap_read(vmctx, buf, len);
        let (file, pos) = match vmctx.memfs.write_pos(fd, chunk.len()) {
            Ok(x) => x,
            Err(e) => {
                if total == 0 {
                    return e;
                }
                break;
            }
        };
        vmctx.memfs.files[file].data[pos..pos + chunk.len()].copy_from_slice(&chunk);
        if concolic != 0 {
            let labels = vmctx.concolic.heap_shadow_read(buf, len);
            let f = &mut vmctx.memfs.files[file];
            if f.shadow.is_empty() && labels.iter().any(|l| !l.is_concrete()) {
                f.shadow.resize(f.data.len(), SymValRef::concrete());
            }
            if !f.shadow.is_empty() {
                f.shadow[pos..pos + chunk.len()].copy_from_slice(&labels);
            }
        }
        total = total.wrapping_add(len);
    }
    write_u32(vmctx, nwritten_out, total);
    ERRNO_SUCCESS
}

unsafe extern "C" fn builtin_wasi_fd_seek(
    fd: u32,
    offset: i64,
    whence: u32,
    newoffset_out: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    match vmctx.memfs.seek(fd, offset, whence as u8) {
        Ok(pos) => {
            write_u64(vmctx, newoffset_out, pos);
            ERRNO_SUCCESS
        }
        Err(e) => e,
    }
}

unsafe extern "C" fn builtin_wasi_fd_fdstat_get(fd: u32, buf: u32, vmctx: *mut VMContext) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    // __wasi_fdstat_t { u8 fs_filetype; u16 fs_flags; u64 fs_rights_base; u64 fs_rights_inheriting; }
    let (filetype, flags, rights) = if fd == PREOPEN_DIR_FD {
        (FILETYPE_DIRECTORY, 0u32, u64::MAX)
    } else if let Some(ofd) = vmctx.memfs.fd(fd) {
        let mut rights = RIGHTS_FD_SEEK;
        if ofd.readable {
            rights |= RIGHTS_FD_READ;
        }
        if ofd.writable {
            rights |= RIGHTS_FD_WRITE;
        }
        let flags = if ofd.append { FDFLAGS_APPEND } else { 0 };
        (FILETYPE_REGULAR_FILE, flags, rights)
    } else {
        // stdin/stdout/stderr: keep failing so isatty() stays false
        return ERRNO_BADF;
    };
    heap_write(
        vmctx,
        buf,
        &[filetype, 0, flags as u8, (flags >> 8) as u8, 0, 0, 0, 0],
    );
    write_u64(vmctx, buf.wrapping_add(8), rights);
    write_u64(vmctx, buf.wrapping_add(16), rights);
    ERRNO_SUCCESS
}

unsafe extern "C" fn builtin_wasi_fd_fdstat_set_flags(
    fd: u32,
    flags: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    match vmctx.memfs.fd_mut(fd) {
        Some(ofd) => {
            ofd.append = flags & FDFLAGS_APPEND != 0;
            ERRNO_SUCCESS
        }
        None if fd <= PREOPEN_DIR_FD => ERRNO_SUCCESS,
        None => ERRNO_BADF,
    }
}

fn write_filestat(vmctx: &mut VMContext, buf: u32, filetype: u8, size: u64) {
    // __wasi_filestat_t { u64 dev; u64 ino; u8 filetype; u64 nlink; u64 size; u64 atim; u64 mtim; u64 ctim; }
    let mut st = [0u8; 64];
    st[8..16].copy_from_slice(&1u64.to_le_bytes());
    st[16] = filetype;
    st[24..32].copy_from_slice(&1u64.to_le_bytes());
    st[32..40].copy_from_slice(&size.to_le_bytes());
    heap_write(vmctx, buf, &st);
}

unsafe extern "C" fn builtin_wasi_fd_filestat_get(fd: u32, buf: u32, vmctx: *mut VMContext) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1);
    if fd == PREOPEN_DIR_FD {
        write_filestat(vmctx, buf, FILETYPE_DIRECTORY, 0);
        return ERRNO_SUCCESS;
    }
    let Some(ofd) = vmctx.memfs.fd(fd) else {
        return ERRNO_BADF;
    };
    let size = vmctx.memfs.files[ofd.file].data.len() as u64;
    write_filestat(vmctx, buf, FILETYPE_REGULAR_FILE, size);
    ERRNO_SUCCESS
}

unsafe extern "C" fn builtin_wasi_fd_filestat_set_size(
    fd: u32,
    size: u64,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(1 + size / 64);
    match vmctx.memfs.set_size(fd, size) {
        Ok(()) => ERRNO_SUCCESS,
        Err(e) => e,
    }
}

unsafe extern "C" fn builtin_wasi_path_filestat_get(
    dirfd: u32,
    path: u32,
    path_len: u32,
    buf: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(4 + path_len as u64);
    if dirfd != PREOPEN_DIR_FD {
        return ERRNO_BADF;
    }
    let path = heap_read(vmctx, path, path_len);
    let Some(path) = MemFs::normalize(&path) else {
        return ERRNO_INVAL;
    };
    if path.is_empty() {
        write_filestat(vmctx, buf, FILETYPE_DIRECTORY, 0);
        return ERRNO_SUCCESS;
    }
    match vmctx.memfs.lookup(&path) {
        Some(idx) => {
            let size = vmctx.memfs.files[idx].data.len() as u64;
            write_filestat(vmctx, buf, FILETYPE_REGULAR_FILE, size);
            ERRNO_SUCCESS
        }
        None => ERRNO_NOENT,
    }
}

unsafe extern "C" fn builtin_wasi_path_unlink_file(
    dirfd: u32,
    path: u32,
    path_len: u32,
    vmctx: *mut VMContext,
) -> u32 {
    let vmctx = unsafe { &mut *vmctx };
    vmctx.builtin_consume_fuel(4 + path_len as u64);
    if dirfd != PREOPEN_DIR_FD {
        return ERRNO_BADF;
    }
    let path = heap_read(vmctx, path, path_len);
    match vmctx.memfs.unlink(&path) {
        Ok(()) => ERRNO_SUCCESS,
        Err(e) => e,
    }
}

impl FuncTranslator<'_, '_> {
    fn pop_args(&mut self, tys: &[Type], bcx: &mut FunctionBuilder) -> Vec<Value> {
        let mut vals: Vec<Value> = tys.iter().rev().map(|ty| self.pop1(*ty, bcx)).collect();
        vals.reverse();
        vals
    }

    fn push_errno(&mut self, errno: Value, bcx: &mut FunctionBuilder) {
        self.set_concolic_concrete(I32, errno, bcx);
        self.push1(I32, errno);
    }

    fn concolic_flag(&self, bcx: &mut FunctionBuilder) -> Value {
        bcx.ins().iconst(I32, self.options.is_concolic() as i64)
    }

    pub(crate) fn translate_wasi_fs(&mut self, name: &str, bcx: &mut FunctionBuilder) -> bool {
        match name {
            "fd_prestat_get" => {
                let [fd, buf] = self.pop_args(&[I32, I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_prestat_get as unsafe extern "C" fn(_, _, _) -> u32,
                    &[fd, buf],
                );
                self.push_errno(res, bcx);
            }
            "fd_prestat_dir_name" => {
                let [fd, path, path_len] = self.pop_args(&[I32, I32, I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_prestat_dir_name as unsafe extern "C" fn(_, _, _, _) -> u32,
                    &[fd, path, path_len],
                );
                self.push_errno(res, bcx);
            }
            "path_open" => {
                // (dirfd, dirflags, path, path_len, oflags, rights_base, rights_inheriting, fdflags, fd_out)
                let [
                    dirfd,
                    _dirflags,
                    path,
                    path_len,
                    oflags,
                    rights_base,
                    _rights_inh,
                    fdflags,
                    fd_out,
                ] = self.pop_args(&[I32, I32, I32, I32, I32, I64, I64, I32, I32], bcx)[..]
                else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_path_open as unsafe extern "C" fn(_, _, _, _, _, _, _, _) -> u32,
                    &[dirfd, path, path_len, oflags, rights_base, fdflags, fd_out],
                );
                self.push_errno(res, bcx);
            }
            "fd_close" => {
                let [fd] = self.pop_args(&[I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_close as unsafe extern "C" fn(_, _) -> u32,
                    &[fd],
                );
                self.push_errno(res, bcx);
            }
            "fd_read" => {
                let [fd, iovs, iovs_len, nread] = self.pop_args(&[I32, I32, I32, I32], bcx)[..]
                else {
                    unreachable!()
                };
                let concolic = self.concolic_flag(bcx);
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_read as unsafe extern "C" fn(_, _, _, _, _, _) -> u32,
                    &[fd, iovs, iovs_len, nread, concolic],
                );
                self.push_errno(res, bcx);
            }
            "fd_write" => {
                let [fd, iovs, iovs_len, nwritten] = self.pop_args(&[I32, I32, I32, I32], bcx)[..]
                else {
                    unreachable!()
                };
                let mode = match self.options.kind {
                    CompilationKind::Reusable => {
                        if std::env::var("STDOUTDEBUG").as_deref().unwrap_or("0") == "1" {
                            StdoutMode::Debug
                        } else {
                            StdoutMode::Ignore
                        }
                    }
                    CompilationKind::Tracing => {
                        if self.options.tracing.stdout {
                            StdoutMode::Capture
                        } else {
                            StdoutMode::Ignore
                        }
                    }
                };
                let mode = bcx.ins().iconst(I32, mode as u32 as i64);
                let concolic = self.concolic_flag(bcx);
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_write as unsafe extern "C" fn(_, _, _, _, _, _, _) -> u32,
                    &[fd, iovs, iovs_len, nwritten, mode, concolic],
                );
                self.push_errno(res, bcx);
            }
            "fd_seek" => {
                let [fd, offset, whence, newoffset] = self.pop_args(&[I32, I64, I32, I32], bcx)[..]
                else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_seek as unsafe extern "C" fn(_, _, _, _, _) -> u32,
                    &[fd, offset, whence, newoffset],
                );
                self.push_errno(res, bcx);
            }
            "fd_fdstat_get" => {
                let [fd, buf] = self.pop_args(&[I32, I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_fdstat_get as unsafe extern "C" fn(_, _, _) -> u32,
                    &[fd, buf],
                );
                self.push_errno(res, bcx);
            }
            "fd_fdstat_set_flags" => {
                let [fd, flags] = self.pop_args(&[I32, I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_fdstat_set_flags as unsafe extern "C" fn(_, _, _) -> u32,
                    &[fd, flags],
                );
                self.push_errno(res, bcx);
            }
            "fd_filestat_get" => {
                let [fd, buf] = self.pop_args(&[I32, I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_filestat_get as unsafe extern "C" fn(_, _, _) -> u32,
                    &[fd, buf],
                );
                self.push_errno(res, bcx);
            }
            "fd_filestat_set_size" => {
                let [fd, size] = self.pop_args(&[I32, I64], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_fd_filestat_set_size as unsafe extern "C" fn(_, _, _) -> u32,
                    &[fd, size],
                );
                self.push_errno(res, bcx);
            }
            "path_filestat_get" => {
                let [dirfd, _flags, path, path_len, buf] =
                    self.pop_args(&[I32, I32, I32, I32, I32], bcx)[..]
                else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_path_filestat_get as unsafe extern "C" fn(_, _, _, _, _) -> u32,
                    &[dirfd, path, path_len, buf],
                );
                self.push_errno(res, bcx);
            }
            "path_unlink_file" => {
                let [dirfd, path, path_len] = self.pop_args(&[I32, I32, I32], bcx)[..] else {
                    unreachable!()
                };
                let [res] = self.host_call(
                    bcx,
                    builtin_wasi_path_unlink_file as unsafe extern "C" fn(_, _, _, _) -> u32,
                    &[dirfd, path, path_len],
                );
                self.push_errno(res, bcx);
            }
            _ => return false,
        }
        true
    }
}
