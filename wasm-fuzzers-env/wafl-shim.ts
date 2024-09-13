declare function malloc(x: i32): i32;
declare function LLVMFuzzerTestOneInput(x: i32, y: i32): i32;
declare function wasi_fd_read(fd: i32, iovs: i32, iovs_cnt: i32, read_ptr: i32): i32;
declare function _initialize(): void;
export function _start():void {
  _initialize();
  var buf_size = 32
  var buf_used = 0
  var iov = malloc(8);
  var buf = malloc(32)
  while (true) {
    store<i32>(iov, buf+buf_used, 0);
    store<i32>(iov, buf_size - buf_used, 4);
    wasi_fd_read(0, iov, 1, iov);
    var bytes_read = load<i32>(iov);
    var is_feof = bytes_read < buf_size - buf_used;
    buf_used += bytes_read;
    if (is_feof) {
      LLVMFuzzerTestOneInput(buf, buf_used);
      return;
    }
    var newbuf = malloc(buf_size+buf_size);
    for (var i: i32 = 0; i < buf_used; i++)
      store<u8>(newbuf+i, load<u8>(buf+i));
    buf = newbuf;
    buf_size += buf_size;
  }
}

