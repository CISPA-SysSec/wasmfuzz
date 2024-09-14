#!/usr/bin/env bash
set -e
inp_file=$1
out_file=${2:-"$inp_file-wafl.wasm"}
wat_file="$out_file.wat"

wasm2wat $inp_file > $wat_file
if ! grep -q "__imported_wasi_snapshot_preview1_fd_read" $wat_file; then
    sed -i -e "/(module/a (import \"wasi_snapshot_preview1\" \"fd_read\" (func \$__imported_wasi_snapshot_preview1_fd_read (param i32 i32 i32 i32) (result i32)))" \
        $wat_file
fi
sed -i -e "/(memory (/r /dev/stdin" $wat_file << 'EOF'
  (export "_start" (func $_start))
  (func $_start
    (local $0 i32)
    (local $1 i32)
    (local $2 i32)
    (local $3 i32)
    (local $4 i32)
    (local $5 i32)
    (; call $_initialize ;)
    i32.const 32
    local.set $5
    i32.const 8
    call $malloc
    local.set $4
    i32.const 32
    call $malloc
    local.set $1
    loop $while-continue|0
      local.get $4
      local.get $1
      local.get $3
      i32.add
      i32.store
      local.get $4
      local.get $5
      local.get $3
      i32.sub
      local.tee $2
      i32.store offset=4
      i32.const 0
      local.get $4
      i32.const 1
      local.get $4
      call $__imported_wasi_snapshot_preview1_fd_read
      drop
      local.get $4
      i32.load
      local.tee $0
      local.get $3
      i32.add
      local.set $3
      local.get $0
      local.get $2
      i32.lt_s
      if
        local.get $1
        local.get $3
        call $LLVMFuzzerTestOneInput
        drop
      else
        local.get $5
        local.get $5
        i32.add
        call $malloc
        local.set $0
        i32.const 0
        local.set $2
        loop $for-loop|1
          local.get $2
          local.get $3
          i32.lt_s
          if
            local.get $0
            local.get $2
            i32.add
            local.get $1
            local.get $2
            i32.add
            i32.load8_u
            i32.store8
            local.get $2
            i32.const 1
            i32.add
            local.set $2
            br $for-loop|1
           end
        end
        local.get $0
        local.set $1
        local.get $5
        local.get $5
        i32.add
        local.set $5
        br $while-continue|0
      end
    end
  )
EOF
wat2wasm -o $out_file $wat_file --debug-names
rm $wat_file