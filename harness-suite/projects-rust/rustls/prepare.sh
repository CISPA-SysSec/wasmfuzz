#!/bin/bash
set -e +x
git clone-rev.sh https://github.com/rustls/rustls "$PROJECT/repo" a40acf9d3bcc413a0860f174ef71f049f20be7d9
# client built its ClientConfig and parsed the verifier trust anchor for every input.
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-client-config-once.patch"
