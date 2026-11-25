#!/bin/bash
set -e
# cssparser (+ cssparser-macros, cssparser-color) at upstream HEAD; Firefox uses a git rev
# via [patch.crates-io] in firefox/Cargo.toml (cssparser 0.38.0).
git clone-rev.sh https://github.com/servo/rust-cssparser "$PROJECT/repo" caa4d97c8bdc7b18974e8f389269d28bf1f74563
# selectors lives in-tree in Firefox (servo/components/selectors); Firefox main HEAD.
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/firefox" 2072eb612d1838fbad4a29d26d78c976f091f31d \
    --sparse=/servo/components/selectors/,/servo/components/servo_arc/,/servo/components/to_shmem/,/servo/components/to_shmem_derive/
