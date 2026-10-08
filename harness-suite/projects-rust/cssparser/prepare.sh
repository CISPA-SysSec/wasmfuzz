#!/bin/bash
set -e
# cssparser (+ cssparser-macros, cssparser-color) at upstream HEAD; Firefox uses a git rev
# via [patch.crates-io] in firefox/Cargo.toml (cssparser 0.38.0).
git clone-rev.sh https://github.com/servo/rust-cssparser "$PROJECT/repo" 106021c7bc55ed2cac83f590c0d356fa530b7061
# selectors lives in-tree in Firefox (servo/components/selectors); Firefox main HEAD.
git clone-rev.sh https://github.com/mozilla-firefox/firefox "$PROJECT/firefox" 4ad2eb15b14e85132e844ef6d46c1ece5b3b9299 \
    --sparse=/servo/components/selectors/,/servo/components/servo_arc/,/servo/components/to_shmem/,/servo/components/to_shmem_derive/
