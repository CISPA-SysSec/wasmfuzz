set -e
# temporal_rs at upstream HEAD; Chromium vendors 0.2.6 for V8's Temporal implementation
# (third_party/rust/temporal_rs/v0_2/README.chromium).
# Firefox implements Temporal in C++ and does not ship temporal_rs.
git clone-rev.sh https://github.com/boa-dev/temporal "$PROJECT/repo" eadf8039d2577e4375493a0eb3f46a66f25616ec
