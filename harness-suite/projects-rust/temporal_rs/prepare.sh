set -e
# temporal_rs at upstream HEAD; Chromium vendors 0.2.6 for V8's Temporal implementation
# (third_party/rust/temporal_rs/v0_2/README.chromium).
# Firefox implements Temporal in C++ and does not ship temporal_rs.
git clone-rev.sh https://github.com/boa-dev/temporal "$PROJECT/repo" 450e284e76240220d68d4a14c841dee44182f971
