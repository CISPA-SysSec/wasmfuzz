set -e
# upstream HEAD; Chromium ships 9547f96ea5 (DEPS, encoder only); Firefox downloads Cisco's
# OpenH264 2.6.0 GMP plugin.
git clone-rev.sh https://github.com/cisco/openh264.git "$PROJECT/repo" 78783f195ce116ecbaea83f7fac0ea8a355518b5
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-no-sysctl.patch"
