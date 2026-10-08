set -e
# upstream HEAD; Chromium ships 9547f96ea5 (DEPS, encoder only); Firefox downloads Cisco's
# OpenH264 2.6.0 GMP plugin.
git clone-rev.sh https://github.com/cisco/openh264.git "$PROJECT/repo" 1a0073f0322c8b74cbcb75ca1bb1c3d19d75538d
git -C "$PROJECT/repo" apply "$PROJECT/port-wasi-no-sysctl.patch"
