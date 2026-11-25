set -e
# upstream HEAD; Firefox ships 1.3.0 (other-licenses/snappy/moz.yaml), Chromium 32ded457c0.
git clone-rev.sh https://github.com/google/snappy.git "$PROJECT/repo" 946606459314e55d029c85f9a8c46f8809467f0f
