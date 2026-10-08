set -e
# upstream HEAD; Firefox ships 1.3.0 (other-licenses/snappy/moz.yaml), Chromium 32ded457c0.
git clone-rev.sh https://github.com/google/snappy.git "$PROJECT/repo" 9c28114a38866f6deeaa826db918293bc28ae410
