set -e

# upstream HEAD; Firefox ships 3.1.4.1 (media/libjpeg/moz.yaml), Chromium a 3.1.0 fork.
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo.git "$PROJECT/repo" dd8ad7915cdf5ab1f8719d488894a5e54c876dd6
