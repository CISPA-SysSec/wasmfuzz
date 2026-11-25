set -e

# upstream HEAD; Firefox ships 3.1.4.1 (media/libjpeg/moz.yaml), Chromium a 3.1.0 fork.
git clone-rev.sh https://github.com/libjpeg-turbo/libjpeg-turbo.git "$PROJECT/repo" 16317632aaee2fad65c979d3c61b0f2ecf6094ec
