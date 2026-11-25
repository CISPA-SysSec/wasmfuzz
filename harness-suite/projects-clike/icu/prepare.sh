set -e
# upstream HEAD (ICU 79 development); Firefox ships 78.3 (intl/icu/GIT-INFO),
# Chromium ships 78.2 (third_party/icu/README.chromium).
# Only icu4c/ is materialized.
git clone-rev.sh https://github.com/unicode-org/icu.git "$PROJECT/repo" 9407c634af9e7f12841dd13fe09a37781baf08e9 --sparse=icu4c
