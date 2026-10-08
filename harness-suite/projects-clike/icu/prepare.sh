set -e
# upstream HEAD (ICU 79 development); Firefox ships 78.3 (intl/icu/GIT-INFO),
# Chromium ships 78.2 (third_party/icu/README.chromium).
# Only icu4c/ is materialized.
git clone-rev.sh https://github.com/unicode-org/icu.git "$PROJECT/repo" e51a88487adbe30813e276b3809430e2a6b22c62 --sparse=icu4c
