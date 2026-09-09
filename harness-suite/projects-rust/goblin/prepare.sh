set -e
git clone-rev.sh https://github.com/m4b/goblin.git "$PROJECT/repo" 24a62600a4a75c145c08ec9dd82964acf1bb833b
git -C "$PROJECT/repo" apply "$PROJECT/fix-32-bit-overflows.patch"
