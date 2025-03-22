set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" a884f9a0ad2aa52497c674ac879cbb6fb1403d09
git -C "$PROJECT/repo" apply "$PROJECT/0001-fixes.patch"
