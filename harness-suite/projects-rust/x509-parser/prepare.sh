set -e
git clone-rev.sh https://github.com/rusticata/x509-parser.git "$PROJECT/repo" 68c5c55e62986e4d82303352db3acd918dce8e6d
git -C "$PROJECT/repo" apply "$PROJECT/port-remove-stale-cratesio-patch.patch"
