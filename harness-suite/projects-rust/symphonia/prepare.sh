set -e
# NOTE: this is the dev-0.6 branch
git clone-rev.sh https://github.com/pdeljanov/symphonia.git "$PROJECT/repo" 4295a846d002b4fa145824d4c11bc18f35d44999
git -C "$PROJECT/repo" apply ../fix-harnesses.patch
