set -e
# upstream HEAD; Firefox ships 767aab2501 (media/libnestegg/moz.yaml).
git clone-rev.sh https://github.com/mozilla/nestegg "$PROJECT/repo" 767aab25013acefbdcc6d68a2a7a2c9081303e3f
