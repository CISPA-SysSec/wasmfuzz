set -e
# HACK: We need --recursive in order to revert the commit below. See clone-rev.sh
git clone-rev.sh https://github.com/tirr-c/jxl-oxide.git "$PROJECT/repo" e653b3cd48529509fbd6bd85bdb5379e5848b779 --recursive

cd "$PROJECT/repo"
git config user.email "you@example.com"
git config user.name "Your Name"
# Bug benchmark: Re-introduce NaN issue https://github.com/tirr-c/jxl-oxide/pull/485
git revert e653b3cd48529509fbd6bd85bdb5379e5848b779
