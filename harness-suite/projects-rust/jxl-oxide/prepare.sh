set -e
git clone-rev.sh https://github.com/tirr-c/jxl-oxide.git "$PROJECT/repo" e653b3cd48529509fbd6bd85bdb5379e5848b779
# Bug benchmark: Re-introduce NaN issue https://github.com/tirr-c/jxl-oxide/pull/485
git -C "$PROJECT/repo" apply ../revert-fix-crash-with-NaNs-in-upsampling-485.patch