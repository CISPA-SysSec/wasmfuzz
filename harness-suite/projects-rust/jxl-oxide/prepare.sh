set -e
git clone-rev.sh https://github.com/tirr-c/jxl-oxide.git "$PROJECT/repo" 4793a821d1a1893ce9ebd475b280a914d04f33df
git -C "$PROJECT/repo" apply ../fuzz-decode-resource-limits.patch
# # Bug benchmark: Re-introduce NaN issue https://github.com/tirr-c/jxl-oxide/pull/485
# git -C "$PROJECT/repo" apply ../revert-fix-crash-with-NaNs-in-upsampling-485.patch