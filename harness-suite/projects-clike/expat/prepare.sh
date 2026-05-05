set -e
git clone-rev.sh https://github.com/libexpat/libexpat "$PROJECT/repo" 9acd83673adc1e9f29a013329f10ab13e948c8fe
git -C "$PROJECT/repo" apply ../fix_link_args.patch
git -C "$PROJECT/repo" apply ../disable-lpm-harness.patch
