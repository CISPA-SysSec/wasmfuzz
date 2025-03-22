set -e
git clone-rev.sh https://github.com/uclouvain/openjpeg "$PROJECT/repo" e7453e398b110891778d8da19209792c69ca7169
git -C "$PROJECT/repo" apply ../stub_clocks.patch
