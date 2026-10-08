set -e
# upstream HEAD; Chromium ships 6184f4484a (third_party/libwebm/README.chromium).
# NOTE: Chromium only compiles mkvmuxer (MediaRecorder); mkvparser is not shipped.
git clone-rev.sh https://chromium.googlesource.com/webm/libwebm "$PROJECT/repo" 6184f4484a826724b5293837134ab9492261b941
