set -e
git clone-rev.sh https://gitlab.com/sequoia-pgp/sequoia.git "$PROJECT/repo" aed60989222991bc57ba83d773309b6f9695b3cd
git -C "$PROJECT/repo" apply "$PROJECT/fix-subpacket-len-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-steal-short-read-error.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-limitor-exact-consume.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-rawcert-body-len-overflow.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-subpacket-length-cmp.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-partial-body-consume-bound.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-hashed-reader-data-consume.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-csf-sig-group-count.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-packet-parser-consume-stashed-error.patch"
git -C "$PROJECT/repo" apply "$PROJECT/limit-reader-buffer-grow-on-demand.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-rawcert-body-read-error-loop.patch"
git -C "$PROJECT/repo" apply "$PROJECT/fix-key4-public-len.patch"
# csf_verify/decrypt/inline_verify parsed their LazyLock test certificate during the first input.
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-init-test-cert.patch"
# cert_from_bytes dropped inputs that are not certificates from the corpus.
git -C "$PROJECT/repo" apply "$PROJECT/fuzz-cert-from-bytes-keep-rejected.patch"
