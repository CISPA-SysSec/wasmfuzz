projects-rust = ${sort ${dir ${wildcard projects-rust/*/}}}
projects-clike = ${sort ${dir ${wildcard projects-clike/*/}}}
projects-rust-wip = ${sort ${dir ${wildcard projects-rust-wip/*/}}}
projects-clike-wip = ${sort ${dir ${wildcard projects-clike-wip/*/}}}

projects = $(projects-rust) $(projects-clike)
all-projects = $(projects) $(projects-rust-wip) $(projects-clike-wip)

.PHONY: all $(all-projects)
all: $(projects)

$(all-projects): dummy/.build $@/*
	./make-one.py $@

# Note: This target is a prerequisite for all other harnesses
#       such that a concurrent make run only builds the Dockerfile once
dummy/.build: scripts/* Dockerfile
	./make-one.py dummy
	@touch $@

.PHONY: rust-libfuzzer
rust-libfuzzer:
	for x in projects-rust/*/; do python3 ./make-one.py $$x x86_64-libfuzzer; done
