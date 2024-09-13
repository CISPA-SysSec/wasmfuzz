projects-rust = ${sort ${dir ${wildcard projects-rust/*/}}}
projects-clike = ${sort ${dir ${wildcard projects-clike/*/}}}
projects-rust-wip = ${sort ${dir ${wildcard projects-rust-wip/*/}}}
projects-clike-wip = ${sort ${dir ${wildcard projects-clike-wip/*/}}}

projects = $(projects-rust) $(projects-clike)
all-projects = $(projects) $(projects-rust-wip) $(projects-clike-wip)

# TODO: make help?

.PHONY: all working $(all-projects)
all: working
working: $(projects)

$(all-projects): $@/*
	./make-one.py $@
