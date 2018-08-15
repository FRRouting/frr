all: ALWAYS
	@$(MAKE) -s -C ../.. doc-user
help: ALWAYS
	@$(MAKE) -s -C ../.. doc/help
pdf: ALWAYS
	@$(MAKE) -s -C ../.. doc/user/_build/latexpdf
info: ALWAYS
	@$(MAKE) -s -C ../.. doc/user/_build/texinfo/frr.info
%: ALWAYS
	@$(MAKE) -s -C ../.. doc/user/_build/$@

Makefile:
	#nothing
ALWAYS:
.PHONY: ALWAYS makefiles
.SUFFIXES:
