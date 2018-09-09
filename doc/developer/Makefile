all: ALWAYS
	@$(MAKE) -s -C ../.. developer-html
help: ALWAYS
	@$(MAKE) -s -C ../.. doc/help
pdf: ALWAYS
	@$(MAKE) -s -C ../.. doc/developer/_build/latexpdf
info: ALWAYS
	@$(MAKE) -s -C ../.. doc/developer/_build/texinfo/frr.info
%: ALWAYS
	@$(MAKE) -s -C ../.. doc/developer/_build/$@

Makefile:
	#nothing
ALWAYS:
.PHONY: ALWAYS makefiles
.SUFFIXES:
