all: ALWAYS
	@$(MAKE) -s -C .. doc
%: ALWAYS
	@$(MAKE) -s -C .. doc/$@
html:
	@$(MAKE) -s -C .. doc/user/_build/html/.buildinfo
info:
	@$(MAKE) -s -C .. doc/user/_build/texinfo/frr.info
pdf:
	@$(MAKE) -s -C .. doc/user/_build/latexpdf
frr.info: info
frr.pdf: pdf

Makefile:
	#nothing
ALWAYS:
.PHONY: ALWAYS makefiles html info frr.info pdf frr.pdf
.SUFFIXES:
