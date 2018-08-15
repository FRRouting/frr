all: ALWAYS
	@$(MAKE) -s -C ../.. doc/manpages/man.stamp
help: ALWAYS
	@$(MAKE) -s -C ../.. doc/help
%: ALWAYS
	@$(MAKE) -s -C ../.. doc/manpages/_build/$@

Makefile:
	#nothing
ALWAYS:
.PHONY: ALWAYS makefiles
.SUFFIXES:
