CXX=g++-15

GCCVER="$(shell $(CXX) -dumpfullversion)$(VERSUFFIX)"
PLUGBASE=`$(CXX) -print-file-name=plugin`
CPPFLAGS=-I$(PLUGBASE)/include -I$(PLUGBASE)/include/c-family

all: frr-format-$(GCCVER).so

# NB: compiler flags must match those used to build gcc, otherwise inlining
# behavior is different and linker errors will result due to missing symbols
# (which should in fact be inlined)

frr-format-$(GCCVER).so: frr-format-$(GCCVER).o
	$(CXX) -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb3 -Og -shared -o $@ $^

frr-format.o: frr-format.cc gcc-common.h
	$(CXX) -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb3 -Og $(CPPFLAGS) -fPIC -Wall -Wextra -Wno-unused-parameter -c -o $@ $<

frr-format-$(GCCVER).o: frr-format.cc frr-format.h
	$(CXX) -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb3 -Og $(CPPFLAGS) -fPIC -Wall -Wextra -Wno-unused-parameter -c -o $@ $<

install:
	install -d $(DESTDIR)$(PLUGBASE)
	install frr-format.so $(DESTDIR)$(PLUGBASE)

clean:
	rm -f frr-format.so frr-format.o
