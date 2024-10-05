all: frr-format.so

CXX=g++-9

PLUGBASE=`$(CXX) -print-file-name=plugin`
CPPFLAGS=-I$(PLUGBASE)/include -I$(PLUGBASE)/include/c-family

# NB: compiler flags must match those used to build gcc, otherwise inlining
# behavior is different and linker errors will result due to missing symbols
# (which should in fact be inlined)

frr-format.so: frr-format.o
	$(CXX) -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb -shared -o $@ $^

frr-format.o: frr-format.c gcc-common.h
	$(CXX) -fno-rtti -fno-exceptions -fasynchronous-unwind-tables -ggdb $(CPPFLAGS) -fPIC -Wall -Wextra -Wno-unused-parameter -c -o $@ $<

install:
	install -d $(DESTDIR)$(PLUGBASE)
	install frr-format.so $(DESTDIR)$(PLUGBASE)

clean:
	rm -f frr-format.so frr-format.o
