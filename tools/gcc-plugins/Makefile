all: frr-format.so

CXX=g++-9

PLUGBASE=`$(CXX) -print-file-name=plugin`
CPPFLAGS=-I$(PLUGBASE)/include -I$(PLUGBASE)/include/c-family

frr-format.so: frr-format.o
	$(CXX) -g -shared -o $@ $^

frr-format.o: frr-format.c gcc-common.h
	$(CXX) -g $(CPPFLAGS) -fPIC -Wall -Wextra -Wno-unused-parameter -c -o $@ $<

install:
	install -d $(DESTDIR)$(PLUGBASE)
	install frr-format.so $(DESTDIR)$(PLUGBASE)

clean:
	rm -f frr-format.so frr-format.o
