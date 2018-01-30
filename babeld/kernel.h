/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef BABEL_KERNEL_H
#define BABEL_KERNEL_H

#include <netinet/in.h>
#include "babel_main.h"
#include "if.h"

#define KERNEL_INFINITY 0xFFFF

#define ROUTE_FLUSH 0
#define ROUTE_ADD 1
#define ROUTE_MODIFY 2

int kernel_interface_operational(struct interface *interface);
int kernel_interface_mtu(struct interface *interface);
int kernel_interface_wireless(struct interface *interface);
int kernel_route(int operation, const unsigned char *dest, unsigned short plen,
                 const unsigned char *gate, int ifindex, unsigned int metric,
                 const unsigned char *newgate, int newifindex,
                 unsigned int newmetric);
int if_eui64(int ifindex, unsigned char *eui);
int gettime(struct timeval *tv);
int read_random_bytes(void *buf, size_t len);

#endif /* BABEL_KERNEL_H */
