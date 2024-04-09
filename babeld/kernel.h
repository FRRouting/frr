// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/

#ifndef BABEL_KERNEL_H
#define BABEL_KERNEL_H

#include <netinet/in.h>
#include "babel_main.h"
#include "if.h"

#define KERNEL_INFINITY 0xFFFF

enum babel_kernel_routes {
    ROUTE_FLUSH,
    ROUTE_ADD,
    ROUTE_MODIFY,
};

int kernel_interface_operational(struct interface *interface);
int kernel_interface_mtu(struct interface *interface);
int kernel_interface_wireless(struct interface *interface);
int kernel_route(enum babel_kernel_routes operation, const unsigned char *dest,
		 unsigned short plen, const unsigned char *gate, int ifindex,
		 unsigned int metric, const unsigned char *newgate,
		 int newifindex, unsigned int newmetric);
int if_eui64(int ifindex, unsigned char *eui);
void gettime(struct timeval *tv);
int read_random_bytes(void *buf, size_t len);

#endif /* BABEL_KERNEL_H */
