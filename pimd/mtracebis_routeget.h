// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Multicast Traceroute for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 */

#ifdef __linux__

#ifndef ROUTEGET_H
#define ROUTEGET_H

#include <netinet/in.h>

int routeget(struct in_addr dst, struct in_addr *src, struct in_addr *gw);

#endif /* ROUTEGET */

#endif /* __linux__ */
