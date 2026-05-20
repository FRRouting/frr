// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026	ATCorp
 *			Nathan Bahr
 */


#ifndef OSPFD_OSPF_QUICKNBR_H
#define OSPFD_OSPF_QUICKNBR_H

#include <netinet/in.h>

struct ospf_interface;

#define IS_QUICKNBR(_nbr) ((_nbr)->router_id.s_addr == INADDR_ANY)

void ospf_qn_add(struct ospf_interface *oi, struct in_addr *endpoint);

#endif /* OSPFD_OSPF_QUICKNBR_H */
