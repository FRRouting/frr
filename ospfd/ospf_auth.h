// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 Amnesh Inc.
 *                    Mahdi Varasteh
 */

#ifndef _ZEBRA_OSPF_AUTH_H
#define _ZEBRA_OSPF_AUTH_H

#include <ospfd/ospf_gr.h>
#include <ospfd/ospf_packet.h>

int ospf_auth_check(struct ospf_interface *oi, struct ip *iph, struct ospf_header *ospfh);
int ospf_auth_check_digest(struct ospf_interface *oi, struct ip *iph, struct ospf_header *ospfh);
int ospf_auth_make(struct ospf_interface *oi, struct ospf_packet *op);
int ospf_auth_make_digest(struct ospf_interface *oi, struct ospf_packet *op);
int ospf_auth_type(struct ospf_interface *oi);
int ospf_auth_make_data(struct ospf_interface *oi, struct ospf_header *ospfh);

#endif /* _ZEBRA_OSPF_AUTH_H */
