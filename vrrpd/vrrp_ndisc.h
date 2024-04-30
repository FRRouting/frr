// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP Neighbor Discovery.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Quentin Young
 */
#ifndef __VRRP_NDISC_H__
#define __VRRP_NDISC_H__

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "vrrp.h"

/*
 * Initialize VRRP neighbor discovery.
 */
extern void vrrp_ndisc_init(void);

/*
 * Check whether VRRP Neighbor Discovery is initialized.
 *
 * Returns:
 *    True if initialized, false otherwise
 */
extern bool vrrp_ndisc_is_init(void);

/*
 * Finish VRRP Neighbor Discovery.
 */
extern void vrrp_ndisc_fini(void);

/*
 * Send VRRP Neighbor Advertisement.
 *
 * ifp
 *    Interface to transmit on
 *
 * ip
 *    IPv6 address to send Neighbor Advertisement for
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
extern int vrrp_ndisc_una_send(struct vrrp_router *r, struct ipaddr *ip);

/*
 * Send VRRP Neighbor Advertisements for all virtual IPs.
 *
 * r
 *    Virtual Router to send NA's for
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
extern int vrrp_ndisc_una_send_all(struct vrrp_router *r);

#endif /* __VRRP_NDISC_H__ */
