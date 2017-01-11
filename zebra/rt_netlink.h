/* Header file exported by rt_netlink.c to zebra.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_RT_NETLINK_H
#define _ZEBRA_RT_NETLINK_H

#ifdef HAVE_NETLINK

#include "zebra/zebra_mpls.h"

#define NL_DEFAULT_ROUTE_METRIC 20

/* Additional protocol strings to push into routes */
#define RTPROT_BGP         186
#define RTPROT_ISIS        187
#define RTPROT_OSPF        188
#define RTPROT_RIP         189
#define RTPROT_RIPNG       190


extern void
clear_nhlfe_installed (zebra_lsp_t *lsp);
extern int
netlink_mpls_multipath (int cmd, zebra_lsp_t *lsp);

extern int netlink_route_change (struct sockaddr_nl *snl, struct nlmsghdr *h,
                                 ns_id_t ns_id);
extern int netlink_route_read (struct zebra_ns *zns);

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_RT_NETLINK_H */
