/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink - public definitions and function declarations.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_RULE_NETLINK_H
#define _ZEBRA_RULE_NETLINK_H

#ifdef HAVE_NETLINK

/*
 * Handle netlink notification informing a rule add or delete.
 */
extern int netlink_rule_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 */
extern int netlink_rules_read(struct zebra_ns *zns);

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_RULE_NETLINK_H */
