/* A generic nexthop structure
 * Copyright (C) 2013 Cumulus Networks, Inc.
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
#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "str.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "prefix.h"
#include "nexthop.h"

/* check if nexthops are same, non-recursive */
int
nexthop_same_no_recurse (struct nexthop *next1, struct nexthop *next2)
{
  if (next1->type != next2->type)
    return 0;

  switch (next1->type)
    {
    case NEXTHOP_TYPE_IPV4:
    case NEXTHOP_TYPE_IPV4_IFINDEX:
      if (! IPV4_ADDR_SAME (&next1->gate.ipv4, &next2->gate.ipv4))
	return 0;
      if (next1->ifindex && (next1->ifindex != next2->ifindex))
	return 0;
      break;
    case NEXTHOP_TYPE_IFINDEX:
    case NEXTHOP_TYPE_IFNAME:
      if (next1->ifindex != next2->ifindex)
	return 0;
      break;
#ifdef HAVE_IPV6
    case NEXTHOP_TYPE_IPV6:
      if (! IPV6_ADDR_SAME (&next1->gate.ipv6, &next2->gate.ipv6))
	return 0;
      break;
    case NEXTHOP_TYPE_IPV6_IFINDEX:
    case NEXTHOP_TYPE_IPV6_IFNAME:
      if (! IPV6_ADDR_SAME (&next1->gate.ipv6, &next2->gate.ipv6))
	return 0;
      if (next1->ifindex != next2->ifindex)
	return 0;
      break;
#endif /* HAVE_IPV6 */
    default:
      /* do nothing */
      break;
    }
  return 1;
}

/*
 * nexthop_type_to_str
 */
const char *
nexthop_type_to_str (enum nexthop_types_t nh_type)
{
  static const char *desc[] = {
    "none",
    "Directly connected",
    "Interface route",
    "IPv4 nexthop",
    "IPv4 nexthop with ifindex",
    "IPv4 nexthop with ifname",
    "IPv6 nexthop",
    "IPv6 nexthop with ifindex",
    "IPv6 nexthop with ifname",
    "Null0 nexthop",
  };

  if (nh_type >= ZEBRA_NUM_OF (desc))
    return "<Invalid nh type>";

  return desc[nh_type];
}
