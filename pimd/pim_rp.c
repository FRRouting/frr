/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#include <zebra.h>

#include "log.h"
#include "network.h"
#include "if.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_str.h"
#include "pim_rp.h"
#include "pim_str.h"
#include "pim_rpf.h"
#include "pim_sock.h"

static int i_am_rp = 0;

static struct pim_rpf  qpim_rp = { .rpf_addr.s_addr = INADDR_NONE };

int
pim_rp_new (const char *rp, const char *group_range)
{
  int result;

  result = inet_pton (AF_INET, rp, &qpim_rp.rpf_addr.s_addr);
  if (result <= 0)
    return -1;

  if (!pim_rp_setup ())
    return -2;

  return 0;
}

int
pim_rp_del (const char *rp, const char *group_range)
{
  qpim_rp.rpf_addr.s_addr = INADDR_NONE;

  return 0;
}

int
pim_rp_setup (void)
{
  if (pim_nexthop_lookup (&qpim_rp.source_nexthop, qpim_rp.rpf_addr, NULL) != 0)
    {
      zlog_err ("Unable to lookup nexthop for rp specified");
      return 0;
    }

  return 1;
}

/*
 * Checks to see if we should elect ourself the actual RP
 */
void
pim_rp_check_rp (struct in_addr old, struct in_addr new)
{
  if (PIM_DEBUG_ZEBRA) {
    char sold[100];
    char snew[100];
    char rp[100];
    pim_inet4_dump("<rp?>", qpim_rp.rpf_addr, rp, sizeof(rp));
    pim_inet4_dump("<old?>", old, sold, sizeof(sold));
    pim_inet4_dump("<new?>", new, snew, sizeof(snew));
    zlog_debug("%s: %s for old %s new %s", __func__, rp, sold, snew );
  }

  if (qpim_rp.rpf_addr.s_addr == INADDR_NONE)
    return;

  if (new.s_addr == qpim_rp.rpf_addr.s_addr)
    {
      i_am_rp = 1;
      return;
    }

  if (old.s_addr == qpim_rp.rpf_addr.s_addr)
    {
      i_am_rp = 0;
      return;
    }
}

/*
 * I_am_RP(G) is true if the group-to-RP mapping indicates that
 * this router is the RP for the group.
 *
 * Since we only have static RP, all groups are part of this RP
 */
int
pim_rp_i_am_rp (struct in_addr group)
{
  return i_am_rp;
}

/*
 * RP(G)
 *
 * Return the RP that the Group belongs too.
 */
struct pim_rpf *
pim_rp_g (struct in_addr group)
{
  /*
   * For staticly configured RP, it is always the qpim_rp
   */
  pim_nexthop_lookup(&qpim_rp.source_nexthop, qpim_rp.rpf_addr, NULL);
  return(&qpim_rp);
}

/*
 * Set the upstream IP address we want to talk to based upon
 * the rp configured and the source address
 *
 * If we have don't have a RP configured and the source address is *
 * then return failure.
 *
 */
int
pim_rp_set_upstream_addr (struct in_addr *up, struct in_addr source)
{
  if ((qpim_rp.rpf_addr.s_addr == INADDR_NONE) && (source.s_addr == INADDR_ANY))
    {
      if (PIM_DEBUG_PIM_TRACE)
	zlog_debug("%s: Received a (*,G) with no RP configured", __PRETTY_FUNCTION__);
      return 0;
    }

  *up = (source.s_addr == INADDR_ANY) ? qpim_rp.rpf_addr : source;

  return 1;
}

int
pim_rp_config_write (struct vty *vty)
{
  char buffer[32];

  if (qpim_rp.rpf_addr.s_addr != INADDR_NONE)
    {
      vty_out(vty, "ip pim rp %s%s", inet_ntop(AF_INET, &qpim_rp.rpf_addr, buffer, 32), VTY_NEWLINE);
      return 1;
    }

  return 0;
}

int
pim_rp_check_is_my_ip_address (struct in_addr group, struct in_addr dest_addr)
{
  /*
   * See if we can short-cut some?
   * This might not make sense if we ever leave a static RP
   * type of configuration.
   * Note - Premature optimization might bite our patooeys' here.
   */
  if (I_am_RP(group))
    {
     if (dest_addr.s_addr == qpim_rp.rpf_addr.s_addr)
       return 1;
    }

  if (if_lookup_exact_address (&dest_addr, AF_INET))
    return 1;
    
  return 0;
}
