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
#include "linklist.h"
#include "prefix.h"
#include "memory.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_str.h"
#include "pim_rp.h"
#include "pim_str.h"
#include "pim_rpf.h"
#include "pim_sock.h"
#include "pim_memory.h"

struct rp_info
{
  struct prefix group;
  struct pim_rpf rp;
  int i_am_rp;
};

static struct list *qpim_rp_list = NULL;
static struct rp_info *tail = NULL;

static void
pim_rp_info_free (struct rp_info *rp_info)
{
  XFREE (MTYPE_PIM_RP, rp_info);
}

static int
pim_rp_list_cmp (void *v1, void *v2)
{
  struct rp_info *rp1 = (struct rp_info *)v1;
  struct rp_info *rp2 = (struct rp_info *)v2;

  if (rp1 == rp2)
    return 0;

  if (!rp1 && rp2)
    return -1;

  if (rp1 && !rp2)
    return 1;

  if (rp1 == tail)
    return 1;

  return -1;
}

void
pim_rp_init (void)
{
  struct rp_info *rp_info;

  qpim_rp_list = list_new ();
  qpim_rp_list->del = (void (*)(void *))pim_rp_info_free;
  qpim_rp_list->cmp = pim_rp_list_cmp;

  rp_info = XCALLOC (MTYPE_PIM_RP, sizeof (*rp_info));

  if (!rp_info)
    return;

  str2prefix ("224.0.0.0/4", &rp_info->group);
  rp_info->rp.rpf_addr.s_addr = INADDR_NONE;
  tail = rp_info;

  listnode_add (qpim_rp_list, rp_info);
}

void
pim_rp_free (void)
{
  if (qpim_rp_list)
    list_free (qpim_rp_list);
}

static struct rp_info *
pim_rp_find_exact (struct in_addr rp, struct prefix *group)
{
  struct listnode *node;
  struct rp_info *rp_info;

  for (ALL_LIST_ELEMENTS_RO (qpim_rp_list, node, rp_info))
    {
      if (rp.s_addr == rp_info->rp.rpf_addr.s_addr &&
	  prefix_same (&rp_info->group, group))
       return rp_info;
    }

  return NULL;
}

static struct rp_info *
pim_rp_find_match (struct in_addr rp, struct prefix *group)
{
  struct listnode *node;
  struct rp_info *rp_info;

  for (ALL_LIST_ELEMENTS_RO (qpim_rp_list, node, rp_info))
    {
      if (rp.s_addr == rp_info->rp.rpf_addr.s_addr &&
          prefix_match (&rp_info->group, group))
       return rp_info;
    }

  return NULL;
}

static struct rp_info *
pim_rp_find_match_group (struct prefix *group)
{
  struct listnode *node;
  struct rp_info *rp_info;

  for (ALL_LIST_ELEMENTS_RO (qpim_rp_list, node, rp_info))
    {
      if (prefix_match (&rp_info->group, group))
       return rp_info;
    }

  return NULL;
}

int
pim_rp_new (const char *rp, const char *group_range)
{
  int result;
  struct rp_info *rp_info;
  struct rp_info *rp_all;
  struct prefix group_all;

  str2prefix ("224.0.0.0/4", &group_all);
  rp_all = pim_rp_find_match_group(&group_all);

  rp_info = XCALLOC (MTYPE_PIM_RP, sizeof (*rp_info));
  if (!rp)
    return -1;

  if (group_range == NULL)
    result = str2prefix ("224.0.0.0/4", &rp_info->group);
  else
    result = str2prefix (group_range, &rp_info->group);

  if (!result)
    return -1;

  result = inet_pton (AF_INET, rp, &rp_info->rp.rpf_addr.s_addr);
  if (result <= 0)
    return -1;

  /*
   * Take over the 224.0.0.0/4 group if the rp is INADDR_NONE
   */
  if (prefix_same (&rp_all->group, &rp_info->group) &&
      rp_all->rp.rpf_addr.s_addr == INADDR_NONE)
    {
      rp_all->rp.rpf_addr = rp_info->rp.rpf_addr;
      XFREE (MTYPE_PIM_RP, rp_info);
      if (!pim_rp_setup ())
        return -2;
      return 0;
    }

  if (pim_rp_find_exact (rp_info->rp.rpf_addr, &rp_info->group))
    {
      XFREE (MTYPE_PIM_RP, rp_info);
      return 0;
    }

  if (pim_rp_find_match (rp_info->rp.rpf_addr, &rp_info->group))
    {
      if (prefix_same (&group_all, &rp_info->group))
        {
          return 0;
        }

      XFREE (MTYPE_PIM_RP, rp_info);
      return -3;
    }

  listnode_add_sort (qpim_rp_list, rp_info);

  if (!pim_rp_setup ())
    return -2;

  return 0;
}

int
pim_rp_del (const char *rp, const char *group_range)
{
  struct prefix group;
  struct in_addr rp_addr;
  struct prefix g_all;
  struct rp_info *rp_info;
  struct rp_info *rp_all;
  int result;

  str2prefix ("224.0.0.0/4", &g_all);
  if (group_range == NULL)
    result = str2prefix ("224.0.0.0/4", &group);
  else
    result = str2prefix (group_range, &group);

  if (!result)
    return -1;

  rp_all = pim_rp_find_match_group (&g_all);

  result = inet_pton (AF_INET, rp, &rp_addr);
  if (result <= 0)
    return -1;

  rp_info = pim_rp_find_exact (rp_addr, &group);
  if (!rp_info)
    return -2;

  if (rp_all == rp_info)
    {
      rp_all->rp.rpf_addr.s_addr = INADDR_NONE;
      rp_all->i_am_rp = 0;
      return 0;
    }

  listnode_delete (qpim_rp_list, rp_info);
  return 0;
}

int
pim_rp_setup (void)
{
  struct listnode *node;
  struct rp_info *rp_info;
  int ret = 0;

  for (ALL_LIST_ELEMENTS_RO (qpim_rp_list, node, rp_info))
    {
      if (pim_nexthop_lookup (&rp_info->rp.source_nexthop, rp_info->rp.rpf_addr) != 0)
        {
          zlog_err ("Unable to lookup nexthop for rp specified");
          ret++;
        }
    }

  if (ret)
    return 0;

  return 1;
}

/*
 * Checks to see if we should elect ourself the actual RP
 */
void
pim_rp_check_rp (struct in_addr old, struct in_addr new)
{
  struct listnode *node;
  struct rp_info *rp_info;

  if (qpim_rp_list == NULL)
    return;

  for (ALL_LIST_ELEMENTS_RO (qpim_rp_list, node, rp_info))
    {
      if (PIM_DEBUG_ZEBRA) {
        char sold[100];
        char snew[100];
        char rp[100];
        pim_inet4_dump("<rp?>", rp_info->rp.rpf_addr, rp, sizeof(rp));
        pim_inet4_dump("<old?>", old, sold, sizeof(sold));
        pim_inet4_dump("<new?>", new, snew, sizeof(snew));
        zlog_debug("%s: %s for old %s new %s", __func__, rp, sold, snew );
      }
      if (rp_info->rp.rpf_addr.s_addr == INADDR_NONE)
        continue;

      if (new.s_addr == rp_info->rp.rpf_addr.s_addr)
        {
	  rp_info->i_am_rp = 1;
        }

      if (old.s_addr == rp_info->rp.rpf_addr.s_addr)
        {
          rp_info->i_am_rp = 0;
        }
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
  struct prefix g;
  struct rp_info *rp_info;

  memset (&g, 0, sizeof (g));
  g.family = AF_INET;
  g.prefixlen = 32;
  g.u.prefix4 = group;

  rp_info = pim_rp_find_match_group (&g);

  if (rp_info)
    return rp_info->i_am_rp;

  return 0;
}

/*
 * RP(G)
 *
 * Return the RP that the Group belongs too.
 */
struct pim_rpf *
pim_rp_g (struct in_addr group)
{
  struct prefix g;
  struct rp_info *rp_info;

  memset (&g, 0, sizeof (g));
  g.family = AF_INET;
  g.prefixlen = 32;
  g.u.prefix4 = group;

  rp_info = pim_rp_find_match_group (&g);

  if (rp_info)
    {
      pim_nexthop_lookup(&rp_info->rp.source_nexthop, rp_info->rp.rpf_addr);
      return (&rp_info->rp);
    }

  // About to Go Down
  return NULL;
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
pim_rp_set_upstream_addr (struct in_addr *up, struct in_addr source, struct in_addr group)
{
  struct rp_info *rp_info;
  struct prefix g;

  memset (&g, 0, sizeof (g));
  g.family = AF_INET;
  g.prefixlen = 32;
  g.u.prefix4 = group;

  rp_info = pim_rp_find_match_group (&g);

  if ((rp_info->rp.rpf_addr.s_addr == INADDR_NONE) && (source.s_addr == INADDR_ANY))
    {
      if (PIM_DEBUG_PIM_TRACE)
	zlog_debug("%s: Received a (*,G) with no RP configured", __PRETTY_FUNCTION__);
      return 0;
    }

  *up = (source.s_addr == INADDR_ANY) ? rp_info->rp.rpf_addr : source;

  return 1;
}

int
pim_rp_config_write (struct vty *vty)
{
  struct listnode *node;
  struct rp_info *rp_info;
  char buffer[32];
  int count = 0;

  for (ALL_LIST_ELEMENTS_RO (qpim_rp_list, node, rp_info))
    {
      if (rp_info->rp.rpf_addr.s_addr == INADDR_NONE)
        continue;

      if (rp_info->rp.rpf_addr.s_addr != INADDR_NONE)
        {
	  char buf[32];
          vty_out(vty, "ip pim rp %s %s%s", inet_ntop(AF_INET, &rp_info->rp.rpf_addr, buffer, 32),
		  prefix2str(&rp_info->group, buf, 32), VTY_NEWLINE);
          count++;
        }
    }

  return count;
}

int
pim_rp_check_is_my_ip_address (struct in_addr group, struct in_addr dest_addr)
{
  struct rp_info *rp_info;
  struct prefix g;

  memset (&g, 0, sizeof (g));
  g.family = AF_INET;
  g.prefixlen = 32;
  g.u.prefix4 = group;

  rp_info = pim_rp_find_match_group (&g);
  /*
   * See if we can short-cut some?
   * This might not make sense if we ever leave a static RP
   * type of configuration.
   * Note - Premature optimization might bite our patooeys' here.
   */
  if (I_am_RP(group))
    {
     if (dest_addr.s_addr == rp_info->rp.rpf_addr.s_addr)
       return 1;
    }

  if (if_lookup_exact_address (&dest_addr, AF_INET))
    return 1;
    
  return 0;
}
