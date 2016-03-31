/* BGP-4, BGP-4+ daemon program
   Copyright (C) 2016, 6WIND

This file is part of GNU Quagga.

GNU Quagga is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Quagga is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Quagga; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */


#include <zebra.h>

#include "prefix.h"
#include "linklist.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_vrf.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mpath.h"

static int
bgp_show_vrf (struct vty *vty, const char *vrf_name, afi_t afi,
              enum bgp_show_type type, void *output_arg, u_char use_json);

static int
bgp_show_vrf_route (struct vty *vty, const char *vrf_name, const char *ip_str,
                    afi_t afi, int prefix_check,u_char use_json);

static void
bgp_vrf_apply_new_imports_internal (struct bgp_vrf *vrf, afi_t afi, safi_t safi);

static void
bgp_vrf_process_one (struct bgp_vrf *vrf, afi_t afi, safi_t safi, struct bgp_node *rn,
                     struct bgp_info *select, int action);

/* for vty access to bgp vrf node */
DEFINE_QOBJ_TYPE(bgp_vrf)

/* for vty config, BGP VRF node. */
static struct cmd_node bgp_vrf_node =
{
  BGP_VRF_NODE,
  "%s(bgp-vrf)# ",
  1
};

/* for debugging */
unsigned long conf_bgp_debug_bgp_vrf;
unsigned long term_bgp_debug_bgp_vrf;

static struct ecommunity * ecommunity_reintern (struct ecommunity *ecom)
{
  assert (ecom->refcnt > 0);
  ecom->refcnt++;
  return ecom;
}

/* route target internals */
static unsigned int bgp_rt_hash_key (void *arg)
{
  const struct bgp_rt_sub *rt_sub = arg;
  uint32_t *rtval = (uint32_t *)(char *)&rt_sub->rt;
  return rtval[0] ^ rtval[1];
}

static int bgp_rt_hash_cmp (const void *a, const void *b)
{
  const struct bgp_rt_sub *aa = a, *bb = b;
  return !memcmp(&aa->rt, &bb->rt, sizeof(aa->rt));
}

static void *
bgp_rt_hash_alloc (void *dummy)
{
  struct bgp_rt_sub *ddummy = dummy, *rt_sub;
  rt_sub = XMALLOC (MTYPE_BGP_RT_SUB, sizeof (*rt_sub));
  rt_sub->rt = ddummy->rt;
  rt_sub->vrfs = list_new();
  return rt_sub;
}

static void
bgp_rt_hash_dealloc (struct bgp_rt_sub *rt_sub)
{
  list_delete (rt_sub->vrfs);
  XFREE (MTYPE_BGP_RT_SUB, rt_sub);
}

void
bgp_vrf_rt_export_unset (struct bgp_vrf *vrf)
{
  if (vrf->rt_export)
    ecommunity_unintern (&vrf->rt_export);
}

void
bgp_vrf_rt_export_set (struct bgp_vrf *vrf, struct ecommunity *rt_export)
{
  if (vrf->rt_export)
    ecommunity_unintern (&vrf->rt_export);

  vrf->rt_export = ecommunity_reintern (rt_export);
}

void
bgp_vrf_rt_import_unset (struct bgp_vrf *vrf)
{
  size_t i;

  if (!vrf->rt_import)
    return;

  for (i = 0; i < (size_t)vrf->rt_import->size; i++)
    {
      struct bgp_rt_sub dummy, *rt_sub;
      memcpy (&dummy.rt, vrf->rt_import->val + 8 * i, 8);

      rt_sub = hash_lookup (vrf->bgp->rt_subscribers, &dummy);
      assert(rt_sub);
      listnode_delete (rt_sub->vrfs, vrf);
      if (list_isempty (rt_sub->vrfs))
        {
          hash_release (vrf->bgp->rt_subscribers, rt_sub);
          bgp_rt_hash_dealloc (rt_sub);
        }
    }

  ecommunity_unintern (&vrf->rt_import);
}

void
bgp_vrf_rt_import_set (struct bgp_vrf *vrf, struct ecommunity *rt_import)
{
  size_t i;
  afi_t afi;

  bgp_vrf_rt_import_unset (vrf);

  vrf->rt_import = ecommunity_reintern (rt_import);

  for (i = 0; i < (size_t)vrf->rt_import->size; i++)
    {
      struct bgp_rt_sub dummy, *rt_sub;
      memcpy (&dummy.rt, vrf->rt_import->val + 8 * i, 8);

      rt_sub = hash_get (vrf->bgp->rt_subscribers, &dummy, bgp_rt_hash_alloc);
      listnode_add (rt_sub->vrfs, vrf);
    }

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    bgp_vrf_apply_new_imports (vrf, afi);
}

/* bgp vrf internals */
struct bgp_vrf *
bgp_vrf_lookup_per_rn (struct bgp *bgp, int afi, struct bgp_node *vrf_rn)
{
  struct listnode *node;
  struct bgp_vrf *vrf;

  if(bgp_node_table (vrf_rn)->type != BGP_TABLE_VRF)
    return NULL;
  for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
    if(vrf->rib[afi] == bgp_node_table (vrf_rn))
      {
        return vrf;
      }
  return NULL;
}

struct bgp_vrf *
bgp_vrf_lookup (struct bgp *bgp, struct prefix_rd *outbound_rd)
{
  struct listnode *node;
  struct bgp_vrf *vrf;

  for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
    if (!memcmp (outbound_rd->val, vrf->outbound_rd.val, 8))
      return vrf;
  return NULL;
}

struct bgp_vrf *
bgp_vrf_update_rd (struct bgp *bgp, struct bgp_vrf *vrf, struct prefix_rd *outbound_rd)
{
  if (!vrf)
    {
      char vrf_rd_str[RD_ADDRSTRLEN];
      prefix_rd2str (outbound_rd, vrf_rd_str, sizeof (vrf_rd_str));
      if ( (vrf = bgp_vrf_lookup_per_name (bgp, vrf_rd_str, 1)) == NULL)
        return NULL;
    }
  vrf->flag &= ~BGP_VRF_RD_UNSET;
  vrf->outbound_rd = *outbound_rd;
  return vrf;
}

/* delete RD <> command as well as RD export/import
 * and RIB table associated
 */
void
bgp_vrf_delete_rd (struct bgp_vrf *vrf)
{
  char vrf_rd_str[RD_ADDRSTRLEN];

  if (!vrf)
    return;

  prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
  zlog_info ("deleting rd %s", vrf_rd_str);

  bgp_vrf_clean_tables (vrf);

  bgp_vrf_rt_import_unset (vrf);
  if (vrf->rt_export)
    ecommunity_unintern (&vrf->rt_export);
  return;
}

static void
bgp_vrf_delete_int (void *arg)
{
  struct bgp_vrf *vrf = arg;
  char vrf_rd_str[RD_ADDRSTRLEN];

  prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
  zlog_info ("deleting vrf %s", vrf_rd_str);

  bgp_vrf_delete_rd (vrf);

  if (vrf->name)
    free (vrf->name);
  QOBJ_UNREG (vrf);
  XFREE (MTYPE_BGP_VRF, vrf);
}

void
bgp_vrf_context_delete (struct bgp_vrf *vrf)
{
  listnode_delete (vrf->bgp->vrfs, vrf);
  bgp_vrf_delete_int(vrf);
}

static void
bgp_vrf_apply_new_imports_internal (struct bgp_vrf *vrf, afi_t afi, safi_t safi)
{
  struct bgp_node *rd_rn, *rn;
  struct bgp_info *sel, *mp;
  struct bgp_table *table;
  struct ecommunity *ecom;
  size_t i, j;
  bool found;

  for (rd_rn = bgp_table_top (vrf->bgp->rib[afi][safi]); rd_rn;
                  rd_rn = bgp_route_next (rd_rn))
    if (rd_rn->info != NULL)
      {
        table = rd_rn->info;

        for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
          {
            for (sel = rn->info; sel; sel = sel->next)
              if (CHECK_FLAG (sel->flags, BGP_INFO_SELECTED))
                break;
            if (!sel)
              continue;
            for (mp = rn->info; mp; mp = mp->next)
              if(mp != sel &&  bgp_is_mpath_entry(mp, sel))
                {
                  /* call bgp_vrf_process_two */
                  if (!mp->attr || !mp->attr->extra)
                    continue;
                  ecom = mp->attr->extra->ecommunity;
                  if (!ecom)
                    continue;
                  found = false;
                  for (i = 0; i < (size_t)ecom->size && !found; i++)
                    for (j = 0; j < (size_t)vrf->rt_import->size && !found; j++)
                      if (!memcmp(ecom->val + i * 8, vrf->rt_import->val + j * 8, 8))
                        found = true;
                  if (!found)
                    continue;
                  bgp_vrf_process_one(vrf, afi, safi, rn, mp, 0);
                }
            if (!sel->attr || !sel->attr->extra)
              continue;
            ecom = sel->attr->extra->ecommunity;
            if (!ecom)
              continue;

            found = false;
            for (i = 0; i < (size_t)ecom->size && !found; i++)
              for (j = 0; j < (size_t)vrf->rt_import->size && !found; j++)
                if (!memcmp(ecom->val + i * 8, vrf->rt_import->val + j * 8, 8))
                  found = true;
            if (!found)
              continue;
            bgp_vrf_process_one(vrf, afi, safi, rn, sel, 0);
          }
      }
}

void
bgp_vrf_apply_new_imports (struct bgp_vrf *vrf, afi_t afi)
{
  if (!vrf->rt_import || vrf->rt_import->size == 0)
    return;
  bgp_vrf_apply_new_imports_internal (vrf, afi, SAFI_MPLS_VPN);
  bgp_vrf_apply_new_imports_internal (vrf, afi, SAFI_ENCAP);
  return;
}

struct bgp_vrf *
bgp_vrf_lookup_per_name (struct bgp *bgp, const char *name, int create)
{
  afi_t afi;
  struct listnode *node;
  struct bgp_vrf *vrf;
  unsigned int len;

  if (!name)
    return NULL;
  len = strlen(name);
  for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
    {
      if (strlen (vrf->name) != len)
        continue;
      if (0 == strcmp (vrf->name, name))
        break;
    }
  if (vrf || create == 0)
    return vrf;
  if ((vrf = XCALLOC (MTYPE_BGP_VRF, sizeof (struct bgp_vrf))) == NULL)
    return NULL;
  QOBJ_REG (vrf, bgp_vrf);
  vrf->bgp = bgp;
  vrf->name = strdup (name);
  vrf->flag |= BGP_VRF_RD_UNSET;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    {
      vrf->route[afi] = bgp_table_init (afi, SAFI_UNICAST);
      vrf->route[afi]->type = BGP_TABLE_VRF;
      vrf->rib[afi] = bgp_table_init (afi, SAFI_UNICAST);
      vrf->rib[afi]->type = BGP_TABLE_VRF;
    }

  listnode_add (bgp->vrfs, vrf);
  return vrf;
}

static bool rd_same (const struct prefix_rd *a, const struct prefix_rd *b)
{
  return !memcmp(&a->val, &b->val, sizeof(a->val));
}

/* VRF import processing */
/* updates selected bgp_info structure to bgp vrf rib table
 * most of the cases, processing consists in adding or removing entries in RIB tables
 * on some cases, there is an update request. then it is necessary to have both old and new ri
 */
static void
bgp_vrf_process_one (struct bgp_vrf *vrf, afi_t afi, safi_t safi, struct bgp_node *rn,
                     struct bgp_info *select, int action)
{
  struct bgp_node *vrf_rn;
  struct bgp_info *iter = NULL;
  struct prefix_rd *prd;
  char pfx_str[INET6_BUFSIZ];

  prd = &bgp_node_table (rn)->prd;
  if (BGP_DEBUG(bgp_vrf, BGPVRF))
    {
      char vrf_rd_str[RD_ADDRSTRLEN], rd_str[RD_ADDRSTRLEN];
      char nh_str[BUFSIZ] = "<?>";

      prefix_rd2str(&vrf->outbound_rd, vrf_rd_str, sizeof(vrf_rd_str));
      prefix_rd2str(prd, rd_str, sizeof(rd_str));
      prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
      if(select && select->attr && select->attr->extra)
        {
          if (afi == AFI_IP)
            strcpy (nh_str, inet_ntoa (select->attr->extra->mp_nexthop_global_in));
          else if (afi == AFI_IP6)
            inet_ntop (AF_INET6, &select->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
        }
      else if(select)
        {
          inet_ntop (AF_INET, &select->attr->nexthop,
                     nh_str, sizeof (nh_str));
        }
      zlog_debug ("vrf[%s] %s: [%s] [nh %s] %s ", vrf_rd_str, pfx_str, rd_str, nh_str,
                action == BGP_VRF_IMPORT_ROUTE_INFO_TO_REMOVE? "withdrawing" : "updating");
    }
  /* add a new entry if necessary
   * if already present, do nothing.
   * use the loop to parse old entry also */

  /* check if global RIB plans for destroying initial entry
   * if yes, then suppress it
   */
  if(!vrf || !vrf->rib[afi] || !select)
    {
      return;
    }
  vrf_rn = bgp_node_get (vrf->rib[afi], &rn->p);
  if(!vrf_rn)
    {
      return;
    }
  if ( (action == BGP_VRF_IMPORT_ROUTE_INFO_TO_REMOVE) &&
       (CHECK_FLAG (select->flags, BGP_INFO_REMOVED)))
    {
      /* check entry not already present */
      for (iter = vrf_rn->info; iter; iter = iter->next)
        {
          /* coming from same peer */
          if(iter->peer->remote_id.s_addr == select->peer->remote_id.s_addr)
            {
              bgp_info_delete(vrf_rn, iter);
              prefix2str(&vrf_rn->p, pfx_str, sizeof(pfx_str));
              if (BGP_DEBUG(bgp_vrf, BGPVRF))
                {
                  char nh_str[BUFSIZ] = "<?>";
                  if(iter->attr && iter->attr->extra)
                    {
                      if (afi == AFI_IP)
                        strcpy (nh_str, inet_ntoa (iter->attr->extra->mp_nexthop_global_in));
                      else if (afi == AFI_IP6)
                        inet_ntop (AF_INET6, &iter->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
                    }
                  else
                    {
                      inet_ntop (AF_INET, &iter->attr->nexthop,
                                 nh_str, sizeof (nh_str));
                    }
                  zlog_debug ("%s: processing entry (for removal) from %s [ nh %s]",
                              pfx_str, iter->peer->host, nh_str);
                }
              bgp_process (iter->peer->bgp, vrf_rn, afi, SAFI_UNICAST);
              break;
            }
        }
    }
  if(action == BGP_VRF_IMPORT_ROUTE_INFO_TO_ADD || action == BGP_VRF_IMPORT_ROUTE_INFO_TO_UPDATE)
    {
      /* check entry not already present */
      for (iter = vrf_rn->info; iter; iter = iter->next)
        {
          if (!rd_same (&iter->extra->vrf_rd, prd))
            continue;
          /* search associated old entry.
           * assume with same nexthop and same peer */
          if(iter->peer->remote_id.s_addr == select->peer->remote_id.s_addr)
            {
              /* update */
              if(action == BGP_VRF_IMPORT_ROUTE_INFO_TO_UPDATE)
                {
                  /* update label */
                  /* update attr part / containing next hop */
                  if(select->extra)
                    memcpy (iter->extra->tag, select->extra->tag, 3);
                  if(select->attr)
                    {
                      if(iter->attr)
                        bgp_attr_unintern(&iter->attr);
                      iter->attr = bgp_attr_intern (select->attr);
                      if(select->attr->extra && select->attr->extra->ecommunity)
                        {
                          bgp_attr_extra_get(iter->attr);
                          iter->attr->extra->ecommunity =
                            ecommunity_dup(select->attr->extra->ecommunity);
                        }
                    }
                  /* if changes, update, and permit resending
                     information */
                  bgp_info_set_flag (rn, iter, BGP_INFO_ATTR_CHANGED);
                }
              break;
            }
        }
      /* silently add new entry to rn */
      if(!iter)
        {
          iter = info_make (select->type, select->sub_type, 0, select->peer, 
                            select->attr?bgp_attr_intern (select->attr):NULL,
                            vrf_rn);
          iter->extra = bgp_info_extra_new();
          iter->extra->vrf_rd = *prd;
          if (select->extra)
            memcpy (iter->extra->tag, select->extra->tag, 3);
          SET_FLAG (iter->flags, BGP_INFO_VALID);
          bgp_info_add (vrf_rn, iter);
          bgp_unlock_node (vrf_rn);
        }
      if (BGP_DEBUG(bgp_vrf, BGPVRF))
        {
          char nh_str[BUFSIZ] = "<?>";

          prefix2str(&rn->p, pfx_str, sizeof(pfx_str));
          if(iter->attr && iter->attr->extra)
            {
              if (afi == AFI_IP)
                strcpy (nh_str, inet_ntoa (iter->attr->extra->mp_nexthop_global_in));
              else if (afi == AFI_IP6)
                inet_ntop (AF_INET6, &iter->attr->extra->mp_nexthop_global, nh_str, BUFSIZ);
            }
          else
            {
              inet_ntop (AF_INET, &iter->attr->nexthop,
                         nh_str, sizeof (nh_str));
            }
          zlog_debug ("%s: processing entry (for %s) from %s [ nh %s]",
                      pfx_str, action == BGP_VRF_IMPORT_ROUTE_INFO_TO_UPDATE?"upgrading":"adding",
                      iter->peer->host, nh_str);

        }
      bgp_process (iter->peer->bgp, vrf_rn, afi, SAFI_UNICAST);
    }
}

/* propagates a change in the BGP per VRF tables,
 * according to import export rules contained:
 * - in bgp vrf configuration
 * - in Route Target extended communities
 * result stands for a new ri to add, an old ri to suppress,
 * or an change in the ri itself. for latter case, old ri is
 * not attached
 */
void
bgp_vrf_process_imports (struct bgp *bgp, afi_t afi, safi_t safi,
                         struct bgp_node *rn,
                         struct bgp_info *old_select,
                         struct bgp_info *new_select)
{
  struct ecommunity *old_ecom = NULL, *new_ecom = NULL;
  struct bgp_vrf *vrf;
  struct listnode *node;
  size_t i, j;
  struct prefix_rd *prd;
  int action;
  struct bgp_info *ri;

  if (safi != SAFI_MPLS_VPN)
    return;

  prd = &bgp_node_table (rn)->prd;
  if(new_select && !old_select)
    {
      ri = new_select;
      action = BGP_VRF_IMPORT_ROUTE_INFO_TO_ADD;
    }
  else if(!new_select && old_select)
    {
      ri = old_select;
      action = BGP_VRF_IMPORT_ROUTE_INFO_TO_REMOVE;
    }
  else
    {
      /* old_select set to null */
      old_select = NULL;
      ri = new_select;
      action = BGP_VRF_IMPORT_ROUTE_INFO_TO_UPDATE;
    }

  if (old_select && old_select->attr && old_select->attr->extra)
    old_ecom = old_select->attr->extra->ecommunity;
  if (new_select && new_select->attr && new_select->attr->extra)
    new_ecom = new_select->attr->extra->ecommunity;

  if (old_select
      && old_select->type == ZEBRA_ROUTE_BGP
      && old_select->sub_type == BGP_ROUTE_STATIC
      && (!new_select
          || !new_select->type == ZEBRA_ROUTE_BGP
          || !new_select->sub_type == BGP_ROUTE_STATIC))
    for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
      if (!prefix_cmp((struct prefix*)&vrf->outbound_rd,
                      (struct prefix*)prd))
        bgp_vrf_process_one(vrf, afi, safi, rn, ri, action);

  if (old_ecom)
    for (i = 0; i < (size_t)old_ecom->size; i++)
      {
        struct bgp_rt_sub dummy, *rt_sub;
        uint8_t *val = old_ecom->val + 8 * i;
        uint8_t type = val[1];
        bool withdraw = true;

        if (type != ECOMMUNITY_ROUTE_TARGET)
          continue;

        memcpy(&dummy.rt, val, 8);
        rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
        if (!rt_sub)
          continue;

        if (new_ecom)
          for (j = 0; j < (size_t)new_ecom->size; j++)
            if (!memcmp(new_ecom->val + j * 8, val, 8))
              {
                withdraw = false;
                break;
              }

        for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
          bgp_vrf_process_one (vrf, afi, safi, rn, ri, withdraw == false?
                               BGP_VRF_IMPORT_ROUTE_INFO_TO_UPDATE:
                               BGP_VRF_IMPORT_ROUTE_INFO_TO_REMOVE);
      }

  if (new_ecom)
    for (i = 0; i < (size_t)new_ecom->size; i++)
      {
        struct bgp_rt_sub dummy, *rt_sub;
        uint8_t *val = new_ecom->val + 8 * i;
        uint8_t type = val[1];
        bool found = false;

        if (type != ECOMMUNITY_ROUTE_TARGET)
          continue;

        memcpy(&dummy.rt, val, 8);
        rt_sub = hash_lookup (bgp->rt_subscribers, &dummy);
        if (!rt_sub)
          continue;

        if (old_ecom)
          for (j = 0; j < (size_t)old_ecom->size; j++)
            if (!memcmp(old_ecom->val + j * 8, val, 8))
              {
                found = true;
                break;
              }

        if (!found)
          for (ALL_LIST_ELEMENTS_RO(rt_sub->vrfs, node, vrf))
            bgp_vrf_process_one (vrf, afi, safi, rn, ri, action);
      }

  if (new_select
      && new_select->type == ZEBRA_ROUTE_BGP
      && new_select->sub_type == BGP_ROUTE_STATIC)
    for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
      if (!prefix_cmp((struct prefix*)&vrf->outbound_rd,
                      (struct prefix*)prd))
        bgp_vrf_process_one(vrf, afi, safi, rn, ri, action);
}

/* VTY configuration and exploitation */

DEFUN (bgp_vrf,
       bgp_vrf_cmd,
       "vrf WORD",
       "BGP VRF\n"
       "VRF Name\n"
)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  struct bgp_vrf *vrf;
  if ( (vrf = bgp_vrf_lookup_per_name (bgp, (const char *)argv[1]->arg, 1)) == NULL)
    return CMD_ERR_NO_MATCH;
  VTY_PUSH_CONTEXT_SUB (BGP_VRF_NODE, vrf);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_vrf,
       no_bgp_vrf_cmd,
       "no vrf WORD",
       NO_STR
       "BGP VRF\n"
       "VRF Name\n"
)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  struct bgp_vrf *vrf;

  vrf = bgp_vrf_lookup_per_name (bgp, argv[2]->arg, 0);
  if (! vrf)
    {
      vty_out (vty, "%% No VRF with name '%s'%s", argv[2]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  bgp_vrf_context_delete (vrf);
  return CMD_SUCCESS;
}

DEFUN (exit_bgp_vrf,
       exit_bgp_vrf_cmd,
       "exit-bgp-vrf",
       "Exit from BGP vrf configuration mode\n")
{
  if (vty->node == BGP_VRF_NODE)
    vty->node = BGP_NODE;
  return CMD_SUCCESS;
}

DEFUN (bgp_vrf_rd,
       bgp_vrf_rd_cmd,
       "rd WORD",
       "Route Distinguisher\n"
       "Route Distinguisher Name\n"
)
{
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  struct prefix_rd prd;

  if (! str2prefix_rd (argv[1]->arg, &prd))
    {
      vty_out (vty, "%% Invalid RD '%s'%s", argv[1]->arg, VTY_NEWLINE);
      return CMD_WARNING;
    }
  bgp_vrf_update_rd (bgp, vrf, &prd);
  return CMD_SUCCESS;
}

DEFUN (bgp_vrf_rt_export,
       bgp_vrf_rt_export_cmd,
       "rt export LINE...",
       "Route Target\n"
       "Export RT values\n"
       "Export RT values\n"
)
{
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  struct ecommunity *ecom = NULL;
  int idx_line = 2;
  char *rts;


  /* forge export list */
  rts = argv_concat(argv, argc, idx_line);

  /* convert list of ecoms string into ecom struct */
  ecom = ecommunity_str2com (rts, ECOMMUNITY_ROUTE_TARGET, 0);
  if (! ecom)
    {
      vty_out (vty, "%% Invalid RT '%s'%s", rts, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (rts)
    XFREE (MTYPE_TMP, rts);

  ecom = ecommunity_intern (ecom);
  bgp_vrf_rt_export_set (vrf, ecom);
  ecommunity_unintern (&ecom);
  return CMD_SUCCESS;
}

DEFUN (bgp_vrf_rt_import,
       bgp_vrf_rt_import_cmd,
       "rt import LINE...",
       "Route Target\n"
       "Import RT values\n"
       "Import RT values\n"
)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);
  struct ecommunity *ecom = NULL;
  char *rts;
  int idx_line = 2;

  /* forge import list */
  rts = argv_concat(argv, argc, idx_line);

  /* convert list of ecoms string into ecom struct */
  ecom = ecommunity_str2com (rts, ECOMMUNITY_ROUTE_TARGET, 0);
  if (! ecom)
    {
      vty_out (vty, "%% Invalid RT '%s'%s", rts, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (rts)
    XFREE (MTYPE_TMP, rts);

  ecom = ecommunity_intern (ecom);
  bgp_vrf_rt_import_set (vrf, ecom);
  ecommunity_unintern (&ecom);
  return CMD_SUCCESS;
}

DEFUN (bgp_vrf_rt_both,
       bgp_vrf_rt_both_cmd,
       "rt both LINE...",
       "Route Target\n"
       "Import and Export RT values\n"
       "Import and Export RT values\n"
)
{
  VTY_DECLVAR_CONTEXT(bgp, bgp);
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);
  struct ecommunity *ecom = NULL, *ecom1;
  char *rts;
  int idx_line = 2;

  /* forge export/import list */
  rts = argv_concat(argv, argc, idx_line);

  /* convert list of ecoms string into ecom struct */
  ecom = ecommunity_str2com (rts, ECOMMUNITY_ROUTE_TARGET, 1);
  if (! ecom)
    {
      vty_out (vty, "%% Invalid RT '%s'%s", rts, VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (rts)
    XFREE (MTYPE_TMP, rts);

  ecom1 = ecommunity_intern (ecom);
  bgp_vrf_rt_import_set (vrf, ecom1);
  ecommunity_unintern (&ecom1);

  ecom1 = ecommunity_intern (ecom);
  bgp_vrf_rt_export_set (vrf, ecom1);
  ecommunity_unintern (&ecom1);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_vrf_rt_import,
       no_bgp_vrf_rt_import_cmd,
       "no rt import",
       NO_STR
       "Route Target\n"
       "Import values\n"
)
{
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);

  bgp_vrf_rt_import_unset (vrf);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_vrf_rt_export,
       no_bgp_vrf_rt_export_cmd,
       "no rt export",
       NO_STR
       "Route Target\n"
       "Export RT values\n"
)
{
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);

  bgp_vrf_rt_export_unset (vrf);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_vrf_rt_both,
       no_bgp_vrf_rt_both_cmd,
       "no rt both",
       NO_STR
       "Route Target\n"
       "Import and Export RT values\n"
)
{
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);

  bgp_vrf_rt_export_unset (vrf);
  bgp_vrf_rt_import_unset (vrf);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_vrf_rd,
       no_bgp_vrf_rd_cmd,
       "no rd WORD",
       NO_STR
       "BGP Route Distinguisher\n"
       "Route Distinguisher\n"
)
{
  VTY_DECLVAR_CONTEXT_SUB (bgp_vrf, vrf);

  bgp_vrf_delete_rd (vrf);
  return CMD_SUCCESS;
}

static int
bgp_show_vrf (struct vty *vty, const char *vrf_name, afi_t afi,
              enum bgp_show_type type, void *output_arg, u_char use_json)
{
  struct bgp *bgp = bgp_get_default();
  struct bgp_vrf *vrf;

  if (! bgp)
    {
      vty_out (vty, "%% No default BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vrf = bgp_vrf_lookup_per_name (bgp, vrf_name, 0);
  if (! vrf)
    {
      vty_out (vty, "%% No VRF with name '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_table (vty, bgp, vrf->rib[afi], type, output_arg, use_json);
}

static int
bgp_show_vrf_route (struct vty *vty, const char *vrf_name, const char *ip_str,
                    afi_t afi, int prefix_check,u_char use_json)
{
  struct bgp *bgp = bgp_get_default();
  struct bgp_vrf *vrf;

  if (! bgp)
    {
      vty_out (vty, "%% No default BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  vrf = bgp_vrf_lookup_per_name (bgp, vrf_name, 0);
  if (! vrf)
    {
      vty_out (vty, "%% No VRF with name '%s'%s", vrf_name, VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route_in_table (vty, bgp, vrf->rib[afi], ip_str,
                                  afi, SAFI_MPLS_LABELED_VPN, NULL,
                                  prefix_check, BGP_PATH_ALL, use_json);
}

DEFUN (show_ip_bgp_vrf,
       show_ip_bgp_vrf_cmd,
       "show ip bgp bgpvrf WORD [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP VRF"
       "BGP VRF Name"
       JSON_STR)
{
  return bgp_show_vrf (vty, argv[4]->arg, AFI_IP, bgp_show_type_normal, NULL, use_json(argc, argv));
}

DEFUN (show_ipv6_bgp_vrf,
       show_ipv6_bgp_vrf_cmd,
       "show ipv6 bgp bgpvrf WORD [json]",
       SHOW_STR
       "IPv6"
       BGP_STR
       "BGP VRF"
       "BGP VRF Name"
       JSON_STR)
{
  return bgp_show_vrf (vty, argv[4]->arg, AFI_IP6, bgp_show_type_normal, NULL, use_json(argc, argv));
}

DEFUN (show_ip_bgp_vrf_route,
       show_ip_bgp_vrf_route_cmd,
       "show ip bgp bgpvrf WORD A.B.C.D [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "VRF\n"
       "BGP VRF Name\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       JSON_STR)
{
  return bgp_show_vrf_route (vty, argv[4]->arg, argv[5]->arg, AFI_IP, 0, use_json (argc,argv));
}

DEFUN (show_ipv6_bgp_vrf_route,
       show_ipv6_bgp_vrf_route_cmd,
       "show ipv6 bgp bgpvrf WORD X:X::X:X [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       "VRF\n"
       "BGP VRF Name\n"
       "IPv6 prefix <network>/<length>\n"
       "JavaScript Object Notation\n")
{
  return bgp_show_vrf_route (vty, argv[4]->arg, argv[5]->arg, AFI_IP6, 0, use_json (argc,argv));
}

DEFUN (debug_bgp_vrf,
       debug_bgp_vrf_cmd,
       "debug bgp vrf",
       DEBUG_STR
       BGP_STR
       "BGP VRF Changes\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_ON (bgp_vrf, BGPVRF);
  else
    {
      TERM_DEBUG_ON (bgp_vrf, BGPVRF);
      vty_out (vty, "BGP VRF debugging is on%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_bgp_vrf,
       no_debug_bgp_vrf_cmd,
       "no debug bgp vrf",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP VRF changes\n")
{
  if (vty->node == CONFIG_NODE)
    DEBUG_OFF (bgp_vrf, BGPVRF);
  else
    {
      TERM_DEBUG_OFF (bgp_vrf, BGPVRF);
      vty_out (vty, "BGP vrf debugging is off%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

/* BGP VRF init/delete/ show running */
void
bgp_bgpvrf_init (struct bgp *bgp)
{
  bgp->vrfs = list_new();
  bgp->vrfs->del = bgp_vrf_delete_int;
  bgp->rt_subscribers = hash_create(bgp_rt_hash_key, bgp_rt_hash_cmp);

}

void bgp_bgpvrf_vty (void)
{
  install_node (&bgp_vrf_node, NULL);
  install_default (BGP_VRF_NODE);

  install_element (BGP_NODE, &bgp_vrf_cmd);
  install_element (BGP_NODE, &no_bgp_vrf_cmd);
  install_element (BGP_VRF_NODE, &bgp_vrf_rd_cmd);
  install_element (BGP_VRF_NODE, &no_bgp_vrf_rd_cmd);
  install_element (BGP_VRF_NODE, &bgp_vrf_rt_export_cmd);
  install_element (BGP_VRF_NODE, &bgp_vrf_rt_import_cmd);
  install_element (BGP_VRF_NODE, &bgp_vrf_rt_both_cmd);
  install_element (BGP_VRF_NODE, &no_bgp_vrf_rt_import_cmd);
  install_element (BGP_VRF_NODE, &no_bgp_vrf_rt_export_cmd);
  install_element (BGP_VRF_NODE, &no_bgp_vrf_rt_both_cmd);
  install_element (BGP_VRF_NODE, &exit_bgp_vrf_cmd);

  install_element (VIEW_NODE, &show_ip_bgp_vrf_cmd);
  install_element (VIEW_NODE, &show_ip_bgp_vrf_route_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_cmd);
  install_element (VIEW_NODE, &show_ipv6_bgp_vrf_route_cmd);

  install_element (ENABLE_NODE, &debug_bgp_vrf_cmd);
  install_element (CONFIG_NODE, &no_debug_bgp_vrf_cmd);

}

void
bgp_bgpvrf_delete (struct bgp *bgp)
{
  if(bgp->vrfs)
    list_delete (bgp->vrfs);
  bgp->vrfs = NULL;
  if(bgp->rt_subscribers)
    {
      hash_clean (bgp->rt_subscribers, NULL);
      hash_free (bgp->rt_subscribers);
      bgp->rt_subscribers = NULL;
    }
}

void bgp_config_write_bgpvrf (struct vty *vty, struct bgp *bgp)
{
  struct bgp_vrf *vrf;
  char rdstr[RD_ADDRSTRLEN];
  char *str_p, *str2_p;
  struct listnode *node;
  
  for (ALL_LIST_ELEMENTS_RO(bgp->vrfs, node, vrf))
    {
      vty_out(vty, " vrf %s%s", vrf->name, VTY_NEWLINE);
      /* an RD has been configured */
      if (!(vrf->flag & BGP_VRF_RD_UNSET))
        {
          str_p = prefix_rd2str(&(vrf->outbound_rd), rdstr, RD_ADDRSTRLEN);
          vty_out(vty, "  rd %s%s", str_p == NULL?"<err>":str_p, VTY_NEWLINE);
        }
      if(vrf->rt_import)
        {
          str2_p = ecommunity_ecom2str (vrf->rt_import, ECOMMUNITY_FORMAT_ROUTE_MAP);
          if(str2_p)
            {
              vty_out(vty, "  rt import %s%s", str2_p, VTY_NEWLINE);
              XFREE (MTYPE_ECOMMUNITY_STR, str2_p);
            }
        }
      if(vrf->rt_export)
        {
          str2_p = ecommunity_ecom2str (vrf->rt_export, ECOMMUNITY_FORMAT_ROUTE_MAP);
          if(str2_p)
            {
              vty_out(vty, "  rt export %s%s", str2_p, VTY_NEWLINE);
              XFREE (MTYPE_ECOMMUNITY_STR, str2_p);
            }
        }
      vty_out (vty, " exit%s", VTY_NEWLINE);
    }
}
