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

static int
bgp_show_vrf (struct vty *vty, const char *vrf_name, afi_t afi,
              enum bgp_show_type type, void *output_arg, u_char use_json);

static int
bgp_show_vrf_route (struct vty *vty, const char *vrf_name, const char *ip_str,
                    afi_t afi, int prefix_check,u_char use_json);

/* for vty access to bgp vrf node */
DEFINE_QOBJ_TYPE(bgp_vrf)

/* for vty config, BGP VRF node. */
static struct cmd_node bgp_vrf_node =
{
  BGP_VRF_NODE,
  "%s(bgp-vrf)# ",
  1
};

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

void
bgp_vrf_apply_new_imports (struct bgp_vrf *vrf, afi_t afi)
{
  struct bgp_node *rd_rn, *rn;
  struct bgp_info *sel;
  struct bgp_table *table;
  struct ecommunity *ecom;
  size_t i, j;
  bool found;

  if (!vrf->rt_import || vrf->rt_import->size == 0)
    return;

  for (rd_rn = bgp_table_top (vrf->bgp->rib[afi][SAFI_MPLS_VPN]); rd_rn;
                  rd_rn = bgp_route_next (rd_rn))
    if (rd_rn->info != NULL)
      {
        table = rd_rn->info;

        for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
          {
            for (sel = rn->info; sel; sel = sel->next)
              if (CHECK_FLAG (sel->flags, BGP_INFO_SELECTED))
                break;
            if (!sel || !sel->attr || !sel->attr->extra)
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
          }
      }
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

/* BGP VRF init/delete/ show running */
void
bgp_bgpvrf_init (struct bgp *bgp)
{
  bgp->vrfs = list_new();
  bgp->vrfs->del = bgp_vrf_delete_int;
  bgp->rt_subscribers = hash_create(bgp_rt_hash_key, bgp_rt_hash_cmp);

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
