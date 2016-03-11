/*
 * IS-IS Rout(e)ing protocol - isisd.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "time.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "stream.h"
#include "prefix.h"
#include "table.h"
#include "qobj.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_csm.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_events.h"
#include "isisd/isis_te.h"

#ifdef TOPOLOGY_GENERATE
#include "spgrid.h"
u_char DEFAULT_TOPOLOGY_BASEIS[6] = { 0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00 };
#endif /* TOPOLOGY_GENERATE */

struct isis *isis = NULL;

DEFINE_QOBJ_TYPE(isis)
DEFINE_QOBJ_TYPE(isis_area)

/*
 * Prototypes.
 */
int isis_area_get(struct vty *, const char *);
int isis_area_destroy(struct vty *, const char *);
int area_net_title(struct vty *, const char *);
int area_clear_net_title(struct vty *, const char *);
int show_isis_interface_common(struct vty *, const char *ifname, char);
int show_isis_neighbor_common(struct vty *, const char *id, char);
int clear_isis_neighbor_common(struct vty *, const char *id);
int isis_config_write(struct vty *);



void
isis_new (unsigned long process_id)
{
  isis = XCALLOC (MTYPE_ISIS, sizeof (struct isis));
  /*
   * Default values
   */
  isis->max_area_addrs = 3;
  isis->process_id = process_id;
  isis->router_id = 0;
  isis->area_list = list_new ();
  isis->init_circ_list = list_new ();
  isis->uptime = time (NULL);
  isis->nexthops = list_new ();
#ifdef HAVE_IPV6
  isis->nexthops6 = list_new ();
#endif /* HAVE_IPV6 */
  dyn_cache_init ();
  /*
   * uncomment the next line for full debugs
   */
  /* isis->debugs = 0xFFFF; */
  isisMplsTE.status = disable;            /* Only support TE metric */
  QOBJ_REG (isis, isis);
}

struct isis_area *
isis_area_create (const char *area_tag)
{
  struct isis_area *area;

  area = XCALLOC (MTYPE_ISIS_AREA, sizeof (struct isis_area));

  /*
   * The first instance is level-1-2 rest are level-1, unless otherwise
   * configured
   */
  if (listcount (isis->area_list) > 0)
    area->is_type = IS_LEVEL_1;
  else
    area->is_type = IS_LEVEL_1_AND_2;

  /*
   * intialize the databases
   */
  if (area->is_type & IS_LEVEL_1)
    {
      area->lspdb[0] = lsp_db_init ();
      area->route_table[0] = route_table_init ();
#ifdef HAVE_IPV6
      area->route_table6[0] = route_table_init ();
#endif /* HAVE_IPV6 */
    }
  if (area->is_type & IS_LEVEL_2)
    {
      area->lspdb[1] = lsp_db_init ();
      area->route_table[1] = route_table_init ();
#ifdef HAVE_IPV6
      area->route_table6[1] = route_table_init ();
#endif /* HAVE_IPV6 */
    }

  spftree_area_init (area);

  area->circuit_list = list_new ();
  area->area_addrs = list_new ();
  THREAD_TIMER_ON (master, area->t_tick, lsp_tick, area, 1);
  flags_initialize (&area->flags);

  /*
   * Default values
   */
  area->max_lsp_lifetime[0] = DEFAULT_LSP_LIFETIME;	/* 1200 */
  area->max_lsp_lifetime[1] = DEFAULT_LSP_LIFETIME;	/* 1200 */
  area->lsp_refresh[0] = DEFAULT_MAX_LSP_GEN_INTERVAL;	/* 900 */
  area->lsp_refresh[1] = DEFAULT_MAX_LSP_GEN_INTERVAL;	/* 900 */
  area->lsp_gen_interval[0] = DEFAULT_MIN_LSP_GEN_INTERVAL;
  area->lsp_gen_interval[1] = DEFAULT_MIN_LSP_GEN_INTERVAL;
  area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
  area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;
  area->dynhostname = 1;
  area->oldmetric = 0;
  area->newmetric = 1;
  area->lsp_frag_threshold = 90;
  area->lsp_mtu = DEFAULT_LSP_MTU;
#ifdef TOPOLOGY_GENERATE
  memcpy (area->topology_baseis, DEFAULT_TOPOLOGY_BASEIS, ISIS_SYS_ID_LEN);
#endif /* TOPOLOGY_GENERATE */

  area->area_tag = strdup (area_tag);
  listnode_add (isis->area_list, area);
  area->isis = isis;

  QOBJ_REG (area, isis_area);

  return area;
}

struct isis_area *
isis_area_lookup (const char *area_tag)
{
  struct isis_area *area;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    if ((area->area_tag == NULL && area_tag == NULL) ||
	(area->area_tag && area_tag
	 && strcmp (area->area_tag, area_tag) == 0))
    return area;

  return NULL;
}

int
isis_area_get (struct vty *vty, const char *area_tag)
{
  struct isis_area *area;

  area = isis_area_lookup (area_tag);

  if (area)
    {
      VTY_PUSH_CONTEXT (ISIS_NODE, area);
      return CMD_SUCCESS;
    }

  area = isis_area_create (area_tag);

  if (isis->debugs & DEBUG_EVENTS)
    zlog_debug ("New IS-IS area instance %s", area->area_tag);

  VTY_PUSH_CONTEXT (ISIS_NODE, area);

  return CMD_SUCCESS;
}

int
isis_area_destroy (struct vty *vty, const char *area_tag)
{
  struct isis_area *area;
  struct listnode *node, *nnode;
  struct isis_circuit *circuit;
  struct area_addr *addr;

  area = isis_area_lookup (area_tag);

  if (area == NULL)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  QOBJ_UNREG (area);

  if (area->circuit_list)
    {
      for (ALL_LIST_ELEMENTS (area->circuit_list, node, nnode, circuit))
        {
          circuit->ip_router = 0;
#ifdef HAVE_IPV6
          circuit->ipv6_router = 0;
#endif
          isis_csm_state_change (ISIS_DISABLE, circuit, area);
        }
      list_delete (area->circuit_list);
      area->circuit_list = NULL;
    }

  if (area->lspdb[0] != NULL)
    {
      lsp_db_destroy (area->lspdb[0]);
      area->lspdb[0] = NULL;
    }
  if (area->lspdb[1] != NULL)
    {
      lsp_db_destroy (area->lspdb[1]);
      area->lspdb[1] = NULL;
    }

  spftree_area_del (area);

  /* invalidate and validate would delete all routes from zebra */
  isis_route_invalidate (area);
  isis_route_validate (area);

  if (area->route_table[0])
    {
      route_table_finish (area->route_table[0]);
      area->route_table[0] = NULL;
    }
  if (area->route_table[1])
    {
      route_table_finish (area->route_table[1]);
      area->route_table[1] = NULL;
    }
#ifdef HAVE_IPV6
  if (area->route_table6[0])
    {
      route_table_finish (area->route_table6[0]);
      area->route_table6[0] = NULL;
    }
  if (area->route_table6[1])
    {
      route_table_finish (area->route_table6[1]);
      area->route_table6[1] = NULL;
    }
#endif /* HAVE_IPV6 */

  isis_redist_area_finish(area);

  for (ALL_LIST_ELEMENTS (area->area_addrs, node, nnode, addr))
    {
      list_delete_node (area->area_addrs, node);
      XFREE (MTYPE_ISIS_AREA_ADDR, addr);
    }
  area->area_addrs = NULL;

  THREAD_TIMER_OFF (area->t_tick);
  THREAD_TIMER_OFF (area->t_lsp_refresh[0]);
  THREAD_TIMER_OFF (area->t_lsp_refresh[1]);

  thread_cancel_event (master, area);

  listnode_delete (isis->area_list, area);

  free (area->area_tag);

  XFREE (MTYPE_ISIS_AREA, area);

  if (listcount (isis->area_list) == 0)
    {
      memset (isis->sysid, 0, ISIS_SYS_ID_LEN);
      isis->sysid_set = 0;
    }

  return CMD_SUCCESS;
}

int
area_net_title (struct vty *vty, const char *net_title)
{
  VTY_DECLVAR_CONTEXT (isis_area, area);
  struct area_addr *addr;
  struct area_addr *addrp;
  struct listnode *node;

  u_char buff[255];

  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  /* We check that we are not over the maximal number of addresses */
  if (listcount (area->area_addrs) >= isis->max_area_addrs)
    {
      vty_out (vty, "Maximum of area addresses (%d) already reached %s",
	       isis->max_area_addrs, VTY_NEWLINE);
      return CMD_ERR_NOTHING_TODO;
    }

  addr = XMALLOC (MTYPE_ISIS_AREA_ADDR, sizeof (struct area_addr));
  addr->addr_len = dotformat2buff (buff, net_title);
  memcpy (addr->area_addr, buff, addr->addr_len);
#ifdef EXTREME_DEBUG
  zlog_debug ("added area address %s for area %s (address length %d)",
	     net_title, area->area_tag, addr->addr_len);
#endif /* EXTREME_DEBUG */
  if (addr->addr_len < 8 || addr->addr_len > 20)
    {
      vty_out (vty, "area address must be at least 8..20 octets long (%d)%s",
               addr->addr_len, VTY_NEWLINE);
      XFREE (MTYPE_ISIS_AREA_ADDR, addr);
      return CMD_ERR_AMBIGUOUS;
    }

  if (addr->area_addr[addr->addr_len-1] != 0)
    {
      vty_out (vty, "nsel byte (last byte) in area address must be 0%s",
               VTY_NEWLINE);
      XFREE (MTYPE_ISIS_AREA_ADDR, addr);
      return CMD_ERR_AMBIGUOUS;
    }

  if (isis->sysid_set == 0)
    {
      /*
       * First area address - get the SystemID for this router
       */
      memcpy (isis->sysid, GETSYSID (addr), ISIS_SYS_ID_LEN);
      isis->sysid_set = 1;
      if (isis->debugs & DEBUG_EVENTS)
	zlog_debug ("Router has SystemID %s", sysid_print (isis->sysid));
    }
  else
    {
      /*
       * Check that the SystemID portions match
       */
      if (memcmp (isis->sysid, GETSYSID (addr), ISIS_SYS_ID_LEN))
	{
	  vty_out (vty,
		   "System ID must not change when defining additional area"
		   " addresses%s", VTY_NEWLINE);
	  XFREE (MTYPE_ISIS_AREA_ADDR, addr);
	  return CMD_ERR_AMBIGUOUS;
	}

      /* now we see that we don't already have this address */
      for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node, addrp))
	{
	  if ((addrp->addr_len + ISIS_SYS_ID_LEN + ISIS_NSEL_LEN) != (addr->addr_len))
	    continue;
	  if (!memcmp (addrp->area_addr, addr->area_addr, addr->addr_len))
	    {
	      XFREE (MTYPE_ISIS_AREA_ADDR, addr);
	      return CMD_SUCCESS;	/* silent fail */
	    }
	}
    }

  /*
   * Forget the systemID part of the address
   */
  addr->addr_len -= (ISIS_SYS_ID_LEN + ISIS_NSEL_LEN);
  listnode_add (area->area_addrs, addr);

  /* only now we can safely generate our LSPs for this area */
  if (listcount (area->area_addrs) > 0)
    {
      if (area->is_type & IS_LEVEL_1)
        lsp_generate (area, IS_LEVEL_1);
      if (area->is_type & IS_LEVEL_2)
        lsp_generate (area, IS_LEVEL_2);
    }

  return CMD_SUCCESS;
}

int
area_clear_net_title (struct vty *vty, const char *net_title)
{
  VTY_DECLVAR_CONTEXT (isis_area, area);
  struct area_addr addr, *addrp = NULL;
  struct listnode *node;
  u_char buff[255];

  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  addr.addr_len = dotformat2buff (buff, net_title);
  if (addr.addr_len < 8 || addr.addr_len > 20)
    {
      vty_out (vty, "Unsupported area address length %d, should be 8...20 %s",
	       addr.addr_len, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  memcpy (addr.area_addr, buff, (int) addr.addr_len);

  for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node, addrp))
    if ((addrp->addr_len + ISIS_SYS_ID_LEN + 1) == addr.addr_len &&
	!memcmp (addrp->area_addr, addr.area_addr, addr.addr_len))
    break;

  if (!addrp)
    {
      vty_out (vty, "No area address %s for area %s %s", net_title,
	       area->area_tag, VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  listnode_delete (area->area_addrs, addrp);
  XFREE (MTYPE_ISIS_AREA_ADDR, addrp);

  /*
   * Last area address - reset the SystemID for this router
   */
  if (listcount (area->area_addrs) == 0)
    {
      memset (isis->sysid, 0, ISIS_SYS_ID_LEN);
      isis->sysid_set = 0;
      if (isis->debugs & DEBUG_EVENTS)
        zlog_debug ("Router has no SystemID");
    }

  return CMD_SUCCESS;
}

/*
 * 'show isis interface' command
 */

int
show_isis_interface_common (struct vty *vty, const char *ifname, char detail)
{
  struct listnode *anode, *cnode;
  struct isis_area *area;
  struct isis_circuit *circuit;

  if (!isis)
    {
      vty_out (vty, "IS-IS Routing Process not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, anode, area))
    {
      vty_out (vty, "Area %s:%s", area->area_tag, VTY_NEWLINE);

      if (detail == ISIS_UI_LEVEL_BRIEF)
        vty_out (vty, "  Interface   CircId   State    Type     Level%s",
                 VTY_NEWLINE);

      for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit))
        if (!ifname)
          isis_circuit_print_vty (circuit, vty, detail);
        else if (strcmp(circuit->interface->name, ifname) == 0)
          isis_circuit_print_vty (circuit, vty, detail);
    }

  return CMD_SUCCESS;
}

DEFUN (show_isis_interface,
       show_isis_interface_cmd,
       "show isis interface",
       SHOW_STR
       "ISIS network information\n"
       "ISIS interface\n")
{
  return show_isis_interface_common (vty, NULL, ISIS_UI_LEVEL_BRIEF);
}

DEFUN (show_isis_interface_detail,
       show_isis_interface_detail_cmd,
       "show isis interface detail",
       SHOW_STR
       "ISIS network information\n"
       "ISIS interface\n"
       "show detailed information\n")
{
  return show_isis_interface_common (vty, NULL, ISIS_UI_LEVEL_DETAIL);
}

DEFUN (show_isis_interface_arg,
       show_isis_interface_arg_cmd,
       "show isis interface WORD",
       SHOW_STR
       "ISIS network information\n"
       "ISIS interface\n"
       "ISIS interface name\n")
{
  return show_isis_interface_common (vty, argv[0], ISIS_UI_LEVEL_DETAIL);
}

/*
 * 'show isis neighbor' command
 */

int
show_isis_neighbor_common (struct vty *vty, const char *id, char detail)
{
  struct listnode *anode, *cnode, *node;
  struct isis_area *area;
  struct isis_circuit *circuit;
  struct list *adjdb;
  struct isis_adjacency *adj;
  struct isis_dynhn *dynhn;
  u_char sysid[ISIS_SYS_ID_LEN];
  int i;

  if (!isis)
    {
      vty_out (vty, "IS-IS Routing Process not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  memset (sysid, 0, ISIS_SYS_ID_LEN);
  if (id)
    {
      if (sysid2buff (sysid, id) == 0)
        {
          dynhn = dynhn_find_by_name (id);
          if (dynhn == NULL)
            {
              vty_out (vty, "Invalid system id %s%s", id, VTY_NEWLINE);
              return CMD_SUCCESS;
            }
          memcpy (sysid, dynhn->id, ISIS_SYS_ID_LEN);
        }
    }

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, anode, area))
    {
      vty_out (vty, "Area %s:%s", area->area_tag, VTY_NEWLINE);

      if (detail == ISIS_UI_LEVEL_BRIEF)
        vty_out (vty, "  System Id           Interface   L  State"
                      "        Holdtime SNPA%s", VTY_NEWLINE);

      for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit))
        {
          if (circuit->circ_type == CIRCUIT_T_BROADCAST)
            {
              for (i = 0; i < 2; i++)
                {
                  adjdb = circuit->u.bc.adjdb[i];
                  if (adjdb && adjdb->count)
                    {
                      for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
                        if (!id || !memcmp (adj->sysid, sysid,
                                            ISIS_SYS_ID_LEN))
                          isis_adj_print_vty (adj, vty, detail);
                    }
                }
            }
          else if (circuit->circ_type == CIRCUIT_T_P2P &&
                   circuit->u.p2p.neighbor)
            {
              adj = circuit->u.p2p.neighbor;
              if (!id || !memcmp (adj->sysid, sysid, ISIS_SYS_ID_LEN))
                isis_adj_print_vty (adj, vty, detail);
            }
        }
    }

  return CMD_SUCCESS;
}

/*
 * 'clear isis neighbor' command
 */
int
clear_isis_neighbor_common (struct vty *vty, const char *id)
{
  struct listnode *anode, *cnode, *cnextnode, *node, *nnode;
  struct isis_area *area;
  struct isis_circuit *circuit;
  struct list *adjdb;
  struct isis_adjacency *adj;
  struct isis_dynhn *dynhn;
  u_char sysid[ISIS_SYS_ID_LEN];
  int i;

  if (!isis)
    {
      vty_out (vty, "IS-IS Routing Process not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  memset (sysid, 0, ISIS_SYS_ID_LEN);
  if (id)
    {
      if (sysid2buff (sysid, id) == 0)
        {
          dynhn = dynhn_find_by_name (id);
          if (dynhn == NULL)
            {
              vty_out (vty, "Invalid system id %s%s", id, VTY_NEWLINE);
              return CMD_SUCCESS;
            }
          memcpy (sysid, dynhn->id, ISIS_SYS_ID_LEN);
        }
    }

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, anode, area))
    {
      for (ALL_LIST_ELEMENTS (area->circuit_list, cnode, cnextnode, circuit))
        {
          if (circuit->circ_type == CIRCUIT_T_BROADCAST)
            {
              for (i = 0; i < 2; i++)
                {
                  adjdb = circuit->u.bc.adjdb[i];
                  if (adjdb && adjdb->count)
                    {
                      for (ALL_LIST_ELEMENTS (adjdb, node, nnode, adj))
                        if (!id || !memcmp (adj->sysid, sysid, ISIS_SYS_ID_LEN))
                          isis_adj_state_change (adj, ISIS_ADJ_DOWN,
                                                 "clear user request");
                    }
                }
            }
          else if (circuit->circ_type == CIRCUIT_T_P2P &&
                   circuit->u.p2p.neighbor)
            {
              adj = circuit->u.p2p.neighbor;
              if (!id || !memcmp (adj->sysid, sysid, ISIS_SYS_ID_LEN))
                isis_adj_state_change (adj, ISIS_ADJ_DOWN,
                                       "clear user request");
            }
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_isis_neighbor,
       show_isis_neighbor_cmd,
       "show isis neighbor",
       SHOW_STR
       "ISIS network information\n"
       "ISIS neighbor adjacencies\n")
{
  return show_isis_neighbor_common (vty, NULL, ISIS_UI_LEVEL_BRIEF);
}

DEFUN (show_isis_neighbor_detail,
       show_isis_neighbor_detail_cmd,
       "show isis neighbor detail",
       SHOW_STR
       "ISIS network information\n"
       "ISIS neighbor adjacencies\n"
       "show detailed information\n")
{
  return show_isis_neighbor_common (vty, NULL, ISIS_UI_LEVEL_DETAIL);
}

DEFUN (show_isis_neighbor_arg,
       show_isis_neighbor_arg_cmd,
       "show isis neighbor WORD",
       SHOW_STR
       "ISIS network information\n"
       "ISIS neighbor adjacencies\n"
       "System id\n")
{
  return show_isis_neighbor_common (vty, argv[0], ISIS_UI_LEVEL_DETAIL);
}

DEFUN (clear_isis_neighbor,
       clear_isis_neighbor_cmd,
       "clear isis neighbor",
       CLEAR_STR
       "Reset ISIS network information\n"
       "Reset ISIS neighbor adjacencies\n")
{
  return clear_isis_neighbor_common (vty, NULL);
}

DEFUN (clear_isis_neighbor_arg,
       clear_isis_neighbor_arg_cmd,
       "clear isis neighbor WORD",
       CLEAR_STR
       "ISIS network information\n"
       "ISIS neighbor adjacencies\n"
       "System id\n")
{
  return clear_isis_neighbor_common (vty, argv[0]);
}

/*
 * 'isis debug', 'show debugging'
 */
void
print_debug (struct vty *vty, int flags, int onoff)
{
  char onoffs[4];
  if (onoff)
    strcpy (onoffs, "on");
  else
    strcpy (onoffs, "off");

  if (flags & DEBUG_ADJ_PACKETS)
    vty_out (vty, "IS-IS Adjacency related packets debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_CHECKSUM_ERRORS)
    vty_out (vty, "IS-IS checksum errors debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_LOCAL_UPDATES)
    vty_out (vty, "IS-IS local updates debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_PROTOCOL_ERRORS)
    vty_out (vty, "IS-IS protocol errors debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_SNP_PACKETS)
    vty_out (vty, "IS-IS CSNP/PSNP packets debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_SPF_EVENTS)
    vty_out (vty, "IS-IS SPF events debugging is %s%s", onoffs, VTY_NEWLINE);
  if (flags & DEBUG_SPF_STATS)
    vty_out (vty, "IS-IS SPF Timing and Statistics Data debugging is %s%s",
	     onoffs, VTY_NEWLINE);
  if (flags & DEBUG_SPF_TRIGGERS)
    vty_out (vty, "IS-IS SPF triggering events debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_UPDATE_PACKETS)
    vty_out (vty, "IS-IS Update related packet debugging is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_RTE_EVENTS)
    vty_out (vty, "IS-IS Route related debuggin is %s%s", onoffs,
	     VTY_NEWLINE);
  if (flags & DEBUG_EVENTS)
    vty_out (vty, "IS-IS Event debugging is %s%s", onoffs, VTY_NEWLINE);
  if (flags & DEBUG_PACKET_DUMP)
    vty_out (vty, "IS-IS Packet dump debugging is %s%s", onoffs, VTY_NEWLINE);
  if (flags & DEBUG_LSP_GEN)
    vty_out (vty, "IS-IS LSP generation debugging is %s%s", onoffs, VTY_NEWLINE);
  if (flags & DEBUG_LSP_SCHED)
    vty_out (vty, "IS-IS LSP scheduling debugging is %s%s", onoffs, VTY_NEWLINE);
}

DEFUN (show_debugging,
       show_debugging_isis_cmd,
       "show debugging isis",
       SHOW_STR
       "State of each debugging option\n"
       ISIS_STR)
{
  if (isis->debugs) {
      vty_out (vty, "IS-IS:%s", VTY_NEWLINE);
      print_debug (vty, isis->debugs, 1);
  }
  return CMD_SUCCESS;
}

/* Debug node. */
static struct cmd_node debug_node = {
  DEBUG_NODE,
  "",
  1
};

static int
config_write_debug (struct vty *vty)
{
  int write = 0;
  int flags = isis->debugs;

  if (flags & DEBUG_ADJ_PACKETS)
    {
      vty_out (vty, "debug isis adj-packets%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_CHECKSUM_ERRORS)
    {
      vty_out (vty, "debug isis checksum-errors%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_LOCAL_UPDATES)
    {
      vty_out (vty, "debug isis local-updates%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_PROTOCOL_ERRORS)
    {
      vty_out (vty, "debug isis protocol-errors%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_SNP_PACKETS)
    {
      vty_out (vty, "debug isis snp-packets%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_SPF_EVENTS)
    {
      vty_out (vty, "debug isis spf-events%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_SPF_STATS)
    {
      vty_out (vty, "debug isis spf-statistics%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_SPF_TRIGGERS)
    {
      vty_out (vty, "debug isis spf-triggers%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_UPDATE_PACKETS)
    {
      vty_out (vty, "debug isis update-packets%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_RTE_EVENTS)
    {
      vty_out (vty, "debug isis route-events%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_EVENTS)
    {
      vty_out (vty, "debug isis events%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_PACKET_DUMP)
    {
      vty_out (vty, "debug isis packet-dump%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_LSP_GEN)
    {
      vty_out (vty, "debug isis lsp-gen%s", VTY_NEWLINE);
      write++;
    }
  if (flags & DEBUG_LSP_SCHED)
    {
      vty_out (vty, "debug isis lsp-sched%s", VTY_NEWLINE);
      write++;
    }

  return write;
}

DEFUN (debug_isis_adj,
       debug_isis_adj_cmd,
       "debug isis adj-packets",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS Adjacency related packets\n")
{
  isis->debugs |= DEBUG_ADJ_PACKETS;
  print_debug (vty, DEBUG_ADJ_PACKETS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_adj,
       no_debug_isis_adj_cmd,
       "no debug isis adj-packets",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS Adjacency related packets\n")
{
  isis->debugs &= ~DEBUG_ADJ_PACKETS;
  print_debug (vty, DEBUG_ADJ_PACKETS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_csum,
       debug_isis_csum_cmd,
       "debug isis checksum-errors",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS LSP checksum errors\n")
{
  isis->debugs |= DEBUG_CHECKSUM_ERRORS;
  print_debug (vty, DEBUG_CHECKSUM_ERRORS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_csum,
       no_debug_isis_csum_cmd,
       "no debug isis checksum-errors",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS LSP checksum errors\n")
{
  isis->debugs &= ~DEBUG_CHECKSUM_ERRORS;
  print_debug (vty, DEBUG_CHECKSUM_ERRORS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_lupd,
       debug_isis_lupd_cmd,
       "debug isis local-updates",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS local update packets\n")
{
  isis->debugs |= DEBUG_LOCAL_UPDATES;
  print_debug (vty, DEBUG_LOCAL_UPDATES, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_lupd,
       no_debug_isis_lupd_cmd,
       "no debug isis local-updates",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS local update packets\n")
{
  isis->debugs &= ~DEBUG_LOCAL_UPDATES;
  print_debug (vty, DEBUG_LOCAL_UPDATES, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_err,
       debug_isis_err_cmd,
       "debug isis protocol-errors",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS LSP protocol errors\n")
{
  isis->debugs |= DEBUG_PROTOCOL_ERRORS;
  print_debug (vty, DEBUG_PROTOCOL_ERRORS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_err,
       no_debug_isis_err_cmd,
       "no debug isis protocol-errors",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS LSP protocol errors\n")
{
  isis->debugs &= ~DEBUG_PROTOCOL_ERRORS;
  print_debug (vty, DEBUG_PROTOCOL_ERRORS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_snp,
       debug_isis_snp_cmd,
       "debug isis snp-packets",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS CSNP/PSNP packets\n")
{
  isis->debugs |= DEBUG_SNP_PACKETS;
  print_debug (vty, DEBUG_SNP_PACKETS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_snp,
       no_debug_isis_snp_cmd,
       "no debug isis snp-packets",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS CSNP/PSNP packets\n")
{
  isis->debugs &= ~DEBUG_SNP_PACKETS;
  print_debug (vty, DEBUG_SNP_PACKETS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_upd,
       debug_isis_upd_cmd,
       "debug isis update-packets",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS Update related packets\n")
{
  isis->debugs |= DEBUG_UPDATE_PACKETS;
  print_debug (vty, DEBUG_UPDATE_PACKETS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_upd,
       no_debug_isis_upd_cmd,
       "no debug isis update-packets",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS Update related packets\n")
{
  isis->debugs &= ~DEBUG_UPDATE_PACKETS;
  print_debug (vty, DEBUG_UPDATE_PACKETS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_spfevents,
       debug_isis_spfevents_cmd,
       "debug isis spf-events",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS Shortest Path First Events\n")
{
  isis->debugs |= DEBUG_SPF_EVENTS;
  print_debug (vty, DEBUG_SPF_EVENTS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_spfevents,
       no_debug_isis_spfevents_cmd,
       "no debug isis spf-events",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS Shortest Path First Events\n")
{
  isis->debugs &= ~DEBUG_SPF_EVENTS;
  print_debug (vty, DEBUG_SPF_EVENTS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_spfstats,
       debug_isis_spfstats_cmd,
       "debug isis spf-statistics ",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS SPF Timing and Statistic Data\n")
{
  isis->debugs |= DEBUG_SPF_STATS;
  print_debug (vty, DEBUG_SPF_STATS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_spfstats,
       no_debug_isis_spfstats_cmd,
       "no debug isis spf-statistics",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS SPF Timing and Statistic Data\n")
{
  isis->debugs &= ~DEBUG_SPF_STATS;
  print_debug (vty, DEBUG_SPF_STATS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_spftrigg,
       debug_isis_spftrigg_cmd,
       "debug isis spf-triggers",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS SPF triggering events\n")
{
  isis->debugs |= DEBUG_SPF_TRIGGERS;
  print_debug (vty, DEBUG_SPF_TRIGGERS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_spftrigg,
       no_debug_isis_spftrigg_cmd,
       "no debug isis spf-triggers",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS SPF triggering events\n")
{
  isis->debugs &= ~DEBUG_SPF_TRIGGERS;
  print_debug (vty, DEBUG_SPF_TRIGGERS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_rtevents,
       debug_isis_rtevents_cmd,
       "debug isis route-events",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS Route related events\n")
{
  isis->debugs |= DEBUG_RTE_EVENTS;
  print_debug (vty, DEBUG_RTE_EVENTS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_rtevents,
       no_debug_isis_rtevents_cmd,
       "no debug isis route-events",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS Route related events\n")
{
  isis->debugs &= ~DEBUG_RTE_EVENTS;
  print_debug (vty, DEBUG_RTE_EVENTS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_events,
       debug_isis_events_cmd,
       "debug isis events",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS Events\n")
{
  isis->debugs |= DEBUG_EVENTS;
  print_debug (vty, DEBUG_EVENTS, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_events,
       no_debug_isis_events_cmd,
       "no debug isis events",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS Events\n")
{
  isis->debugs &= ~DEBUG_EVENTS;
  print_debug (vty, DEBUG_EVENTS, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_packet_dump,
       debug_isis_packet_dump_cmd,
       "debug isis packet-dump",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS packet dump\n")
{
  isis->debugs |= DEBUG_PACKET_DUMP;
  print_debug (vty, DEBUG_PACKET_DUMP, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_packet_dump,
       no_debug_isis_packet_dump_cmd,
       "no debug isis packet-dump",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS packet dump\n")
{
  isis->debugs &= ~DEBUG_PACKET_DUMP;
  print_debug (vty, DEBUG_PACKET_DUMP, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_lsp_gen,
       debug_isis_lsp_gen_cmd,
       "debug isis lsp-gen",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS generation of own LSPs\n")
{
  isis->debugs |= DEBUG_LSP_GEN;
  print_debug (vty, DEBUG_LSP_GEN, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_lsp_gen,
       no_debug_isis_lsp_gen_cmd,
       "no debug isis lsp-gen",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS generation of own LSPs\n")
{
  isis->debugs &= ~DEBUG_LSP_GEN;
  print_debug (vty, DEBUG_LSP_GEN, 0);

  return CMD_SUCCESS;
}

DEFUN (debug_isis_lsp_sched,
       debug_isis_lsp_sched_cmd,
       "debug isis lsp-sched",
       DEBUG_STR
       "IS-IS information\n"
       "IS-IS scheduling of LSP generation\n")
{
  isis->debugs |= DEBUG_LSP_SCHED;
  print_debug (vty, DEBUG_LSP_SCHED, 1);

  return CMD_SUCCESS;
}

DEFUN (no_debug_isis_lsp_sched,
       no_debug_isis_lsp_sched_cmd,
       "no debug isis lsp-sched",
       UNDEBUG_STR
       "IS-IS information\n"
       "IS-IS scheduling of LSP generation\n")
{
  isis->debugs &= ~DEBUG_LSP_SCHED;
  print_debug (vty, DEBUG_LSP_SCHED, 0);

  return CMD_SUCCESS;
}

DEFUN (show_hostname,
       show_hostname_cmd,
       "show isis hostname",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS Dynamic hostname mapping\n")
{
  dynhn_print_all (vty);

  return CMD_SUCCESS;
}

static void
vty_out_timestr(struct vty *vty, time_t uptime)
{
  struct tm *tm;
  time_t difftime = time (NULL);
  difftime -= uptime;
  tm = gmtime (&difftime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
  if (difftime < ONE_DAY_SECOND)
    vty_out (vty,  "%02d:%02d:%02d", 
        tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (difftime < ONE_WEEK_SECOND)
    vty_out (vty, "%dd%02dh%02dm", 
        tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    vty_out (vty, "%02dw%dd%02dh", 
        tm->tm_yday/7,
        tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
  vty_out (vty, " ago");
}

DEFUN (show_isis_summary,
       show_isis_summary_cmd,
       "show isis summary",
       SHOW_STR "IS-IS information\n" "IS-IS summary\n")
{
  struct listnode *node, *node2;
  struct isis_area *area;
  struct isis_spftree *spftree;
  int level;

  if (isis == NULL)
  {
    vty_out (vty, "ISIS is not running%s", VTY_NEWLINE);
    return CMD_SUCCESS;
  }

  vty_out (vty, "Process Id      : %ld%s", isis->process_id,
      VTY_NEWLINE);
  if (isis->sysid_set)
    vty_out (vty, "System Id       : %s%s", sysid_print (isis->sysid),
        VTY_NEWLINE);

  vty_out (vty, "Up time         : ");
  vty_out_timestr(vty, isis->uptime);
  vty_out (vty, "%s", VTY_NEWLINE);

  if (isis->area_list)
    vty_out (vty, "Number of areas : %d%s", isis->area_list->count,
        VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
  {
    vty_out (vty, "Area %s:%s", area->area_tag ? area->area_tag : "null",
        VTY_NEWLINE);

    if (listcount (area->area_addrs) > 0)
    {
      struct area_addr *area_addr;
      for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node2, area_addr))
      {
        vty_out (vty, "  Net: %s%s",
            isonet_print (area_addr->area_addr,
              area_addr->addr_len + ISIS_SYS_ID_LEN +
              1), VTY_NEWLINE);
      }
    }

    for (level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++)
    {
      if ((area->is_type & level) == 0)
        continue;

      vty_out (vty, "  Level-%d:%s", level, VTY_NEWLINE);
      spftree = area->spftree[level - 1];
      if (spftree->pending)
        vty_out (vty, "    IPv4 SPF: (pending)%s", VTY_NEWLINE);
      else
        vty_out (vty, "    IPv4 SPF:%s", VTY_NEWLINE);

      vty_out (vty, "      minimum interval  : %d%s",
          area->min_spf_interval[level - 1], VTY_NEWLINE);

      vty_out (vty, "      last run elapsed  : ");
      vty_out_timestr(vty, spftree->last_run_timestamp);
      vty_out (vty, "%s", VTY_NEWLINE);

      vty_out (vty, "      last run duration : %u usec%s",
               (u_int32_t)spftree->last_run_duration, VTY_NEWLINE);

      vty_out (vty, "      run count         : %d%s",
          spftree->runcount, VTY_NEWLINE);

#ifdef HAVE_IPV6
      spftree = area->spftree6[level - 1];
      if (spftree->pending)
        vty_out (vty, "    IPv6 SPF: (pending)%s", VTY_NEWLINE);
      else
        vty_out (vty, "    IPv6 SPF:%s", VTY_NEWLINE);

      vty_out (vty, "      minimum interval  : %d%s",
          area->min_spf_interval[level - 1], VTY_NEWLINE);

      vty_out (vty, "      last run elapsed  : ");
      vty_out_timestr(vty, spftree->last_run_timestamp);
      vty_out (vty, "%s", VTY_NEWLINE);

      vty_out (vty, "      last run duration : %llu msec%s",
               (unsigned long long)spftree->last_run_duration, VTY_NEWLINE);

      vty_out (vty, "      run count         : %d%s",
          spftree->runcount, VTY_NEWLINE);
#endif
    }
  }
  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

/*
 * This function supports following display options:
 * [ show isis database [detail] ]
 * [ show isis database <sysid> [detail] ]
 * [ show isis database <hostname> [detail] ]
 * [ show isis database <sysid>.<pseudo-id> [detail] ]
 * [ show isis database <hostname>.<pseudo-id> [detail] ]
 * [ show isis database <sysid>.<pseudo-id>-<fragment-number> [detail] ]
 * [ show isis database <hostname>.<pseudo-id>-<fragment-number> [detail] ]
 * [ show isis database detail <sysid> ]
 * [ show isis database detail <hostname> ]
 * [ show isis database detail <sysid>.<pseudo-id> ]
 * [ show isis database detail <hostname>.<pseudo-id> ]
 * [ show isis database detail <sysid>.<pseudo-id>-<fragment-number> ]
 * [ show isis database detail <hostname>.<pseudo-id>-<fragment-number> ]
 */
static int
show_isis_database (struct vty *vty, const char *argv, int ui_level)
{
  struct listnode *node;
  struct isis_area *area;
  struct isis_lsp *lsp;
  struct isis_dynhn *dynhn;
  const char *pos = argv;
  u_char lspid[ISIS_SYS_ID_LEN+2];
  char sysid[255];
  u_char number[3];
  int level, lsp_count;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  memset (&lspid, 0, ISIS_SYS_ID_LEN);
  memset (&sysid, 0, 255);

  /*
   * extract fragment and pseudo id from the string argv
   * in the forms:
   * (a) <systemid/hostname>.<pseudo-id>-<framenent> or
   * (b) <systemid/hostname>.<pseudo-id> or
   * (c) <systemid/hostname> or
   * Where systemid is in the form:
   * xxxx.xxxx.xxxx
   */
  if (argv)
     strncpy (sysid, argv, 254);
  if (argv && strlen (argv) > 3)
    {
      pos = argv + strlen (argv) - 3;
      if (strncmp (pos, "-", 1) == 0)
      {
        memcpy (number, ++pos, 2);
        lspid[ISIS_SYS_ID_LEN+1] = (u_char) strtol ((char *)number, NULL, 16);
        pos -= 4;
        if (strncmp (pos, ".", 1) != 0)
          return CMD_ERR_AMBIGUOUS;
      }
      if (strncmp (pos, ".", 1) == 0)
      {
        memcpy (number, ++pos, 2);
        lspid[ISIS_SYS_ID_LEN] = (u_char) strtol ((char *)number, NULL, 16);
        sysid[pos - argv - 1] = '\0';
      }
    }

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "Area %s:%s", area->area_tag ? area->area_tag : "null",
               VTY_NEWLINE);

      for (level = 0; level < ISIS_LEVELS; level++)
        {
          if (area->lspdb[level] && dict_count (area->lspdb[level]) > 0)
            {
              lsp = NULL;
              if (argv != NULL)
                {
                  /*
                   * Try to find the lsp-id if the argv string is in
                   * the form hostname.<pseudo-id>-<fragment>
                   */
                  if (sysid2buff (lspid, sysid))
                    {
                      lsp = lsp_search (lspid, area->lspdb[level]);
                    }
                  else if ((dynhn = dynhn_find_by_name (sysid)))
                    {
                      memcpy (lspid, dynhn->id, ISIS_SYS_ID_LEN);
                      lsp = lsp_search (lspid, area->lspdb[level]);
                    }
                  else if (strncmp(unix_hostname (), sysid, 15) == 0)
                    {
                      memcpy (lspid, isis->sysid, ISIS_SYS_ID_LEN);
                      lsp = lsp_search (lspid, area->lspdb[level]);
                    }
                }

              if (lsp != NULL || argv == NULL)
                {
                  vty_out (vty, "IS-IS Level-%d link-state database:%s",
                           level + 1, VTY_NEWLINE);

                  /* print the title in all cases */
                  vty_out (vty, "LSP ID                  PduLen  "
                           "SeqNumber   Chksum  Holdtime  ATT/P/OL%s",
                           VTY_NEWLINE);
                }

              if (lsp)
                {
                  if (ui_level == ISIS_UI_LEVEL_DETAIL)
                    lsp_print_detail (lsp, vty, area->dynhostname);
                  else
                    lsp_print (lsp, vty, area->dynhostname);
                }
              else if (argv == NULL)
                {
                  lsp_count = lsp_print_all (vty, area->lspdb[level],
                                             ui_level,
                                             area->dynhostname);

                  vty_out (vty, "    %u LSPs%s%s",
                           lsp_count, VTY_NEWLINE, VTY_NEWLINE);
                }
            }
        }
    }

  return CMD_SUCCESS;
}

DEFUN (show_database_brief,
       show_database_cmd,
       "show isis database",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS link state database\n")
{
  return show_isis_database (vty, NULL, ISIS_UI_LEVEL_BRIEF);
}

DEFUN (show_database_lsp_brief,
       show_database_arg_cmd,
       "show isis database WORD",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS link state database\n"
       "LSP ID\n")
{
  return show_isis_database (vty, argv[0], ISIS_UI_LEVEL_BRIEF);
}

DEFUN (show_database_lsp_detail,
       show_database_arg_detail_cmd,
       "show isis database WORD detail",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS link state database\n"
       "LSP ID\n"
       "Detailed information\n")
{
  return show_isis_database (vty, argv[0], ISIS_UI_LEVEL_DETAIL);
}

DEFUN (show_database_detail,
       show_database_detail_cmd,
       "show isis database detail",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS link state database\n")
{
  return show_isis_database (vty, NULL, ISIS_UI_LEVEL_DETAIL);
}

DEFUN (show_database_detail_lsp,
       show_database_detail_arg_cmd,
       "show isis database detail WORD",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS link state database\n"
       "Detailed information\n"
       "LSP ID\n")
{
  return show_isis_database (vty, argv[0], ISIS_UI_LEVEL_DETAIL);
}

/* 
 * 'router isis' command 
 */
DEFUN (router_isis,
       router_isis_cmd,
       "router isis WORD",
       ROUTER_STR
       "ISO IS-IS\n"
       "ISO Routing area tag")
{
  return isis_area_get (vty, argv[0]);
}

/* 
 *'no router isis' command 
 */
DEFUN (no_router_isis,
       no_router_isis_cmd,
       "no router isis WORD",
       "no\n" ROUTER_STR "ISO IS-IS\n" "ISO Routing area tag")
{
  return isis_area_destroy (vty, argv[0]);
}

/*
 * 'net' command
 */
DEFUN (net,
       net_cmd,
       "net WORD",
       "A Network Entity Title for this process (OSI only)\n"
       "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
  return area_net_title (vty, argv[0]);
}

/*
 * 'no net' command
 */
DEFUN (no_net,
       no_net_cmd,
       "no net WORD",
       NO_STR
       "A Network Entity Title for this process (OSI only)\n"
       "XX.XXXX. ... .XXX.XX  Network entity title (NET)\n")
{
  return area_clear_net_title (vty, argv[0]);
}

void isis_area_lsp_mtu_set(struct isis_area *area, unsigned int lsp_mtu)
{
  area->lsp_mtu = lsp_mtu;
  lsp_regenerate_schedule(area, IS_LEVEL_1_AND_2, 1);
}

static int
isis_area_passwd_set(struct isis_area *area, int level, u_char passwd_type,
		     const char *passwd, u_char snp_auth)
{
  struct isis_passwd *dest;
  struct isis_passwd modified;
  int len;

  assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));
  dest = (level == IS_LEVEL_1) ? &area->area_passwd : &area->domain_passwd;
  memset(&modified, 0, sizeof(modified));

  if (passwd_type != ISIS_PASSWD_TYPE_UNUSED)
    {
      if (!passwd)
        return -1;

      len = strlen(passwd);
      if (len > 254)
        return -1;

      modified.len = len;
      strncpy((char*)modified.passwd, passwd, 255);
      modified.type = passwd_type;
      modified.snp_auth = snp_auth;
    }

  if (memcmp(&modified, dest, sizeof(modified)))
    {
      memcpy(dest, &modified, sizeof(modified));
      lsp_regenerate_schedule(area, IS_LEVEL_1|IS_LEVEL_2, 1);
    }

  return 0;
}

int
isis_area_passwd_unset (struct isis_area *area, int level)
{
  return isis_area_passwd_set (area, level, ISIS_PASSWD_TYPE_UNUSED, NULL, 0);
}

int
isis_area_passwd_cleartext_set (struct isis_area *area, int level,
                                const char *passwd, u_char snp_auth)
{
  return isis_area_passwd_set (area, level, ISIS_PASSWD_TYPE_CLEARTXT,
                               passwd, snp_auth);
}

int
isis_area_passwd_hmac_md5_set (struct isis_area *area, int level,
                               const char *passwd, u_char snp_auth)
{
  return isis_area_passwd_set (area, level, ISIS_PASSWD_TYPE_HMAC_MD5,
                               passwd, snp_auth);
}

static void
area_resign_level (struct isis_area *area, int level)
{
  if (area->lspdb[level - 1])
    {
      lsp_db_destroy (area->lspdb[level - 1]);
      area->lspdb[level - 1] = NULL;
    }
  if (area->spftree[level - 1])
    {
      isis_spftree_del (area->spftree[level - 1]);
      area->spftree[level - 1] = NULL;
    }
#ifdef HAVE_IPV6
  if (area->spftree6[level - 1])
    {
      isis_spftree_del (area->spftree6[level - 1]);
      area->spftree6[level - 1] = NULL;
    }
#endif
  if (area->route_table[level - 1])
    {
      route_table_finish (area->route_table[level - 1]);
      area->route_table[level - 1] = NULL;
    }
#ifdef HAVE_IPV6
  if (area->route_table6[level - 1])
    {
      route_table_finish (area->route_table6[level - 1]);
      area->route_table6[level - 1] = NULL;
    }
#endif /* HAVE_IPV6 */

  sched_debug("ISIS (%s): Resigned from L%d - canceling LSP regeneration timer.",
              area->area_tag, level);
  THREAD_TIMER_OFF (area->t_lsp_refresh[level - 1]);
  area->lsp_regenerate_pending[level - 1] = 0;
}

void
isis_area_is_type_set(struct isis_area *area, int is_type)
{
  struct listnode *node;
  struct isis_circuit *circuit;

  if (isis->debugs & DEBUG_EVENTS)
    zlog_debug ("ISIS-Evt (%s) system type change %s -> %s", area->area_tag,
	       circuit_t2string (area->is_type), circuit_t2string (is_type));

  if (area->is_type == is_type)
    return;			/* No change */

  switch (area->is_type)
  {
    case IS_LEVEL_1:
      if (is_type == IS_LEVEL_2)
        area_resign_level (area, IS_LEVEL_1);

      if (area->lspdb[1] == NULL)
        area->lspdb[1] = lsp_db_init ();
      if (area->route_table[1] == NULL)
        area->route_table[1] = route_table_init ();
#ifdef HAVE_IPV6
      if (area->route_table6[1] == NULL)
        area->route_table6[1] = route_table_init ();
#endif /* HAVE_IPV6 */
      break;

    case IS_LEVEL_1_AND_2:
      if (is_type == IS_LEVEL_1)
        area_resign_level (area, IS_LEVEL_2);
      else
        area_resign_level (area, IS_LEVEL_1);
      break;

    case IS_LEVEL_2:
      if (is_type == IS_LEVEL_1)
        area_resign_level (area, IS_LEVEL_2);

      if (area->lspdb[0] == NULL)
        area->lspdb[0] = lsp_db_init ();
      if (area->route_table[0] == NULL)
        area->route_table[0] = route_table_init ();
#ifdef HAVE_IPV6
      if (area->route_table6[0] == NULL)
        area->route_table6[0] = route_table_init ();
#endif /* HAVE_IPV6 */
      break;

    default:
      break;
  }

  area->is_type = is_type;

  /* override circuit's is_type */
  if (area->is_type != IS_LEVEL_1_AND_2)
  {
    for (ALL_LIST_ELEMENTS_RO (area->circuit_list, node, circuit))
      isis_circuit_is_type_set (circuit, is_type);
  }

  spftree_area_init (area);

  if (is_type & IS_LEVEL_1)
    lsp_generate (area, IS_LEVEL_1);
  if (is_type & IS_LEVEL_2)
    lsp_generate (area, IS_LEVEL_2);
  lsp_regenerate_schedule (area, IS_LEVEL_1 | IS_LEVEL_2, 1);

  return;
}

void isis_area_metricstyle_set(struct isis_area *area, bool old_metric,
			       bool new_metric)
{
  if (area->oldmetric != old_metric
      || area->newmetric != new_metric)
    {
      area->oldmetric = old_metric;
      area->newmetric = new_metric;
      lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
    }
}

void isis_area_overload_bit_set(struct isis_area *area, bool overload_bit)
{
  char new_overload_bit = overload_bit ? LSPBIT_OL : 0;

  if (new_overload_bit != area->overload_bit)
    {
      area->overload_bit = new_overload_bit;
      lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
    }
}

void isis_area_attached_bit_set(struct isis_area *area, bool attached_bit)
{
  char new_attached_bit = attached_bit ? LSPBIT_ATT : 0;

  if (new_attached_bit != area->attached_bit)
    {
      area->attached_bit = new_attached_bit;
      lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 1);
    }
}

void isis_area_dynhostname_set(struct isis_area *area, bool dynhostname)
{
  if (area->dynhostname != dynhostname)
    {
      area->dynhostname = dynhostname;
      lsp_regenerate_schedule(area, IS_LEVEL_1 | IS_LEVEL_2, 0);
    }
}

void
isis_area_max_lsp_lifetime_set(struct isis_area *area, int level,
			       uint16_t max_lsp_lifetime)
{
  assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));

  if (area->max_lsp_lifetime[level-1] == max_lsp_lifetime)
    return;

  area->max_lsp_lifetime[level-1] = max_lsp_lifetime;
  lsp_regenerate_schedule(area, level, 1);
}

void
isis_area_lsp_refresh_set(struct isis_area *area, int level,
			  uint16_t lsp_refresh)
{
  assert((level == IS_LEVEL_1) || (level == IS_LEVEL_2));

  if (area->lsp_refresh[level-1] == lsp_refresh)
    return;

  area->lsp_refresh[level-1] = lsp_refresh;
  lsp_regenerate_schedule(area, level, 1);
}

DEFUN (log_adj_changes,
       log_adj_changes_cmd,
       "log-adjacency-changes",
       "Log changes in adjacency state\n")
{
  VTY_DECLVAR_CONTEXT (isis_area, area);

  area->log_adj_changes = 1;

  return CMD_SUCCESS;
}

DEFUN (no_log_adj_changes,
       no_log_adj_changes_cmd,
       "no log-adjacency-changes",
       "Stop logging changes in adjacency state\n")
{
  VTY_DECLVAR_CONTEXT (isis_area, area);

  area->log_adj_changes = 0;

  return CMD_SUCCESS;
}

#ifdef TOPOLOGY_GENERATE

DEFUN (topology_generate_grid,
       topology_generate_grid_cmd,
       "topology generate grid <1-100> <1-100> <1-65000> [param] [param] "
       "[param]",
       "Topology generation for IS-IS\n"
       "Topology generation\n"
       "Grid topology\n"
       "X parameter of the grid\n"
       "Y parameter of the grid\n"
       "Random seed\n"
       "Optional param 1\n"
       "Optional param 2\n"
       "Optional param 3\n"
       "Topology\n")
{
  VTY_DECLVAR_CONTEXT (isis_area, area);

  if (!spgrid_check_params (vty, argc, argv))
    {
      if (area->topology)
	list_delete (area->topology);
      area->topology = list_new ();
      memcpy (area->top_params, vty->buf, 200);
      gen_spgrid_topology (vty, area->topology);
      remove_topology_lsps (area);
      generate_topology_lsps (area);
      /* Regenerate L1 LSP to get two way connection to the generated
       * topology. */
      lsp_regenerate_schedule (area, IS_LEVEL_1 | IS_LEVEL_2, 1);
    }

  return CMD_SUCCESS;
}

DEFUN (show_isis_generated_topology,
       show_isis_generated_topology_cmd,
       "show isis generated-topologies",
       SHOW_STR
       "ISIS network information\n"
       "Show generated topologies\n")
{
  struct isis_area *area;
  struct listnode *node;
  struct listnode *node2;
  struct arc *arc;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      if (!area->topology)
	continue;

      vty_out (vty, "Topology for isis area: %s%s", area->area_tag,
	       VTY_NEWLINE);
      vty_out (vty, "From node     To node     Distance%s", VTY_NEWLINE);

      for (ALL_LIST_ELEMENTS_RO (area->topology, node2, arc))
	vty_out (vty, "%9ld %11ld %12ld%s", arc->from_node, arc->to_node,
		 arc->distance, VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

/* Base IS for topology generation. */
DEFUN (topology_baseis,
       topology_baseis_cmd,
       "topology base-is WORD",
       "Topology generation for IS-IS\n"
       "A Network IS Base for this topology\n"
       "XXXX.XXXX.XXXX Network entity title (NET)\n")
{
  u_char buff[ISIS_SYS_ID_LEN];
  VTY_DECLVAR_CONTEXT (isis_area, area);

  if (sysid2buff (buff, argv[0]))
    sysid2buff (area->topology_baseis, argv[0]);

  return CMD_SUCCESS;
}

DEFUN (no_topology_baseis,
       no_topology_baseis_cmd,
       "no topology base-is WORD",
       NO_STR
       "Topology generation for IS-IS\n"
       "A Network IS Base for this topology\n"
       "XXXX.XXXX.XXXX Network entity title (NET)\n")
{
  VTY_DECLVAR_CONTEXT (isis_area, area);

  memcpy (area->topology_baseis, DEFAULT_TOPOLOGY_BASEIS, ISIS_SYS_ID_LEN);
  return CMD_SUCCESS;
}

ALIAS (no_topology_baseis,
       no_topology_baseis_noid_cmd,
       "no topology base-is",
       NO_STR
       "Topology generation for IS-IS\n"
       "A Network IS Base for this topology\n")

DEFUN (topology_basedynh,
       topology_basedynh_cmd,
       "topology base-dynh WORD",
       "Topology generation for IS-IS\n"
       "Dynamic hostname base for this topology\n"
       "Dynamic hostname base\n")
{
  VTY_DECLVAR_CONTEXT (isis_area, area);

  /* I hope that it's enough. */
  area->topology_basedynh = strndup (argv[0], 16); 
  return CMD_SUCCESS;
}

#endif /* TOPOLOGY_GENERATE */

/* IS-IS configuration write function */
int
isis_config_write (struct vty *vty)
{
  int write = 0;

  if (isis != NULL)
    {
      struct isis_area *area;
      struct listnode *node, *node2;

      for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
      {
	/* ISIS - Area name */
	vty_out (vty, "router isis %s%s", area->area_tag, VTY_NEWLINE);
	write++;
	/* ISIS - Net */
	if (listcount (area->area_addrs) > 0)
	  {
	    struct area_addr *area_addr;
	    for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node2, area_addr))
	      {
		vty_out (vty, " net %s%s",
			 isonet_print (area_addr->area_addr,
				       area_addr->addr_len + ISIS_SYS_ID_LEN +
				       1), VTY_NEWLINE);
		write++;
	      }
	  }
	/* ISIS - Dynamic hostname - Defaults to true so only display if
	 * false. */
	if (!area->dynhostname)
	  {
	    vty_out (vty, " no hostname dynamic%s", VTY_NEWLINE);
	    write++;
	  }
	/* ISIS - Metric-Style - when true displays wide */
	if (area->newmetric)
	  {
	    if (!area->oldmetric)
	      vty_out (vty, " metric-style wide%s", VTY_NEWLINE);
	    else
	      vty_out (vty, " metric-style transition%s", VTY_NEWLINE);
	    write++;
	  }
	else
	  {
	    vty_out (vty, " metric-style narrow%s", VTY_NEWLINE);
	    write++;
	  }
	/* ISIS - overload-bit */
	if (area->overload_bit)
	  {
	    vty_out (vty, " set-overload-bit%s", VTY_NEWLINE);
	    write++;
	  }
	/* ISIS - Area is-type (level-1-2 is default) */
	if (area->is_type == IS_LEVEL_1)
	  {
	    vty_out (vty, " is-type level-1%s", VTY_NEWLINE);
	    write++;
	  }
	else if (area->is_type == IS_LEVEL_2)
	  {
	    vty_out (vty, " is-type level-2-only%s", VTY_NEWLINE);
	    write++;
	  }
	write += isis_redist_config_write(vty, area, AF_INET);
	write += isis_redist_config_write(vty, area, AF_INET6);
	/* ISIS - Lsp generation interval */
	if (area->lsp_gen_interval[0] == area->lsp_gen_interval[1])
	  {
	    if (area->lsp_gen_interval[0] != DEFAULT_MIN_LSP_GEN_INTERVAL)
	      {
		vty_out (vty, " lsp-gen-interval %d%s",
			 area->lsp_gen_interval[0], VTY_NEWLINE);
		write++;
	      }
	  }
	else
	  {
	    if (area->lsp_gen_interval[0] != DEFAULT_MIN_LSP_GEN_INTERVAL)
	      {
		vty_out (vty, " lsp-gen-interval level-1 %d%s",
			 area->lsp_gen_interval[0], VTY_NEWLINE);
		write++;
	      }
	    if (area->lsp_gen_interval[1] != DEFAULT_MIN_LSP_GEN_INTERVAL)
	      {
		vty_out (vty, " lsp-gen-interval level-2 %d%s",
			 area->lsp_gen_interval[1], VTY_NEWLINE);
		write++;
	      }
	  }
	/* ISIS - LSP lifetime */
	if (area->max_lsp_lifetime[0] == area->max_lsp_lifetime[1])
	  {
	    if (area->max_lsp_lifetime[0] != DEFAULT_LSP_LIFETIME)
	      {
		vty_out (vty, " max-lsp-lifetime %u%s", area->max_lsp_lifetime[0],
			 VTY_NEWLINE);
		write++;
	      }
	  }
	else
	  {
	    if (area->max_lsp_lifetime[0] != DEFAULT_LSP_LIFETIME)
	      {
		vty_out (vty, " max-lsp-lifetime level-1 %u%s",
			 area->max_lsp_lifetime[0], VTY_NEWLINE);
		write++;
	      }
	    if (area->max_lsp_lifetime[1] != DEFAULT_LSP_LIFETIME)
	      {
		vty_out (vty, " max-lsp-lifetime level-2 %u%s",
			 area->max_lsp_lifetime[1], VTY_NEWLINE);
		write++;
	      }
	  }
	/* ISIS - LSP refresh interval */
	if (area->lsp_refresh[0] == area->lsp_refresh[1])
	  {
	    if (area->lsp_refresh[0] != DEFAULT_MAX_LSP_GEN_INTERVAL)
	      {
		vty_out (vty, " lsp-refresh-interval %u%s", area->lsp_refresh[0],
			 VTY_NEWLINE);
		write++;
	      }
	  }
	else
	  {
	    if (area->lsp_refresh[0] != DEFAULT_MAX_LSP_GEN_INTERVAL)
	      {
		vty_out (vty, " lsp-refresh-interval level-1 %u%s",
			 area->lsp_refresh[0], VTY_NEWLINE);
		write++;
	      }
	    if (area->lsp_refresh[1] != DEFAULT_MAX_LSP_GEN_INTERVAL)
	      {
		vty_out (vty, " lsp-refresh-interval level-2 %u%s",
			 area->lsp_refresh[1], VTY_NEWLINE);
		write++;
	      }
	  }
	if (area->lsp_mtu != DEFAULT_LSP_MTU)
	  {
	    vty_out(vty, " lsp-mtu %u%s", area->lsp_mtu, VTY_NEWLINE);
	    write++;
	  }

	/* Minimum SPF interval. */
	if (area->min_spf_interval[0] == area->min_spf_interval[1])
	  {
	    if (area->min_spf_interval[0] != MINIMUM_SPF_INTERVAL)
	      {
		vty_out (vty, " spf-interval %d%s",
			 area->min_spf_interval[0], VTY_NEWLINE);
		write++;
	      }
	  }
	else
	  {
	    if (area->min_spf_interval[0] != MINIMUM_SPF_INTERVAL)
	      {
		vty_out (vty, " spf-interval level-1 %d%s",
			 area->min_spf_interval[0], VTY_NEWLINE);
		write++;
	      }
	    if (area->min_spf_interval[1] != MINIMUM_SPF_INTERVAL)
	      {
		vty_out (vty, " spf-interval level-2 %d%s",
			 area->min_spf_interval[1], VTY_NEWLINE);
		write++;
	      }
	  }
	/* Authentication passwords. */
	if (area->area_passwd.type == ISIS_PASSWD_TYPE_HMAC_MD5)
	  {
	    vty_out(vty, " area-password md5 %s", area->area_passwd.passwd);
	    if (CHECK_FLAG(area->area_passwd.snp_auth, SNP_AUTH_SEND))
	      {
		vty_out(vty, " authenticate snp ");
		if (CHECK_FLAG(area->area_passwd.snp_auth, SNP_AUTH_RECV))
		  vty_out(vty, "validate");
		else
		  vty_out(vty, "send-only");
	      }
	    vty_out(vty, "%s", VTY_NEWLINE);
	    write++; 
	  }
        else if (area->area_passwd.type == ISIS_PASSWD_TYPE_CLEARTXT)
          {
	    vty_out(vty, " area-password clear %s", area->area_passwd.passwd);
	    if (CHECK_FLAG(area->area_passwd.snp_auth, SNP_AUTH_SEND))
	      {
		vty_out(vty, " authenticate snp ");
		if (CHECK_FLAG(area->area_passwd.snp_auth, SNP_AUTH_RECV))
		  vty_out(vty, "validate");
		else
		  vty_out(vty, "send-only");
	      }
	    vty_out(vty, "%s", VTY_NEWLINE);
	    write++; 
          }
	if (area->domain_passwd.type == ISIS_PASSWD_TYPE_HMAC_MD5)
	  {
            vty_out(vty, " domain-password md5 %s",
                    area->domain_passwd.passwd);
	    if (CHECK_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_SEND))
	      {
		vty_out(vty, " authenticate snp ");
		if (CHECK_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_RECV))
		  vty_out(vty, "validate");
		else
		  vty_out(vty, "send-only");
	      }
	    vty_out(vty, "%s", VTY_NEWLINE);
	    write++;
	  }
        else if (area->domain_passwd.type == ISIS_PASSWD_TYPE_CLEARTXT)
	  {
	    vty_out(vty, " domain-password clear %s",
                    area->domain_passwd.passwd); 
	    if (CHECK_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_SEND))
	      {
		vty_out(vty, " authenticate snp ");
		if (CHECK_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_RECV))
		  vty_out(vty, "validate");
		else
		  vty_out(vty, "send-only");
	      }
	    vty_out(vty, "%s", VTY_NEWLINE);
	    write++;
	  }

	if (area->log_adj_changes)
	  {
	    vty_out (vty, " log-adjacency-changes%s", VTY_NEWLINE);
	    write++;
	  }

#ifdef TOPOLOGY_GENERATE
	if (memcmp (area->topology_baseis, DEFAULT_TOPOLOGY_BASEIS,
		    ISIS_SYS_ID_LEN))
	  {
	    vty_out (vty, " topology base-is %s%s",
		     sysid_print ((u_char *)area->topology_baseis), VTY_NEWLINE);
	    write++;
	  }
	if (area->topology_basedynh)
	  {
	    vty_out (vty, " topology base-dynh %s%s",
		     area->topology_basedynh, VTY_NEWLINE);
	    write++;
	  }
	/* We save the whole command line here. */
	if (strlen(area->top_params))
	  {
	    vty_out (vty, " %s%s", area->top_params, VTY_NEWLINE);
	    write++;
	  }
#endif /* TOPOLOGY_GENERATE */

      }
    isis_mpls_te_config_write_router(vty);
    }

  return write;
}

struct cmd_node isis_node = {
  ISIS_NODE,
  "%s(config-router)# ",
  1
};

void
isis_init ()
{
  /* Install IS-IS top node */
  install_node (&isis_node, isis_config_write);

  install_element (VIEW_NODE, &show_isis_summary_cmd);

  install_element (VIEW_NODE, &show_isis_interface_cmd);
  install_element (VIEW_NODE, &show_isis_interface_detail_cmd);
  install_element (VIEW_NODE, &show_isis_interface_arg_cmd);

  install_element (VIEW_NODE, &show_isis_neighbor_cmd);
  install_element (VIEW_NODE, &show_isis_neighbor_detail_cmd);
  install_element (VIEW_NODE, &show_isis_neighbor_arg_cmd);
  install_element (VIEW_NODE, &clear_isis_neighbor_cmd);
  install_element (VIEW_NODE, &clear_isis_neighbor_arg_cmd);

  install_element (VIEW_NODE, &show_hostname_cmd);
  install_element (VIEW_NODE, &show_database_cmd);
  install_element (VIEW_NODE, &show_database_arg_cmd);
  install_element (VIEW_NODE, &show_database_arg_detail_cmd);
  install_element (VIEW_NODE, &show_database_detail_cmd);
  install_element (VIEW_NODE, &show_database_detail_arg_cmd);

  install_element (ENABLE_NODE, &show_debugging_isis_cmd);

  install_node (&debug_node, config_write_debug);

  install_element (ENABLE_NODE, &debug_isis_adj_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_adj_cmd);
  install_element (ENABLE_NODE, &debug_isis_csum_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_csum_cmd);
  install_element (ENABLE_NODE, &debug_isis_lupd_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_lupd_cmd);
  install_element (ENABLE_NODE, &debug_isis_err_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_err_cmd);
  install_element (ENABLE_NODE, &debug_isis_snp_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_snp_cmd);
  install_element (ENABLE_NODE, &debug_isis_upd_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_upd_cmd);
  install_element (ENABLE_NODE, &debug_isis_spfevents_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_spfevents_cmd);
  install_element (ENABLE_NODE, &debug_isis_spfstats_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_spfstats_cmd);
  install_element (ENABLE_NODE, &debug_isis_spftrigg_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_spftrigg_cmd);
  install_element (ENABLE_NODE, &debug_isis_rtevents_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_rtevents_cmd);
  install_element (ENABLE_NODE, &debug_isis_events_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_events_cmd);
  install_element (ENABLE_NODE, &debug_isis_packet_dump_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_packet_dump_cmd);
  install_element (ENABLE_NODE, &debug_isis_lsp_gen_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_lsp_gen_cmd);
  install_element (ENABLE_NODE, &debug_isis_lsp_sched_cmd);
  install_element (ENABLE_NODE, &no_debug_isis_lsp_sched_cmd);

  install_element (CONFIG_NODE, &debug_isis_adj_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_adj_cmd);
  install_element (CONFIG_NODE, &debug_isis_csum_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_csum_cmd);
  install_element (CONFIG_NODE, &debug_isis_lupd_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_lupd_cmd);
  install_element (CONFIG_NODE, &debug_isis_err_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_err_cmd);
  install_element (CONFIG_NODE, &debug_isis_snp_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_snp_cmd);
  install_element (CONFIG_NODE, &debug_isis_upd_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_upd_cmd);
  install_element (CONFIG_NODE, &debug_isis_spfevents_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_spfevents_cmd);
  install_element (CONFIG_NODE, &debug_isis_spfstats_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_spfstats_cmd);
  install_element (CONFIG_NODE, &debug_isis_spftrigg_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_spftrigg_cmd);
  install_element (CONFIG_NODE, &debug_isis_rtevents_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_rtevents_cmd);
  install_element (CONFIG_NODE, &debug_isis_events_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_events_cmd);
  install_element (CONFIG_NODE, &debug_isis_packet_dump_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_packet_dump_cmd);
  install_element (CONFIG_NODE, &debug_isis_lsp_gen_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_lsp_gen_cmd);
  install_element (CONFIG_NODE, &debug_isis_lsp_sched_cmd);
  install_element (CONFIG_NODE, &no_debug_isis_lsp_sched_cmd);

  install_element (CONFIG_NODE, &router_isis_cmd);
  install_element (CONFIG_NODE, &no_router_isis_cmd);

  install_default (ISIS_NODE);

  install_element (ISIS_NODE, &net_cmd);
  install_element (ISIS_NODE, &no_net_cmd);

  install_element (ISIS_NODE, &log_adj_changes_cmd);
  install_element (ISIS_NODE, &no_log_adj_changes_cmd);

#ifdef TOPOLOGY_GENERATE
  install_element (ISIS_NODE, &topology_generate_grid_cmd);
  install_element (ISIS_NODE, &topology_baseis_cmd);
  install_element (ISIS_NODE, &topology_basedynh_cmd);
  install_element (ISIS_NODE, &no_topology_baseis_cmd);
  install_element (ISIS_NODE, &no_topology_baseis_noid_cmd);
  install_element (VIEW_NODE, &show_isis_generated_topology_cmd);
#endif /* TOPOLOGY_GENERATE */
}
