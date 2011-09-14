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
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "stream.h"
#include "prefix.h"
#include "table.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
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
#include "isisd/isis_csm.h"

#ifdef TOPOLOGY_GENERATE
#include "spgrid.h"
u_char DEFAULT_TOPOLOGY_BASEIS[6] = { 0xFE, 0xED, 0xFE, 0xED, 0x00, 0x00 };
#endif /* TOPOLOGY_GENERATE */

struct isis *isis = NULL;
extern struct thread_master *master;

/*
 * Prototypes.
 */
void isis_new(unsigned long);
struct isis_area *isis_area_create(void);
int isis_area_get(struct vty *, const char *);
int isis_area_destroy(struct vty *, const char *);
int area_net_title(struct vty *, const u_char *);
int area_clear_net_title(struct vty *, const u_char *);
int show_clns_neigh(struct vty *, char);
void print_debug(struct vty *, int, int);
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
  isis->area_list = list_new ();
  isis->init_circ_list = list_new ();
  isis->uptime = time (NULL);
  isis->nexthops = list_new ();
#ifdef HAVE_IPV6
  isis->nexthops6 = list_new ();
#endif /* HAVE_IPV6 */
  /*
   * uncomment the next line for full debugs
   */
  /* isis->debugs = 0xFFFF; */
}

struct isis_area *
isis_area_create ()
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
  area->lspdb[0] = lsp_db_init ();
  area->lspdb[1] = lsp_db_init ();

  spftree_area_init (area);
  area->route_table[0] = route_table_init ();
  area->route_table[1] = route_table_init ();
#ifdef HAVE_IPV6
  area->route_table6[0] = route_table_init ();
  area->route_table6[1] = route_table_init ();
#endif /* HAVE_IPV6 */
  area->circuit_list = list_new ();
  area->area_addrs = list_new ();
  THREAD_TIMER_ON (master, area->t_tick, lsp_tick, area, 1);
  flags_initialize (&area->flags);
  /*
   * Default values
   */
  area->max_lsp_lifetime[0] = MAX_AGE;	/* 1200 */
  area->max_lsp_lifetime[1] = MAX_AGE;	/* 1200 */
  area->lsp_gen_interval[0] = LSP_GEN_INTERVAL_DEFAULT;
  area->lsp_gen_interval[1] = LSP_GEN_INTERVAL_DEFAULT;
  area->lsp_refresh[0] = MAX_LSP_GEN_INTERVAL;	/* 900 */
  area->lsp_refresh[1] = MAX_LSP_GEN_INTERVAL;	/* 900 */
  area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
  area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;
  area->dynhostname = 1;
  area->oldmetric = 1;
  area->lsp_frag_threshold = 90;
#ifdef TOPOLOGY_GENERATE
  memcpy (area->topology_baseis, DEFAULT_TOPOLOGY_BASEIS, ISIS_SYS_ID_LEN);
#endif /* TOPOLOGY_GENERATE */

  /* FIXME: Think of a better way... */
  area->min_bcast_mtu = 1497;

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
      vty->node = ISIS_NODE;
      vty->index = area;
      return CMD_SUCCESS;
    }

  area = isis_area_create ();
  area->area_tag = strdup (area_tag);
  listnode_add (isis->area_list, area);

  if (isis->debugs & DEBUG_EVENTS)
    zlog_debug ("New IS-IS area instance %s", area->area_tag);

  vty->node = ISIS_NODE;
  vty->index = area;

  return CMD_SUCCESS;
}

int
isis_area_destroy (struct vty *vty, const char *area_tag)
{
  struct isis_area *area;
  struct listnode *node, *nnode;
  struct isis_circuit *circuit;

  area = isis_area_lookup (area_tag);

  if (area == NULL)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (area->circuit_list)
    {
      for (ALL_LIST_ELEMENTS (area->circuit_list, node, nnode, circuit))
	{
	  /* The fact that it's in circuit_list means that it was configured */
	  isis_csm_state_change (ISIS_DISABLE, circuit, area);
	  isis_circuit_down (circuit);
	  isis_circuit_deconfigure (circuit, area);
	}
      
      list_delete (area->circuit_list);
    }
  listnode_delete (isis->area_list, area);

  THREAD_TIMER_OFF (area->t_tick);
  if (area->t_remove_aged)
    thread_cancel (area->t_remove_aged);
  THREAD_TIMER_OFF (area->t_lsp_refresh[0]);
  THREAD_TIMER_OFF (area->t_lsp_refresh[1]);

  THREAD_TIMER_OFF (area->spftree[0]->t_spf);
  THREAD_TIMER_OFF (area->spftree[1]->t_spf);

  THREAD_TIMER_OFF (area->t_lsp_l1_regenerate);
  THREAD_TIMER_OFF (area->t_lsp_l2_regenerate);

  XFREE (MTYPE_ISIS_AREA, area);

  isis->sysid_set=0;

  return CMD_SUCCESS;
}

int
area_net_title (struct vty *vty, const u_char *net_title)
{
  struct isis_area *area;
  struct area_addr *addr;
  struct area_addr *addrp;
  struct listnode *node;

  u_char buff[255];
  area = vty->index;

  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* We check that we are not over the maximal number of addresses */
  if (listcount (area->area_addrs) >= isis->max_area_addrs)
    {
      vty_out (vty, "Maximum of area addresses (%d) already reached %s",
	       isis->max_area_addrs, VTY_NEWLINE);
      return CMD_WARNING;
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
      zlog_warn ("area address must be at least 8..20 octets long (%d)",
		 addr->addr_len);
      XFREE (MTYPE_ISIS_AREA_ADDR, addr);
      return CMD_WARNING;
    }

  if (isis->sysid_set == 0)
    {
      /*
       * First area address - get the SystemID for this router
       */
      memcpy (isis->sysid, GETSYSID (addr, ISIS_SYS_ID_LEN), ISIS_SYS_ID_LEN);
      isis->sysid_set = 1;
      if (isis->debugs & DEBUG_EVENTS)
	zlog_debug ("Router has SystemID %s", sysid_print (isis->sysid));
    }
  else
    {
      /*
       * Check that the SystemID portions match
       */
      if (memcmp (isis->sysid, GETSYSID (addr, ISIS_SYS_ID_LEN),
		  ISIS_SYS_ID_LEN))
	{
	  vty_out (vty,
		   "System ID must not change when defining additional area"
		   " addresses%s", VTY_NEWLINE);
	  XFREE (MTYPE_ISIS_AREA_ADDR, addr);
	  return CMD_WARNING;
	}

      /* now we see that we don't already have this address */
      for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node, addrp))
	{
	  if ((addrp->addr_len + ISIS_SYS_ID_LEN + 1) != (addr->addr_len))
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
  addr->addr_len -= (ISIS_SYS_ID_LEN + 1);
  listnode_add (area->area_addrs, addr);

  /* only now we can safely generate our LSPs for this area */
  if (listcount (area->area_addrs) > 0)
    {
      lsp_l1_generate (area);
      lsp_l2_generate (area);
    }

  return CMD_SUCCESS;
}

int
area_clear_net_title (struct vty *vty, const u_char *net_title)
{
  struct isis_area *area;
  struct area_addr addr, *addrp = NULL;
  struct listnode *node;
  u_char buff[255];

  area = vty->index;
  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  addr.addr_len = dotformat2buff (buff, net_title);
  if (addr.addr_len < 8 || addr.addr_len > 20)
    {
      vty_out (vty, "Unsupported area address length %d, should be 8...20 %s",
	       addr.addr_len, VTY_NEWLINE);
      return CMD_WARNING;
    }

  memcpy (addr.area_addr, buff, (int) addr.addr_len);

  for (ALL_LIST_ELEMENTS_RO (area->area_addrs, node, addrp))
    if (addrp->addr_len == addr.addr_len &&
	!memcmp (addrp->area_addr, addr.area_addr, addr.addr_len))
    break;

  if (!addrp)
    {
      vty_out (vty, "No area address %s for area %s %s", net_title,
	       area->area_tag, VTY_NEWLINE);
      return CMD_WARNING;
    }

  listnode_delete (area->area_addrs, addrp);

  return CMD_SUCCESS;
}

/*
 * 'show clns neighbors' command
 */

int
show_clns_neigh (struct vty *vty, char detail)
{
  struct listnode *anode, *cnode;
  struct isis_area *area;
  struct isis_circuit *circuit;
  struct list *db;
  int i;

  if (!isis)
    {
      vty_out (vty, "IS-IS Routing Process not enabled%s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, anode, area))
    {
      vty_out (vty, "Area %s:%s", area->area_tag, VTY_NEWLINE);

      if (detail == ISIS_UI_LEVEL_BRIEF)
	vty_out (vty, "  System Id           Interface   L  State        "
		 "Holdtime SNPA%s", VTY_NEWLINE);

      for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit))
	{
	  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
	    {
	      for (i = 0; i < 2; i++)
		{
		  db = circuit->u.bc.adjdb[i];
		  if (db && db->count)
		    {
		      if (detail == ISIS_UI_LEVEL_BRIEF)
			isis_adjdb_iterate (db,
					    (void (*)
					     (struct isis_adjacency *,
					      void *)) isis_adj_print_vty,
					    vty);
		      if (detail == ISIS_UI_LEVEL_DETAIL)
			isis_adjdb_iterate (db,
					    (void (*)
					     (struct isis_adjacency *,
					      void *))
					    isis_adj_print_vty_detail, vty);
		      if (detail == ISIS_UI_LEVEL_EXTENSIVE)
			isis_adjdb_iterate (db,
					    (void (*)
					     (struct isis_adjacency *,
					      void *))
					    isis_adj_print_vty_extensive,
					    vty);
		    }
		}
	    }
	  else if (circuit->circ_type == CIRCUIT_T_P2P &&
		   circuit->u.p2p.neighbor)
	    {
	      if (detail == ISIS_UI_LEVEL_BRIEF)
		isis_adj_p2p_print_vty (circuit->u.p2p.neighbor, vty);
	      if (detail == ISIS_UI_LEVEL_DETAIL)
		isis_adj_p2p_print_vty_detail (circuit->u.p2p.neighbor, vty);
	      if (detail == ISIS_UI_LEVEL_EXTENSIVE)
		isis_adj_p2p_print_vty_extensive (circuit->u.p2p.neighbor,
						  vty);
	    }
	}
    }

  return CMD_SUCCESS;
}

DEFUN (show_clns_neighbors,
       show_clns_neighbors_cmd,
       "show clns neighbors",
       SHOW_STR
       "clns network information\n"
       "CLNS neighbor adjacencies\n")
{
  return show_clns_neigh (vty, ISIS_UI_LEVEL_BRIEF);
}

ALIAS (show_clns_neighbors,
       show_isis_neighbors_cmd,
       "show isis neighbors",
       SHOW_STR
       "IS-IS network information\n"
       "IS-IS neighbor adjacencies\n")

DEFUN (show_clns_neighbors_detail,
       show_clns_neighbors_detail_cmd,
       "show clns neighbors detail",
       SHOW_STR
       "clns network information\n"
       "CLNS neighbor adjacencies\n"
       "show detailed information\n")
{
  return show_clns_neigh (vty, ISIS_UI_LEVEL_DETAIL);
}

ALIAS (show_clns_neighbors_detail,
       show_isis_neighbors_detail_cmd,
       "show isis neighbors detail",
       SHOW_STR
       "IS-IS network information\n"
       "IS-IS neighbor adjacencies\n"
       "show detailed information\n")
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

}

DEFUN (show_debugging,
       show_debugging_cmd,
       "show debugging",
       SHOW_STR
       "State of each debugging option\n")
{
  vty_out (vty, "IS-IS:%s", VTY_NEWLINE);
  print_debug (vty, isis->debugs, 1);
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

DEFUN (show_database,
       show_database_cmd,
       "show isis database",
       SHOW_STR "IS-IS information\n" "IS-IS link state database\n")
{
  struct listnode *node;
  struct isis_area *area;
  int level, lsp_count;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "Area %s:%s", area->area_tag ? area->area_tag : "null",
	       VTY_NEWLINE);
      for (level = 0; level < ISIS_LEVELS; level++)
	{
	  if (area->lspdb[level] && dict_count (area->lspdb[level]) > 0)
	    {
	      vty_out (vty, "IS-IS Level-%d link-state database:%s",
		       level + 1, VTY_NEWLINE);

	      lsp_count = lsp_print_all (vty, area->lspdb[level],
					 ISIS_UI_LEVEL_BRIEF,
					 area->dynhostname);

	      vty_out (vty, "%s    %u LSPs%s%s",
		       VTY_NEWLINE, lsp_count, VTY_NEWLINE, VTY_NEWLINE);
	    }
	}
    }

  return CMD_SUCCESS;
}

DEFUN (show_database_detail,
       show_database_detail_cmd,
       "show isis database detail",
       SHOW_STR
       "IS-IS information\n"
       "IS-IS link state database\n")
{
  struct listnode *node;
  struct isis_area *area;
  int level, lsp_count;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "Area %s:%s", area->area_tag ? area->area_tag : "null",
	       VTY_NEWLINE);
      for (level = 0; level < ISIS_LEVELS; level++)
	{
	  if (area->lspdb[level] && dict_count (area->lspdb[level]) > 0)
	    {
	      vty_out (vty, "IS-IS Level-%d Link State Database:%s",
		       level + 1, VTY_NEWLINE);

	      lsp_count = lsp_print_all (vty, area->lspdb[level],
					 ISIS_UI_LEVEL_DETAIL,
					 area->dynhostname);

	      vty_out (vty, "%s    %u LSPs%s%s",
		       VTY_NEWLINE, lsp_count, VTY_NEWLINE, VTY_NEWLINE);
	    }
	}
    }

  return CMD_SUCCESS;
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

DEFUN (area_passwd,
       area_passwd_cmd,
       "area-password WORD",
       "Configure the authentication password for an area\n"
       "Area password\n")
{
  struct isis_area *area;
  int len;

  area = vty->index;

  if (!area)
    {
      vty_out (vty, "Cant find IS-IS instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  len = strlen (argv[0]);
  if (len > 254)
    {
      vty_out (vty, "Too long area password (>254)%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  area->area_passwd.len = (u_char) len;
  area->area_passwd.type = ISIS_PASSWD_TYPE_CLEARTXT;
  strncpy ((char *)area->area_passwd.passwd, argv[0], 255);

  if (argc > 1)
    {
      SET_FLAG(area->area_passwd.snp_auth, SNP_AUTH_SEND);
      if (strncmp(argv[1], "v", 1) == 0)
	SET_FLAG(area->area_passwd.snp_auth, SNP_AUTH_RECV);
      else
	UNSET_FLAG(area->area_passwd.snp_auth, SNP_AUTH_RECV);
    }
  else
    {
      UNSET_FLAG(area->area_passwd.snp_auth, SNP_AUTH_SEND);
      UNSET_FLAG(area->area_passwd.snp_auth, SNP_AUTH_RECV);
    }

  return CMD_SUCCESS;
}

ALIAS (area_passwd,
       area_passwd_snpauth_cmd,
       "area-password WORD authenticate snp (send-only|validate)",
       "Configure the authentication password for an area\n"
       "Area password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n");

DEFUN (no_area_passwd,
       no_area_passwd_cmd,
       "no area-password",
       NO_STR
       "Configure the authentication password for an area\n")
{
  struct isis_area *area;

  area = vty->index;

  if (!area)
    {
      vty_out (vty, "Cant find IS-IS instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&area->area_passwd, 0, sizeof (struct isis_passwd));

  return CMD_SUCCESS;
}

DEFUN (domain_passwd,
       domain_passwd_cmd,
       "domain-password WORD",
       "Set the authentication password for a routing domain\n"
       "Routing domain password\n")
{
  struct isis_area *area;
  int len;

  area = vty->index;

  if (!area)
    {
      vty_out (vty, "Cant find IS-IS instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  len = strlen (argv[0]);
  if (len > 254)
    {
      vty_out (vty, "Too long area password (>254)%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  area->domain_passwd.len = (u_char) len;
  area->domain_passwd.type = ISIS_PASSWD_TYPE_CLEARTXT;
  strncpy ((char *)area->domain_passwd.passwd, argv[0], 255);

  if (argc > 1)
    {
      SET_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_SEND);
      if (strncmp(argv[1], "v", 1) == 0)
	SET_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_RECV);
      else
	UNSET_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_RECV);
    }
  else
    {
      UNSET_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_SEND);
      UNSET_FLAG(area->domain_passwd.snp_auth, SNP_AUTH_RECV);
    }

  return CMD_SUCCESS;
}

ALIAS (domain_passwd,
       domain_passwd_snpauth_cmd,
       "domain-password WORD authenticate snp (send-only|validate)",
       "Set the authentication password for a routing domain\n"
       "Routing domain password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n");

DEFUN (no_domain_passwd,
       no_domain_passwd_cmd,
       "no domain-password WORD",
       NO_STR
       "Set the authentication password for a routing domain\n")
{
  struct isis_area *area;

  area = vty->index;

  if (!area)
    {
      vty_out (vty, "Cant find IS-IS instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&area->domain_passwd, 0, sizeof (struct isis_passwd));

  return CMD_SUCCESS;
}

DEFUN (is_type,
       is_type_cmd,
       "is-type (level-1|level-1-2|level-2-only)",
       "IS Level for this routing process (OSI only)\n"
       "Act as a station router only\n"
       "Act as both a station router and an area router\n"
       "Act as an area router only\n")
{
  struct isis_area *area;
  int type;

  area = vty->index;

  if (!area)
    {
      vty_out (vty, "Cant find IS-IS instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  type = string2circuit_t (argv[0]);
  if (!type)
    {
      vty_out (vty, "Unknown IS level %s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  isis_event_system_type_change (area, type);

  return CMD_SUCCESS;
}

DEFUN (no_is_type,
       no_is_type_cmd,
       "no is-type (level-1|level-1-2|level-2-only)",
       NO_STR
       "IS Level for this routing process (OSI only)\n"
       "Act as a station router only\n"
       "Act as both a station router and an area router\n"
       "Act as an area router only\n")
{
  struct isis_area *area;
  int type;

  area = vty->index;
  assert (area);

  /*
   * Put the is-type back to default. Which is level-1-2 on first
   * circuit for the area level-1 for the rest
   */
  if (listgetdata (listhead (isis->area_list)) == area)
    type = IS_LEVEL_1_AND_2;
  else
    type = IS_LEVEL_1;

  isis_event_system_type_change (area, type);

  return CMD_SUCCESS;
}

DEFUN (lsp_gen_interval,
       lsp_gen_interval_cmd,
       "lsp-gen-interval <1-120>",
       "Minimum interval between regenerating same LSP\n"
       "Minimum interval in seconds\n")
{
  struct isis_area *area;
  uint16_t interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);
  area->lsp_gen_interval[0] = interval;
  area->lsp_gen_interval[1] = interval;

  return CMD_SUCCESS;
}

DEFUN (no_lsp_gen_interval,
       no_lsp_gen_interval_cmd,
       "no lsp-gen-interval",
       NO_STR
       "Minimum interval between regenerating same LSP\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->lsp_gen_interval[0] = LSP_GEN_INTERVAL_DEFAULT;
  area->lsp_gen_interval[1] = LSP_GEN_INTERVAL_DEFAULT;

  return CMD_SUCCESS;
}

ALIAS (no_lsp_gen_interval,
       no_lsp_gen_interval_arg_cmd,
       "no lsp-gen-interval <1-120>",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Minimum interval in seconds\n")

DEFUN (lsp_gen_interval_l1,
       lsp_gen_interval_l1_cmd,
       "lsp-gen-interval level-1 <1-120>",
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n"
       "Minimum interval in seconds\n")
{
  struct isis_area *area;
  uint16_t interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);
  area->lsp_gen_interval[0] = interval;

  return CMD_SUCCESS;
}

DEFUN (no_lsp_gen_interval_l1,
       no_lsp_gen_interval_l1_cmd,
       "no lsp-gen-interval level-1",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->lsp_gen_interval[0] = LSP_GEN_INTERVAL_DEFAULT;

  return CMD_SUCCESS;
}

ALIAS (no_lsp_gen_interval_l1,
       no_lsp_gen_interval_l1_arg_cmd,
       "no lsp-gen-interval level-1 <1-120>",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n"
       "Minimum interval in seconds\n")

DEFUN (lsp_gen_interval_l2,
       lsp_gen_interval_l2_cmd,
       "lsp-gen-interval level-2 <1-120>",
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 2 only\n"
       "Minimum interval in seconds\n")
{
  struct isis_area *area;
  int interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);
  area->lsp_gen_interval[1] = interval;

  return CMD_SUCCESS;
}

DEFUN (no_lsp_gen_interval_l2,
       no_lsp_gen_interval_l2_cmd,
       "no lsp-gen-interval level-2",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 2 only\n")
{
  struct isis_area *area;
  int interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);
  area->lsp_gen_interval[1] = LSP_GEN_INTERVAL_DEFAULT;

  return CMD_SUCCESS;
}

ALIAS (no_lsp_gen_interval_l2,
       no_lsp_gen_interval_l2_arg_cmd,
       "no lsp-gen-interval level-2 <1-120>",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 2 only\n"
       "Minimum interval in seconds\n")

DEFUN (metric_style,
       metric_style_cmd,
       "metric-style (narrow|transition|wide)",
       "Use old-style (ISO 10589) or new-style packet formats\n"
       "Use old style of TLVs with narrow metric\n"
       "Send and accept both styles of TLVs during transition\n"
       "Use new style of TLVs to carry wider metric\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  if (strncmp (argv[0], "w", 1) == 0)
    {
      area->newmetric = 1;
      area->oldmetric = 0;
    }
  else if (strncmp (argv[0], "t", 1) == 0)
    {
      area->newmetric = 1;
      area->oldmetric = 1;
    }
  else if (strncmp (argv[0], "n", 1) == 0)
    {
      area->newmetric = 0;
      area->oldmetric = 1;
    }

  return CMD_SUCCESS;
}

DEFUN (no_metric_style,
       no_metric_style_cmd,
       "no metric-style",
       NO_STR
       "Use old-style (ISO 10589) or new-style packet formats\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  /* Default is narrow metric. */
  area->newmetric = 0;
  area->oldmetric = 1;

  return CMD_SUCCESS;
}

DEFUN (dynamic_hostname,
       dynamic_hostname_cmd,
       "hostname dynamic",
       "Dynamic hostname for IS-IS\n"
       "Dynamic hostname\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->dynhostname = 1;

  return CMD_SUCCESS;
}

DEFUN (no_dynamic_hostname,
       no_dynamic_hostname_cmd,
       "no hostname dynamic",
       NO_STR
       "Dynamic hostname for IS-IS\n"
       "Dynamic hostname\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->dynhostname = 0;

  return CMD_SUCCESS;
}

DEFUN (spf_interval,
       spf_interval_cmd,
       "spf-interval <1-120>",
       "Minimum interval between SPF calculations\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
  struct isis_area *area;
  u_int16_t interval;

  area = vty->index;
  interval = atoi (argv[0]);
  area->min_spf_interval[0] = interval;
  area->min_spf_interval[1] = interval;

  return CMD_SUCCESS;
}

DEFUN (no_spf_interval,
       no_spf_interval_cmd,
       "no spf-interval",
       NO_STR
       "Minimum interval between SPF calculations\n")
{
  struct isis_area *area;

  area = vty->index;

  area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
  area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_spf_interval,
       no_spf_interval_arg_cmd,
       "no spf-interval <1-120>",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Minimum interval between consecutive SPFs in seconds\n")

DEFUN (spf_interval_l1,
       spf_interval_l1_cmd,
       "spf-interval level-1 <1-120>",
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
  struct isis_area *area;
  u_int16_t interval;

  area = vty->index;
  interval = atoi (argv[0]);
  area->min_spf_interval[0] = interval;

  return CMD_SUCCESS;
}

DEFUN (no_spf_interval_l1,
       no_spf_interval_l1_cmd,
       "no spf-interval level-1",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n")
{
  struct isis_area *area;

  area = vty->index;

  area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_spf_interval,
       no_spf_interval_l1_arg_cmd,
       "no spf-interval level-1 <1-120>",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")

DEFUN (spf_interval_l2,
       spf_interval_l2_cmd,
       "spf-interval level-2 <1-120>",
       "Minimum interval between SPF calculations\n"
       "Set interval for level 2 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
  struct isis_area *area;
  u_int16_t interval;

  area = vty->index;
  interval = atoi (argv[0]);
  area->min_spf_interval[1] = interval;

  return CMD_SUCCESS;
}

DEFUN (no_spf_interval_l2,
       no_spf_interval_l2_cmd,
       "no spf-interval level-2",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 2 only\n")
{
  struct isis_area *area;

  area = vty->index;

  area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_spf_interval,
       no_spf_interval_l2_arg_cmd,
       "no spf-interval level-2 <1-120>",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 2 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")

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
  struct isis_area *area;

  area = vty->index;
  assert (area);

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
      lsp_regenerate_schedule (area);
    }

  return CMD_SUCCESS;
}

DEFUN (show_isis_generated_topology,
       show_isis_generated_topology_cmd,
       "show isis generated-topologies",
       SHOW_STR
       "CLNS network information\n"
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
  struct isis_area *area;
  u_char buff[ISIS_SYS_ID_LEN];

  area = vty->index;
  assert (area);

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
  struct isis_area *area;

  area = vty->index;
  assert (area);

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
  struct isis_area *area;

  area = vty->index;
  assert (area);

  /* I hope that it's enough. */
  area->topology_basedynh = strndup (argv[0], 16); 
  return CMD_SUCCESS;
}
#endif /* TOPOLOGY_GENERATE */

DEFUN (lsp_lifetime,
       lsp_lifetime_cmd,
       "lsp-lifetime <380-65535>",
       "Maximum LSP lifetime\n"
       "LSP lifetime in seconds\n")
{
  struct isis_area *area;
  uint16_t interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);

  if (interval < ISIS_MIN_LSP_LIFETIME)
    {
      vty_out (vty, "LSP lifetime (%us) below %us%s",
	       interval, ISIS_MIN_LSP_LIFETIME, VTY_NEWLINE);

      return CMD_WARNING;
    }


  area->max_lsp_lifetime[0] = interval;
  area->max_lsp_lifetime[1] = interval;
  area->lsp_refresh[0] = interval - 300;
  area->lsp_refresh[1] = interval - 300;

  if (area->t_lsp_refresh[0])
    {
      thread_cancel (area->t_lsp_refresh[0]);
      thread_execute (master, lsp_refresh_l1, area, 0);
    }

  if (area->t_lsp_refresh[1])
    {
      thread_cancel (area->t_lsp_refresh[1]);
      thread_execute (master, lsp_refresh_l2, area, 0);
    }


  return CMD_SUCCESS;
}

DEFUN (no_lsp_lifetime,
       no_lsp_lifetime_cmd,
       "no lsp-lifetime",
       NO_STR
       "LSP lifetime in seconds\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->max_lsp_lifetime[0] = MAX_AGE;	/* 1200s */
  area->max_lsp_lifetime[1] = MAX_AGE;	/* 1200s */
  area->lsp_refresh[0] = MAX_LSP_GEN_INTERVAL;	/*  900s */
  area->lsp_refresh[1] = MAX_LSP_GEN_INTERVAL;	/*  900s */

  return CMD_SUCCESS;
}

ALIAS (no_lsp_lifetime,
       no_lsp_lifetime_arg_cmd,
       "no lsp-lifetime <380-65535>",
       NO_STR
       "Maximum LSP lifetime\n"
       "LSP lifetime in seconds\n")

DEFUN (lsp_lifetime_l1,
       lsp_lifetime_l1_cmd,
       "lsp-lifetime level-1 <380-65535>",
       "Maximum LSP lifetime for Level 1 only\n"
       "LSP lifetime for Level 1 only in seconds\n")
{
  struct isis_area *area;
  uint16_t interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);

  if (interval < ISIS_MIN_LSP_LIFETIME)
    {
      vty_out (vty, "Level-1 LSP lifetime (%us) below %us%s",
	       interval, ISIS_MIN_LSP_LIFETIME, VTY_NEWLINE);

      return CMD_WARNING;
    }


  area->max_lsp_lifetime[0] = interval;
  area->lsp_refresh[0] = interval - 300;

  return CMD_SUCCESS;
}

DEFUN (no_lsp_lifetime_l1,
       no_lsp_lifetime_l1_cmd,
       "no lsp-lifetime level-1",
       NO_STR
       "LSP lifetime for Level 1 only in seconds\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->max_lsp_lifetime[0] = MAX_AGE;	/* 1200s */
  area->lsp_refresh[0] = MAX_LSP_GEN_INTERVAL;	/*  900s */

  return CMD_SUCCESS;
}

ALIAS (no_lsp_lifetime_l1,
       no_lsp_lifetime_l1_arg_cmd,
       "no lsp-lifetime level-1 <380-65535>",
       NO_STR
       "Maximum LSP lifetime for Level 1 only\n"
       "LSP lifetime for Level 1 only in seconds\n")

DEFUN (lsp_lifetime_l2,
       lsp_lifetime_l2_cmd,
       "lsp-lifetime level-2 <380-65535>",
       "Maximum LSP lifetime for Level 2 only\n"
       "LSP lifetime for Level 2 only in seconds\n")
{
  struct isis_area *area;
  uint16_t interval;

  area = vty->index;
  assert (area);

  interval = atoi (argv[0]);

  if (interval < ISIS_MIN_LSP_LIFETIME)
    {
      vty_out (vty, "Level-2 LSP lifetime (%us) below %us%s",
	       interval, ISIS_MIN_LSP_LIFETIME, VTY_NEWLINE);

      return CMD_WARNING;
    }

  area->max_lsp_lifetime[1] = interval;
  area->lsp_refresh[1] = interval - 300;

  return CMD_SUCCESS;
}

DEFUN (no_lsp_lifetime_l2,
       no_lsp_lifetime_l2_cmd,
       "no lsp-lifetime level-2",
       NO_STR
       "LSP lifetime for Level 2 only in seconds\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);

  area->max_lsp_lifetime[1] = MAX_AGE;	/* 1200s */
  area->lsp_refresh[1] = MAX_LSP_GEN_INTERVAL;	/*  900s */

  return CMD_SUCCESS;
}

ALIAS (no_lsp_lifetime_l2,
       no_lsp_lifetime_l2_arg_cmd,
       "no lsp-lifetime level-2 <380-65535>",
       NO_STR
       "Maximum LSP lifetime for Level 2 only\n"
       "LSP lifetime for Level 2 only in seconds\n")

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

	/* ISIS - Area is-type (level-1-2 is default) */
	if (area->is_type == IS_LEVEL_1)
	  {
	    vty_out (vty, " is-type level-1%s", VTY_NEWLINE);
	    write++;
	  }
	else
	  {
	    if (area->is_type == IS_LEVEL_2)
	      {
		vty_out (vty, " is-type level-2-only%s", VTY_NEWLINE);
		write++;
	      }
	  }
	/* ISIS - Lsp generation interval */
	if (area->lsp_gen_interval[0] == area->lsp_gen_interval[1])
	  {
	    if (area->lsp_gen_interval[0] != LSP_GEN_INTERVAL_DEFAULT)
	      {
		vty_out (vty, " lsp-gen-interval %d%s",
			 area->lsp_gen_interval[0], VTY_NEWLINE);
		write++;
	      }
	  }
	else
	  {
	    if (area->lsp_gen_interval[0] != LSP_GEN_INTERVAL_DEFAULT)
	      {
		vty_out (vty, " lsp-gen-interval level-1 %d%s",
			 area->lsp_gen_interval[0], VTY_NEWLINE);
		write++;
	      }
	    if (area->lsp_gen_interval[1] != LSP_GEN_INTERVAL_DEFAULT)
	      {
		vty_out (vty, " lsp-gen-interval level-2 %d%s",
			 area->lsp_gen_interval[1], VTY_NEWLINE);
		write++;
	      }
	  }
	/* ISIS - LSP lifetime */
	if (area->max_lsp_lifetime[0] == area->max_lsp_lifetime[1])
	  {
	    if (area->max_lsp_lifetime[0] != MAX_AGE)
	      {
		vty_out (vty, " lsp-lifetime %u%s", area->max_lsp_lifetime[0],
			 VTY_NEWLINE);
		write++;
	      }
	  }
	else
	  {
	    if (area->max_lsp_lifetime[0] != MAX_AGE)
	      {
		vty_out (vty, " lsp-lifetime level-1 %u%s",
			 area->max_lsp_lifetime[0], VTY_NEWLINE);
		write++;
	      }
	    if (area->max_lsp_lifetime[1] != MAX_AGE)
	      {
		vty_out (vty, " lsp-lifetime level-2 %u%s",
			 area->max_lsp_lifetime[1], VTY_NEWLINE);
		write++;
	      }
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
	if (area->area_passwd.len > 0)
	  {
	    vty_out(vty, " area-password %s", area->area_passwd.passwd);
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
	if (area->domain_passwd.len > 0)
	  {
	    vty_out(vty, " domain-password %s", area->domain_passwd.passwd);
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

#ifdef TOPOLOGY_GENERATE
	if (memcmp (area->topology_baseis, DEFAULT_TOPOLOGY_BASEIS,
		    ISIS_SYS_ID_LEN))
	  {
	    vty_out (vty, " topology base-is %s%s",
		     sysid_print (area->topology_baseis), VTY_NEWLINE);
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
    }

  return write;
}

static struct cmd_node isis_node = {
  ISIS_NODE,
  "%s(config-router)# ",
  1
};

void
isis_init ()
{
  /* Install IS-IS top node */
  install_node (&isis_node, isis_config_write);

  install_element (VIEW_NODE, &show_clns_neighbors_cmd);
  install_element (VIEW_NODE, &show_isis_neighbors_cmd);
  install_element (VIEW_NODE, &show_clns_neighbors_detail_cmd);
  install_element (VIEW_NODE, &show_isis_neighbors_detail_cmd);

  install_element (VIEW_NODE, &show_hostname_cmd);
  install_element (VIEW_NODE, &show_database_cmd);
  install_element (VIEW_NODE, &show_database_detail_cmd);

  install_element (ENABLE_NODE, &show_clns_neighbors_cmd);
  install_element (ENABLE_NODE, &show_isis_neighbors_cmd);
  install_element (ENABLE_NODE, &show_clns_neighbors_detail_cmd);
  install_element (ENABLE_NODE, &show_isis_neighbors_detail_cmd);

  install_element (ENABLE_NODE, &show_hostname_cmd);
  install_element (ENABLE_NODE, &show_database_cmd);
  install_element (ENABLE_NODE, &show_database_detail_cmd);
  install_element (ENABLE_NODE, &show_debugging_cmd);

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

  install_element (CONFIG_NODE, &router_isis_cmd);
  install_element (CONFIG_NODE, &no_router_isis_cmd);

  install_default (ISIS_NODE);

  install_element (ISIS_NODE, &net_cmd);
  install_element (ISIS_NODE, &no_net_cmd);

  install_element (ISIS_NODE, &is_type_cmd);
  install_element (ISIS_NODE, &no_is_type_cmd);

  install_element (ISIS_NODE, &area_passwd_cmd);
  install_element (ISIS_NODE, &area_passwd_snpauth_cmd);
  install_element (ISIS_NODE, &no_area_passwd_cmd);

  install_element (ISIS_NODE, &domain_passwd_cmd);
  install_element (ISIS_NODE, &domain_passwd_snpauth_cmd);
  install_element (ISIS_NODE, &no_domain_passwd_cmd);

  install_element (ISIS_NODE, &lsp_gen_interval_cmd);
  install_element (ISIS_NODE, &no_lsp_gen_interval_cmd);
  install_element (ISIS_NODE, &no_lsp_gen_interval_arg_cmd);
  install_element (ISIS_NODE, &lsp_gen_interval_l1_cmd);
  install_element (ISIS_NODE, &no_lsp_gen_interval_l1_cmd);
  install_element (ISIS_NODE, &no_lsp_gen_interval_l1_arg_cmd);
  install_element (ISIS_NODE, &lsp_gen_interval_l2_cmd);
  install_element (ISIS_NODE, &no_lsp_gen_interval_l2_cmd);
  install_element (ISIS_NODE, &no_lsp_gen_interval_l2_arg_cmd);

  install_element (ISIS_NODE, &spf_interval_cmd);
  install_element (ISIS_NODE, &no_spf_interval_cmd);
  install_element (ISIS_NODE, &no_spf_interval_arg_cmd);
  install_element (ISIS_NODE, &spf_interval_l1_cmd);
  install_element (ISIS_NODE, &no_spf_interval_l1_cmd);
  install_element (ISIS_NODE, &no_spf_interval_l1_arg_cmd);
  install_element (ISIS_NODE, &spf_interval_l2_cmd);
  install_element (ISIS_NODE, &no_spf_interval_l2_cmd);
  install_element (ISIS_NODE, &no_spf_interval_l2_arg_cmd);

  install_element (ISIS_NODE, &lsp_lifetime_cmd);
  install_element (ISIS_NODE, &no_lsp_lifetime_cmd);
  install_element (ISIS_NODE, &no_lsp_lifetime_arg_cmd);
  install_element (ISIS_NODE, &lsp_lifetime_l1_cmd);
  install_element (ISIS_NODE, &no_lsp_lifetime_l1_cmd);
  install_element (ISIS_NODE, &no_lsp_lifetime_l1_arg_cmd);
  install_element (ISIS_NODE, &lsp_lifetime_l2_cmd);
  install_element (ISIS_NODE, &no_lsp_lifetime_l2_cmd);
  install_element (ISIS_NODE, &no_lsp_lifetime_l2_arg_cmd);

  install_element (ISIS_NODE, &dynamic_hostname_cmd);
  install_element (ISIS_NODE, &no_dynamic_hostname_cmd);

  install_element (ISIS_NODE, &metric_style_cmd);
  install_element (ISIS_NODE, &no_metric_style_cmd);
#ifdef TOPOLOGY_GENERATE
  install_element (ISIS_NODE, &topology_generate_grid_cmd);
  install_element (ISIS_NODE, &topology_baseis_cmd);
  install_element (ISIS_NODE, &topology_basedynh_cmd);
  install_element (ISIS_NODE, &no_topology_baseis_cmd);
  install_element (ISIS_NODE, &no_topology_baseis_noid_cmd);
  install_element (VIEW_NODE, &show_isis_generated_topology_cmd);
  install_element (ENABLE_NODE, &show_isis_generated_topology_cmd);
#endif /* TOPOLOGY_GENERATE */

  isis_new (0);
  isis_circuit_init ();
  isis_zebra_init ();
  isis_spf_cmds_init ();
}
