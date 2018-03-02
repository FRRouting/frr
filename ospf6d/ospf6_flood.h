/*
 * Copyright (C) 2003 Yasuhiro Ohara
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef OSPF6_FLOOD_H
#define OSPF6_FLOOD_H

/* Debug option */
extern unsigned char conf_debug_ospf6_flooding;
#define OSPF6_DEBUG_FLOODING_ON() (conf_debug_ospf6_flooding = 1)
#define OSPF6_DEBUG_FLOODING_OFF() (conf_debug_ospf6_flooding = 0)
#define IS_OSPF6_DEBUG_FLOODING (conf_debug_ospf6_flooding)

/* Function Prototypes */
extern struct ospf6_lsdb *ospf6_get_scoped_lsdb(struct ospf6_lsa *lsa);
extern struct ospf6_lsdb *ospf6_get_scoped_lsdb_self(struct ospf6_lsa *lsa);

/* origination & purging */
extern void ospf6_lsa_originate(struct ospf6_lsa *lsa);
extern void ospf6_lsa_originate_process(struct ospf6_lsa *lsa,
					struct ospf6 *process);
extern void ospf6_lsa_originate_area(struct ospf6_lsa *lsa,
				     struct ospf6_area *oa);
extern void ospf6_lsa_originate_interface(struct ospf6_lsa *lsa,
					  struct ospf6_interface *oi);
extern void ospf6_lsa_purge(struct ospf6_lsa *lsa);

extern void ospf6_lsa_purge_multi_ls_id(struct ospf6_area *oa,
					struct ospf6_lsa *lsa);

/* access method to retrans_count */
extern void ospf6_increment_retrans_count(struct ospf6_lsa *lsa);
extern void ospf6_decrement_retrans_count(struct ospf6_lsa *lsa);

/* flooding & clear flooding */
extern void ospf6_flood_clear(struct ospf6_lsa *lsa);
extern void ospf6_flood(struct ospf6_neighbor *from, struct ospf6_lsa *lsa);
extern void ospf6_flood_area(struct ospf6_neighbor *from, struct ospf6_lsa *lsa,
			     struct ospf6_area *oa);

/* receive & install */
extern void ospf6_receive_lsa(struct ospf6_neighbor *from,
			      struct ospf6_lsa_header *header);
extern void ospf6_install_lsa(struct ospf6_lsa *lsa);

extern int config_write_ospf6_debug_flood(struct vty *vty);
extern void install_element_ospf6_debug_flood(void);
extern void ospf6_flood_interface(struct ospf6_neighbor *from,
				  struct ospf6_lsa *lsa,
				  struct ospf6_interface *oi);
extern int ospf6_lsupdate_send_neighbor_now(struct ospf6_neighbor *on,
					    struct ospf6_lsa *lsa);

#endif /* OSPF6_FLOOD_H */
