/*
 * IS-IS Rout(e)ing protocol - isis_dynhn.h
 *                             Dynamic hostname cache
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef _ZEBRA_ISIS_DYNHN_H
#define _ZEBRA_ISIS_DYNHN_H

struct isis_dynhn {
	uint8_t id[ISIS_SYS_ID_LEN];
	char hostname[256];
	time_t refresh;
	int level;
};

void dyn_cache_init(struct isis *isis);
void dyn_cache_finish(struct isis *isis);
void isis_dynhn_insert(struct isis *isis, const uint8_t *id,
		       const char *hostname, int level);
void isis_dynhn_remove(struct isis *isis, const uint8_t *id);
struct isis_dynhn *dynhn_find_by_id(struct isis *isis, const uint8_t *id);
struct isis_dynhn *dynhn_find_by_name(struct isis *isis, const char *hostname);
void dynhn_print_all(struct vty *vty, struct isis *isis);

/* Snmp support */
struct isis_dynhn *dynhn_snmp_next(struct isis *isis, const uint8_t *id,
				   int level);

#endif /* _ZEBRA_ISIS_DYNHN_H */
