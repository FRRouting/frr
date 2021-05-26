/*
 * IS-IS Rout(e)ing protocol - isis_redist.h
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
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

#ifndef ISIS_REDIST_H
#define ISIS_REDIST_H

#define REDIST_PROTOCOL_COUNT 2

#define DEFAULT_ROUTE ZEBRA_ROUTE_MAX
#define DEFAULT_ORIGINATE 1
#define DEFAULT_ORIGINATE_ALWAYS 2

struct isis_ext_info {
	int origin;
	uint32_t metric;
	uint8_t distance;
	route_tag_t tag;
};

struct isis_redist {
	int redist;
	uint32_t metric;
	char *map_name;
	struct route_map *map;
};

struct isis;
struct isis_area;
struct prefix;
struct prefix_ipv6;
struct vty;

afi_t afi_for_redist_protocol(int protocol);

struct route_table *get_ext_reach(struct isis_area *area, int family,
				  int level);
void isis_redist_add(struct isis *isis, int type, struct prefix *p,
		     struct prefix_ipv6 *src_p, uint8_t distance,
		     uint32_t metric, route_tag_t tag);
void isis_redist_delete(struct isis *isis, int type, struct prefix *p,
			struct prefix_ipv6 *src_p);
int isis_redist_config_write(struct vty *vty, struct isis_area *area,
			     int family);
void isis_redist_init(void);
void isis_redist_area_finish(struct isis_area *area);

void isis_redist_set(struct isis_area *area, int level, int family, int type,
		     uint32_t metric, const char *routemap, int originate_type);
void isis_redist_unset(struct isis_area *area, int level, int family, int type);

void isis_redist_free(struct isis *isis);
#endif
