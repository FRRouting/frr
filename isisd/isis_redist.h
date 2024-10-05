// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_redist.h
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
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
	uint16_t table;
};

struct isis_redist_table_present_args {
	/* from filter.h, struct acl_dup_args */
	const char *rtda_ip;
	const char *rtda_level;
	const char *rtda_table;
	bool rtda_found;
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
		     uint32_t metric, route_tag_t tag, uint16_t instance);
void isis_redist_delete(struct isis *isis, int type, struct prefix *p,
			struct prefix_ipv6 *src_p, uint16_t tableid);
int isis_redist_config_write(struct vty *vty, struct isis_area *area,
			     int family);
void isis_redist_init(void);
void isis_redist_area_finish(struct isis_area *area);

void isis_redist_set(struct isis_area *area, int level, int family, int type,
		     uint32_t metric, const char *routemap, int originate_type,
		     uint16_t table);
void isis_redist_unset(struct isis_area *area, int level, int family, int type,
		       uint16_t table);

void isis_redist_free(struct isis *isis);

bool isis_redist_table_is_present(const struct vty *vty,
				  struct isis_redist_table_present_args *rtda);
uint16_t isis_redist_table_get_first(const struct vty *vty,
				     struct isis_redist_table_present_args *rtda);
#endif
