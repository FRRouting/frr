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

#ifndef OSPF_AREA_H
#define OSPF_AREA_H

#include "ospf6_top.h"
#include "lib/json.h"

struct ospf6_area {
	/* Reference to Top data structure */
	struct ospf6 *ospf6;

	/* Area-ID */
	in_addr_t area_id;

#define OSPF6_AREA_FMT_UNSET      0
#define OSPF6_AREA_FMT_DOTTEDQUAD 1
#define OSPF6_AREA_FMT_DECIMAL    2
	/* Area-ID string */
	char name[16];

	/* flag */
	uint8_t flag;

	/* OSPF Option */
	uint8_t options[3];

	/* Summary routes to be originated (includes Configured Address Ranges)
	 */
	struct ospf6_route_table *range_table;
	struct ospf6_route_table *nssa_range_table;
	struct ospf6_route_table *summary_prefix;
	struct ospf6_route_table *summary_router;

	/* Area type */
	int no_summary;

	/* NSSA default-information-originate */
	struct {
		bool enabled;
		int metric_type;
		int metric_value;
	} nssa_default_originate;

	/* Brouter traversal protection */
	bool intra_brouter_calc;

	/* OSPF interface list */
	struct list *if_list;

	struct ospf6_lsdb *lsdb;
	struct ospf6_lsdb *lsdb_self;
	struct ospf6_lsdb *temp_router_lsa_lsdb;

	struct ospf6_route_table *spf_table;
	struct ospf6_route_table *route_table;

	uint32_t spf_calculation; /* SPF calculation count */

	struct thread *thread_router_lsa;
	struct thread *thread_intra_prefix_lsa;
	uint32_t router_lsa_size_limit;

	/* Area announce list */
	struct {
		char *name;
		struct access_list *list;
	} _export;
#define EXPORT_NAME(A)  (A)->_export.name
#define EXPORT_LIST(A)  (A)->_export.list

	/* Area acceptance list */
	struct {
		char *name;
		struct access_list *list;
	} import;
#define IMPORT_NAME(A)  (A)->import.name
#define IMPORT_LIST(A)  (A)->import.list

	/* Type 3 LSA Area prefix-list */
	struct {
		char *name;
		struct prefix_list *list;
	} plist_in;
#define PREFIX_NAME_IN(A)  (A)->plist_in.name
#define PREFIX_LIST_IN(A)  (A)->plist_in.list

	struct {
		char *name;
		struct prefix_list *list;
	} plist_out;
#define PREFIX_NAME_OUT(A)  (A)->plist_out.name
#define PREFIX_LIST_OUT(A)  (A)->plist_out.list

	/* Time stamps. */
	struct timeval ts_spf; /* SPF calculation time stamp. */

	uint32_t full_nbrs; /* Fully adjacent neighbors. */
	uint8_t intra_prefix_originate; /* Force intra_prefix lsa originate */
	uint8_t NSSATranslatorRole;	/* NSSA configured role */
#define OSPF6_NSSA_ROLE_NEVER     0
#define OSPF6_NSSA_ROLE_CANDIDATE 1
#define OSPF6_NSSA_ROLE_ALWAYS    2
	uint8_t NSSATranslatorState; /* NSSA operational role */
#define OSPF6_NSSA_TRANSLATE_DISABLED 0
#define OSPF6_NSSA_TRANSLATE_ENABLED  1
};

#define OSPF6_AREA_ENABLE     0x01
#define OSPF6_AREA_ACTIVE     0x02
#define OSPF6_AREA_TRANSIT    0x04 /* TransitCapability */
#define OSPF6_AREA_STUB       0x08
#define OSPF6_AREA_NSSA       0x10

#define IS_AREA_ENABLED(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_ENABLE))
#define IS_AREA_ACTIVE(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_ACTIVE))
#define IS_AREA_TRANSIT(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_TRANSIT))
#define IS_AREA_STUB(oa) (CHECK_FLAG ((oa)->flag, OSPF6_AREA_STUB))
#define IS_AREA_NSSA(oa) (CHECK_FLAG((oa)->flag, OSPF6_AREA_NSSA))

#define OSPF6_CMD_AREA_GET(str, oa, ospf6)                                     \
	{                                                                      \
		uint32_t area_id;                                              \
		int format, ret;                                               \
		ret = str2area_id(str, &area_id, &format);                     \
		if (ret) {                                                     \
			vty_out(vty, "Malformed Area-ID: %s\n", str);          \
			return CMD_WARNING;                                    \
		}                                                              \
		oa = ospf6_area_lookup(area_id, ospf6);                        \
		if (oa == NULL)                                                \
			oa = ospf6_area_create(area_id, ospf6, format);        \
	}

/* prototypes */
extern int str2area_id(const char *str, uint32_t *area_id, int *area_id_fmt);
extern void area_id2str(char *buf, int len, uint32_t area_id, int area_id_fmt);

extern int ospf6_area_cmp(void *va, void *vb);

extern struct ospf6_area *ospf6_area_create(uint32_t area_id,
					    struct ospf6 *ospf6, int df);
extern void ospf6_area_delete(struct ospf6_area *oa);
extern struct ospf6_area *ospf6_area_lookup(uint32_t area_id,
					    struct ospf6 *ospf6);
extern struct ospf6_area *ospf6_area_lookup_by_area_id(uint32_t area_id);

extern void ospf6_area_stub_unset(struct ospf6 *ospf6, struct ospf6_area *area);
extern void ospf6_area_enable(struct ospf6_area *oa);
extern void ospf6_area_disable(struct ospf6_area *oa);

extern void ospf6_area_show(struct vty *vty, struct ospf6_area *oa,
			    json_object *json_areas, bool use_json);

extern void ospf6_plist_update(struct prefix_list *plist);
extern void ospf6_filter_update(struct access_list *access);
extern void ospf6_area_config_write(struct vty *vty, struct ospf6 *ospf6);
extern void ospf6_area_init(void);
struct ospf6_interface;
extern void ospf6_area_interface_delete(struct ospf6_interface *oi);

#endif /* OSPF_AREA_H */
