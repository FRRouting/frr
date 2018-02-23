/*
 * VRF related header.
 * Copyright (C) 2014 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _ZEBRA_VRF_H
#define _ZEBRA_VRF_H

#include "openbsd-tree.h"
#include "linklist.h"
#include "qobj.h"
#include "vty.h"

/* The default NS ID */
#define NS_DEFAULT 0

/* The default VRF ID */
#define VRF_DEFAULT 0
#define VRF_UNKNOWN UINT32_MAX

/* Pending: May need to refine this. */
#ifndef IFLA_VRF_MAX
enum { IFLA_VRF_UNSPEC, IFLA_VRF_TABLE, __IFLA_VRF_MAX };

#define IFLA_VRF_MAX (__IFLA_VRF_MAX - 1)
#endif

#define VRF_NAMSIZ      36

#define VRF_DEFAULT_NAME    "Default-IP-Routing-Table"

/*
 * The command strings
 */
#define VRF_CMD_HELP_STR    "Specify the VRF\nThe VRF name\n"
#define VRF_ALL_CMD_HELP_STR    "Specify the VRF\nAll VRFs\n"
#define VRF_FULL_CMD_HELP_STR   "Specify the VRF\nThe VRF name\nAll VRFs\n"

/*
 * Pass some OS specific data up through
 * to the daemons
 */
struct vrf_data {
	union {
		struct {
			uint32_t table_id;
		} l;
	};
};

struct vrf {
	RB_ENTRY(vrf) id_entry, name_entry;

	/* Identifier, same as the vector index */
	vrf_id_t vrf_id;

	/* Name */
	char name[VRF_NAMSIZ + 1];

	/* Zebra internal VRF status */
	u_char status;
#define VRF_ACTIVE     (1 << 0) /* VRF is up in kernel */
#define VRF_CONFIGURED (1 << 1) /* VRF has some FRR configuration */

	/* Interfaces belonging to this VRF */
	struct if_name_head ifaces_by_name;
	struct if_index_head ifaces_by_index;

	/* User data */
	void *info;

	/* The table_id from the kernel */
	struct vrf_data data;

	QOBJ_FIELDS
};
RB_HEAD(vrf_id_head, vrf);
RB_PROTOTYPE(vrf_id_head, vrf, id_entry, vrf_id_compare)
RB_HEAD(vrf_name_head, vrf);
RB_PROTOTYPE(vrf_name_head, vrf, name_entry, vrf_name_compare)
DECLARE_QOBJ_TYPE(vrf)


extern struct vrf_id_head vrfs_by_id;
extern struct vrf_name_head vrfs_by_name;

extern struct vrf *vrf_lookup_by_id(vrf_id_t);
extern struct vrf *vrf_lookup_by_name(const char *);
extern struct vrf *vrf_get(vrf_id_t, const char *);
extern const char *vrf_id_to_name(vrf_id_t vrf_id);
extern vrf_id_t vrf_name_to_id(const char *);

#define VRF_GET_ID(V, NAME)                                                    \
	do {                                                                   \
		struct vrf *vrf;                                               \
		if (!(vrf = vrf_lookup_by_name(NAME))) {                       \
			vty_out(vty, "%% VRF %s not found\n", NAME);           \
			return CMD_WARNING;                                    \
		}                                                              \
		if (vrf->vrf_id == VRF_UNKNOWN) {                              \
			vty_out(vty, "%% VRF %s not active\n", NAME);          \
			return CMD_WARNING;                                    \
		}                                                              \
		(V) = vrf->vrf_id;                                             \
	} while (0)

/*
 * Check whether the VRF is enabled.
 */
static inline int vrf_is_enabled(struct vrf *vrf)
{
	return vrf && CHECK_FLAG(vrf->status, VRF_ACTIVE);
}

/* check if the vrf is user configured */
static inline int vrf_is_user_cfged(struct vrf *vrf)
{
	return vrf && CHECK_FLAG(vrf->status, VRF_CONFIGURED);
}

/* Mark that VRF has user configuration */
static inline void vrf_set_user_cfged(struct vrf *vrf)
{
	SET_FLAG(vrf->status, VRF_CONFIGURED);
}

/* Mark that VRF no longer has any user configuration */
static inline void vrf_reset_user_cfged(struct vrf *vrf)
{
	UNSET_FLAG(vrf->status, VRF_CONFIGURED);
}

/*
 * Utilities to obtain the user data
 */

/* Get the data pointer of the specified VRF. If not found, create one. */
extern void *vrf_info_get(vrf_id_t);
/* Look up the data pointer of the specified VRF. */
extern void *vrf_info_lookup(vrf_id_t);

/*
 * VRF bit-map: maintaining flags, one bit per VRF ID
 */

typedef void *vrf_bitmap_t;
#define VRF_BITMAP_NULL     NULL

extern vrf_bitmap_t vrf_bitmap_init(void);
extern void vrf_bitmap_free(vrf_bitmap_t);
extern void vrf_bitmap_set(vrf_bitmap_t, vrf_id_t);
extern void vrf_bitmap_unset(vrf_bitmap_t, vrf_id_t);
extern int vrf_bitmap_check(vrf_bitmap_t, vrf_id_t);

/*
 * VRF initializer/destructor
 *
 * create -> Called back when a new VRF is created.  This
 *           can be either through these 3 options:
 *           1) CLI mentions a vrf before OS knows about it
 *           2) OS calls zebra and we create the vrf from OS
 *              callback
 *           3) zebra calls individual protocols to notify
 *              about the new vrf
 *
 * enable -> Called back when a VRF is actually usable from
 *           an OS perspective ( 2 and 3 above )
 *
 * disable -> Called back when a VRF is being deleted from
 *            the system ( 2 and 3 ) above
 *
 * delete -> Called back when a vrf is being deleted from
 *           the system ( 2 and 3 ) above.
 */
extern void vrf_init(int (*create)(struct vrf *), int (*enable)(struct vrf *),
		     int (*disable)(struct vrf *), int (*delete)(struct vrf *));
/*
 * Call vrf_terminate when the protocol is being shutdown
 */
extern void vrf_terminate(void);

extern void vrf_cmd_init(int (*writefunc)(struct vty *vty));

/*
 * VRF utilities
 */

/* Create a socket serving for the given VRF */
extern int vrf_socket(int, int, int, vrf_id_t);

/*
 * VRF Debugging
 */
extern void vrf_install_commands(void);
#endif /*_ZEBRA_VRF_H*/
