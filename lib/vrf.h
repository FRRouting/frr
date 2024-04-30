// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRF related header.
 * Copyright (C) 2014 6WIND S.A.
 */

#ifndef _ZEBRA_VRF_H
#define _ZEBRA_VRF_H

#include "openbsd-tree.h"
#include "linklist.h"
#include "qobj.h"
#include "vty.h"
#include "ns.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The default VRF ID */
#define VRF_UNKNOWN UINT32_MAX

/* Pending: May need to refine this. */
#ifndef IFLA_VRF_MAX
enum { IFLA_VRF_UNSPEC, IFLA_VRF_TABLE, __IFLA_VRF_MAX };

#define IFLA_VRF_MAX (__IFLA_VRF_MAX - 1)
#endif

#define VRF_NAMSIZ      36
#define NS_NAMSIZ 36

/*
 * The command strings
 */
#define VRF_CMD_HELP_STR    "Specify the VRF\nThe VRF name\n"
#define VRF_ALL_CMD_HELP_STR    "Specify the VRF\nAll VRFs\n"
#define VRF_FULL_CMD_HELP_STR   "Specify the VRF\nThe VRF name\nAll VRFs\n"

#define FRR_VRF_XPATH "/frr-vrf:lib/vrf"
#define FRR_VRF_KEY_XPATH "/frr-vrf:lib/vrf[name='%s']"

/*
 * Pass some OS specific data up through
 * to the daemons
 */
struct vrf_data {
	union {
		struct {
			uint32_t table_id;
			char netns_name[NS_NAMSIZ];
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
	uint8_t status;
#define VRF_ACTIVE     (1 << 0) /* VRF is up in kernel */
#define VRF_CONFIGURED (1 << 1) /* VRF has some FRR configuration */

	/* Interfaces belonging to this VRF */
	struct if_name_head ifaces_by_name;
	struct if_index_head ifaces_by_index;

	/* User data */
	void *info;

	/* The table_id from the kernel */
	struct vrf_data data;

	/* Back pointer to namespace context */
	void *ns_ctxt;

	QOBJ_FIELDS;
};
RB_HEAD(vrf_id_head, vrf);
RB_PROTOTYPE(vrf_id_head, vrf, id_entry, vrf_id_compare)
RB_HEAD(vrf_name_head, vrf);
RB_PROTOTYPE(vrf_name_head, vrf, name_entry, vrf_name_compare)
DECLARE_QOBJ_TYPE(vrf);

/* Allow VRF with netns as backend */
enum vrf_backend_type {
	VRF_BACKEND_VRF_LITE,
	VRF_BACKEND_NETNS,
	VRF_BACKEND_UNKNOWN,
	VRF_BACKEND_MAX,
};

extern struct vrf_id_head vrfs_by_id;
extern struct vrf_name_head vrfs_by_name;

extern struct vrf *vrf_lookup_by_id(vrf_id_t);
extern struct vrf *vrf_lookup_by_name(const char *);
extern struct vrf *vrf_get(vrf_id_t, const char *);
extern struct vrf *vrf_update(vrf_id_t new_vrf_id, const char *name);
extern const char *vrf_id_to_name(vrf_id_t vrf_id);

#define VRF_LOGNAME(V) V ? V->name : "Unknown"

#define VRF_GET_ID(V, NAME, USE_JSON)                                          \
	do {                                                                   \
		struct vrf *_vrf;                                              \
		if (!(_vrf = vrf_lookup_by_name(NAME))) {                      \
			if (USE_JSON) {                                        \
				vty_out(vty, "{}\n");                          \
			} else {                                               \
				vty_out(vty, "%% VRF %s not found\n", NAME);   \
			}                                                      \
			return CMD_WARNING;                                    \
		}                                                              \
		if (_vrf->vrf_id == VRF_UNKNOWN) {                             \
			if (USE_JSON) {                                        \
				vty_out(vty, "{}\n");                          \
			} else {                                               \
				vty_out(vty, "%% VRF %s not active\n", NAME);  \
			}                                                      \
			return CMD_WARNING;                                    \
		}                                                              \
		(V) = _vrf->vrf_id;                                            \
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

static inline uint32_t vrf_interface_count(struct vrf *vrf)
{
	uint32_t count = 0;
	struct interface *ifp;

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		/* skip the l3mdev */
		if (strncmp(ifp->name, vrf->name, VRF_NAMSIZ) == 0)
			continue;
		count++;
	}
	return count;
}

/*
 * Utilities to obtain the user data
 */

/* Look up the data pointer of the specified VRF. */
extern void *vrf_info_lookup(vrf_id_t);

/*
 * VRF bit-map: maintaining flags, one bit per VRF ID
 */
typedef void *vrf_bitmap_t;
#define VRF_BITMAP_NULL     NULL

extern void vrf_bitmap_init(vrf_bitmap_t *pbmap);
extern void vrf_bitmap_free(vrf_bitmap_t *pbmap);
extern void vrf_bitmap_set(vrf_bitmap_t *pbmap, vrf_id_t vrf_id);
extern void vrf_bitmap_unset(vrf_bitmap_t *pbmap, vrf_id_t vrf_id);
extern int vrf_bitmap_check(vrf_bitmap_t *pbmap, vrf_id_t vrf_id);

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
extern void vrf_init(int (*create)(struct vrf *vrf),
		     int (*enable)(struct vrf *vrf),
		     int (*disable)(struct vrf *vrf),
		     int (*destroy)(struct vrf *vrf));

/*
 * Iterate over custom VRFs and round up by processing the default VRF.
 */
typedef void (*vrf_iter_func)(struct vrf *vrf);
extern void vrf_iterate(vrf_iter_func fnc);

/*
 * Call vrf_terminate when the protocol is being shutdown
 */
extern void vrf_terminate(void);

/*
 * Utilities to create networks objects,
 * or call network operations
 */

/*
 * Create a new socket associated with a VRF.
 *
 * This is a wrapper that ensures correct behavior when using namespace VRFs.
 * In the namespace case, the socket is created within the namespace. In the
 * non-namespace case, this is equivalent to socket().
 *
 * If name is provided, this is provided to vrf_bind() to bind the socket to
 * the VRF. This is only relevant when using VRF-lite.
 *
 * Summary:
 * - Namespace: pass vrf_id but not name
 * - VRF-lite: pass vrf_id and name of VRF device to bind to
 * - VRF-lite, no binding: pass vrf_id but not name, or just use socket()
 */
extern int vrf_socket(int domain, int type, int protocol, vrf_id_t vrf_id,
		      const char *name);

extern int vrf_sockunion_socket(const union sockunion *su, vrf_id_t vrf_id,
				const char *name);

/*
 * Binds a socket to an interface (ifname) in a VRF (vrf_id).
 *
 * If ifname is NULL or is equal to the VRF name then bind to a VRF device.
 * Otherwise, bind to the specified interface in the specified VRF.
 *
 * Returns 0 on success and -1 on failure.
 */
extern int vrf_bind(vrf_id_t vrf_id, int fd, const char *ifname);

/* VRF ioctl operations */
extern int vrf_getaddrinfo(const char *node, const char *service,
			   const struct addrinfo *hints, struct addrinfo **res,
			   vrf_id_t vrf_id);

extern int vrf_ioctl(vrf_id_t vrf_id, int d, unsigned long request, char *args);

/* The default VRF ID */
#define VRF_DEFAULT 0

/* Must be called only during startup, before config is read */
extern void vrf_set_default_name(const char *default_name);

extern const char *vrf_get_default_name(void);
#define VRF_DEFAULT_NAME    vrf_get_default_name()

/* VRF switch from NETNS */
extern int vrf_switch_to_netns(vrf_id_t vrf_id);
extern int vrf_switchback_to_initial(void);

/*
 * VRF backend routines
 * should be called from zebra only
 */

/* VRF vty command initialisation
 */
extern void vrf_cmd_init(int (*writefunc)(struct vty *vty));

/* VRF vty debugging
 */
extern void vrf_install_commands(void);

/*
 * VRF utilities
 */

/*
 * API for configuring VRF backend
 */
extern int vrf_configure_backend(enum vrf_backend_type backend);
extern int vrf_get_backend(void);
extern int vrf_is_backend_netns(void);

/* used internally to enable or disable VRF.
 * Notify a change in the VRF ID of the VRF
 */
extern void vrf_disable(struct vrf *vrf);
extern int vrf_enable(struct vrf *vrf);
extern void vrf_delete(struct vrf *vrf);

extern const struct frr_yang_module_info frr_vrf_info;
extern const struct frr_yang_module_info frr_vrf_cli_info;

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_VRF_H*/
