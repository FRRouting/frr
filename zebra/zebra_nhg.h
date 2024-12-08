// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra Nexthop Group header.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *                    Stephen Worley
 */
#ifndef __ZEBRA_NHG_H__
#define __ZEBRA_NHG_H__

#include "lib/nexthop.h"
#include "lib/nexthop_group.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This struct is used exclusively for dataplane
 * interaction via a dataplane context.
 *
 * It is designed to mimic the netlink nexthop_grp
 * struct in include/linux/nexthop.h
 */
struct nh_grp {
	uint32_t id;
	uint8_t weight;
};

PREDECL_RBTREE_UNIQ(nhg_connected_tree);

/*
 * Hashtables containing nhg entries is in `zebra_router`.
 */
struct nhg_hash_entry {
	uint32_t id;
	afi_t afi;
	vrf_id_t vrf_id;

	/* Time since last update */
	time_t uptime;

	/* Source protocol - zebra or another daemon */
	int type;

	/* zapi instance and session id, for groups from other daemons */
	uint16_t zapi_instance;
	uint32_t zapi_session;

	struct nexthop_group nhg;

	/* If supported, a mapping of backup nexthops. */
	struct nhg_backup_info *backup_info;

	/* If this is not a group, it
	 * will be a single nexthop
	 * and must have an interface
	 * associated with it.
	 * Otherwise, this will be null.
	 */
	struct interface *ifp;

	uint32_t refcnt;
	uint32_t dplane_ref;

	uint32_t flags;

	/* Dependency trees for other entries.
	 * For instance a group with two
	 * nexthops will have two dependencies
	 * pointing to those nhg_hash_entries.
	 *
	 * Using a rb tree here to make lookups
	 * faster with ID's.
	 *
	 * nhg_depends the RB tree of entries that this
	 * group contains.
	 *
	 * nhg_dependents the RB tree of entries that
	 * this group is being used by
	 *
	 * NHG id 3 with nexthops id 1/2
	 * nhg(3)->nhg_depends has 1 and 2 in the tree
	 * nhg(3)->nhg_dependents is empty
	 *
	 * nhg(1)->nhg_depends is empty
	 * nhg(1)->nhg_dependents is 3 in the tree
	 *
	 * nhg(2)->nhg_depends is empty
	 * nhg(2)->nhg_dependents is 3 in the tree
	 */
	struct nhg_connected_tree_head nhg_depends, nhg_dependents;
	struct nhg_hash_entry *pic_nhe;
	struct event *timer;

/*
 * Is this nexthop group valid, ie all nexthops are fully resolved.
 * What is fully resolved?  It's a nexthop that is either self contained
 * and correct( ie no recursive pointer ) or a nexthop that is recursively
 * resolved and correct.
 */
#define NEXTHOP_GROUP_VALID (1 << 0)
/*
 * Has this nexthop group been installed?  At this point in time, this
 * means that the data-plane has been told about this nexthop group
 * and it's possible usage by a route entry.
 */
#define NEXTHOP_GROUP_INSTALLED (1 << 1)
/*
 * Has the nexthop group been queued to be send to the FIB?
 * The NEXTHOP_GROUP_VALID flag should also be set by this point.
 */
#define NEXTHOP_GROUP_QUEUED (1 << 2)
/*
 * Is this a nexthop that is recursively resolved?
 */
#define NEXTHOP_GROUP_RECURSIVE (1 << 3)

/*
 * Backup nexthop support - identify groups that are backups for
 * another group.
 */
#define NEXTHOP_GROUP_BACKUP (1 << 4)

/*
 * The NHG has been release by an upper level protocol via the
 * `zebra_nhg_proto_del()` API.
 *
 * We use this flag to track this state in case the NHG is still being used
 * by routes therefore holding their refcnts as well. Otherwise, the NHG will
 * be removed and uninstalled.
 *
 */
#define NEXTHOP_GROUP_PROTO_RELEASED (1 << 5)

/*
 * When deleting a NHG notice that it is still installed
 * and if it is, slightly delay the actual removal to
 * the future.  So that upper level protocols might
 * be able to take advantage of some NHG's that
 * are there
 */
#define NEXTHOP_GROUP_KEEP_AROUND (1 << 6)

/*
 * Track FPM installation status..
 */
#define NEXTHOP_GROUP_FPM (1 << 7)

/*
 * When an interface comes up install the
 * singleton's and schedule the NHG's that
 * are using this nhg to be reinstalled
 * when installation is successful.
 */
#define NEXTHOP_GROUP_REINSTALL (1 << 8)

/*
 * Connected routes and kernel routes received
 * from the kernel or created by Zebra do no
 * need to be installed.  For connected, this
 * is because the routes are in the local table
 * but not imported and we create an amalgram
 * route for it.  For kernel routes if the route
 * is an pre-nhg route, there is no nexthop associated
 * with it and we should not create it until it
 * is used by something else.
 * The reason for this is because is that this just
 * fills up the DPlane's nexthop slots when there
 * are a bunch of interfaces or pre-existing routes
 * As such let's not initially install it ( but
 * pretend it was successful ) and if another route
 * chooses this NHG then we can install it then.
 */
#define NEXTHOP_GROUP_INITIAL_DELAY_INSTALL (1 << 9)
#define NEXTHOP_GROUP_PIC_NHT		    (1 << 10)
};

/* Upper 4 bits of the NHG are reserved for indicating the NHG type */
#define NHG_ID_TYPE_POS 28
enum nhg_type {
	NHG_TYPE_L3 = 0,
	NHG_TYPE_L2_NH, /* NHs in a L2 NHG used as a MAC/FDB dest */
	NHG_TYPE_L2,    /* L2 NHG used as a MAC/FDB dest */
};

/* Was this one we created, either this session or previously? */
#define ZEBRA_NHG_CREATED(NHE)                                                 \
	(((NHE->type) <= ZEBRA_ROUTE_MAX) && (NHE->type != ZEBRA_ROUTE_KERNEL))

/* Is this an NHE owned by zebra and not an upper level protocol? */
#define ZEBRA_OWNED(NHE) (NHE->type == ZEBRA_ROUTE_NHG)

#define PROTO_OWNED(NHE) (NHE->id >= ZEBRA_NHG_PROTO_LOWER)

/*
 * Backup nexthops: this is a group object itself, so
 * that the backup nexthops can use the same code as a normal object.
 */
struct nhg_backup_info {
	struct nhg_hash_entry *nhe;
};

enum nhg_ctx_op_e {
	NHG_CTX_OP_NONE = 0,
	NHG_CTX_OP_NEW,
	NHG_CTX_OP_DEL,
};

enum nhg_ctx_status {
	NHG_CTX_NONE = 0,
	NHG_CTX_QUEUED,
	NHG_CTX_REQUEUED,
	NHG_CTX_SUCCESS,
	NHG_CTX_FAILURE,
};

/*
 * Context needed to queue nhg updates on the
 * work queue.
 */
struct nhg_ctx {

	/* Unique ID */
	uint32_t id;

	vrf_id_t vrf_id;
	afi_t afi;

	/*
	 * This should only ever be ZEBRA_ROUTE_NHG unless we get a a kernel
	 * created nexthop not made by us.
	 */
	int type;

	/* If its a group array, how many? */
	uint16_t count;

	/* Its either a single nexthop or an array of ID's */
	union {
		struct nexthop nh;
		struct nh_grp grp[MULTIPATH_NUM];
	} u;

	struct nhg_resilience resilience;
	enum nhg_ctx_op_e op;
	enum nhg_ctx_status status;
};

/* Global control to disable use of kernel nexthops, if available. We can't
 * force the kernel to support nexthop ids, of course, but we can disable
 * zebra's use of them, for testing e.g. By default, if the kernel supports
 * nexthop ids, zebra uses them.
 */
void zebra_nhg_enable_kernel_nexthops(bool set);
bool zebra_nhg_kernel_nexthops_enabled(void);

/* Global control for zebra to only use proto-owned nexthops */
void zebra_nhg_set_proto_nexthops_only(bool set);
bool zebra_nhg_proto_nexthops_only(void);

/* Global control for use of activated backups for recursive resolution. */
void zebra_nhg_set_recursive_use_backups(bool set);
bool zebra_nhg_recursive_use_backups(void);

/**
 * NHE abstracted tree functions.
 * Use these where possible instead of direct access.
 */
struct nhg_hash_entry *zebra_nhg_alloc(void);
void zebra_nhg_free(struct nhg_hash_entry *nhe);
/* In order to clear a generic hash, we need a generic api, sigh. */
void zebra_nhg_hash_free(void *p);
void zebra_nhg_hash_free_zero_id(struct hash_bucket *b, void *arg);

/* Init an nhe, for use in a hash lookup for example. There's some fuzziness
 * if the nhe represents only a single nexthop, so we try to capture that
 * variant also.
 */
void zebra_nhe_init(struct nhg_hash_entry *nhe, afi_t afi,
		    const struct nexthop *nh);

/*
 * Shallow copy of 'orig', into new/allocated nhe.
 */
struct nhg_hash_entry *zebra_nhe_copy(const struct nhg_hash_entry *orig,
				      uint32_t id);

/* Allocate, free backup nexthop info objects */
struct nhg_backup_info *zebra_nhg_backup_alloc(void);
void zebra_nhg_backup_free(struct nhg_backup_info **p);

struct nexthop_group *zebra_nhg_get_backup_nhg(struct nhg_hash_entry *nhe);

extern struct nhg_hash_entry *zebra_nhg_resolve(struct nhg_hash_entry *nhe);

extern unsigned int zebra_nhg_depends_count(const struct nhg_hash_entry *nhe);
extern bool zebra_nhg_depends_is_empty(const struct nhg_hash_entry *nhe);

extern unsigned int
zebra_nhg_dependents_count(const struct nhg_hash_entry *nhe);
extern bool zebra_nhg_dependents_is_empty(const struct nhg_hash_entry *nhe);

/* Lookup ID, doesn't create */
extern struct nhg_hash_entry *zebra_nhg_lookup_id(uint32_t id);

/* Hash functions */
extern uint32_t zebra_nhg_hash_key(const void *arg);
extern uint32_t zebra_nhg_id_key(const void *arg);

extern bool zebra_nhg_hash_equal(const void *arg1, const void *arg2);
extern bool zebra_nhg_hash_id_equal(const void *arg1, const void *arg2);

/*
 * Process a context off of a queue.
 * Specifically this should be from
 * the rib meta queue.
 */
extern int nhg_ctx_process(struct nhg_ctx *ctx);
void nhg_ctx_free(struct nhg_ctx **ctx);

/* Find via kernel nh creation */
extern int zebra_nhg_kernel_find(uint32_t id, struct nexthop *nh, struct nh_grp *grp,
				 uint16_t count, vrf_id_t vrf_id, afi_t afi, int type, int startup,
				 struct nhg_resilience *resilience);
/* Del via kernel */
extern int zebra_nhg_kernel_del(uint32_t id, vrf_id_t vrf_id);

/* Find an nhe based on a nexthop_group */
extern struct nhg_hash_entry *zebra_nhg_rib_find(uint32_t id, struct nexthop_group *nhg,
						 afi_t rt_afi, int type, bool pic);

/* Find an nhe based on a route's nhe, used during route creation */
struct nhg_hash_entry *
zebra_nhg_rib_find_nhe(struct nhg_hash_entry *rt_nhe, afi_t rt_afi);
extern bool zebra_pic_nhe_find(struct nhg_hash_entry **pic_nhe, /* return value */
			       struct nhg_hash_entry *nhe, afi_t afi, bool from_dplane);


/**
 * Functions for Add/Del/Replace via protocol NHG creation.
 *
 * The NHEs will not be hashed. They will only be present in the
 * ID table and therefore not sharable.
 *
 * It is the owning protocols job to manage these.
 */

/*
 * Add NHE. If already exists, Replace.
 *
 * Returns allocated NHE on success, otherwise NULL.
 */
struct nhg_hash_entry *zebra_nhg_proto_add(uint32_t id, int type,
					   uint16_t instance, uint32_t session,
					   struct nexthop_group *nhg,
					   afi_t afi);

/*
 * Del NHE.
 *
 * Returns deleted NHE on success, otherwise NULL.
 *
 * Caller must decrement ref with zebra_nhg_decrement_ref() when done.
 */
struct nhg_hash_entry *zebra_nhg_proto_del(uint32_t id, int type);

/*
 * Remove specific by proto NHGs.
 *
 * Called after client disconnect.
 *
 */
unsigned long zebra_nhg_score_proto(int type);

/* Reference counter functions */
extern void zebra_nhg_decrement_ref(struct nhg_hash_entry *nhe);
extern void zebra_nhg_increment_ref(struct nhg_hash_entry *nhe);

/* Check validity of nhe, if invalid will update dependents as well */
extern void zebra_nhg_check_valid(struct nhg_hash_entry *nhe);

/* Convert nhe depends to a grp context that can be passed around safely */
extern uint16_t zebra_nhg_nhe2grp(struct nh_grp *grp, struct nhg_hash_entry *nhe, int size);

/* Dataplane install/uninstall */
extern void zebra_nhg_install_kernel(struct nhg_hash_entry *nhe, uint8_t type);
extern void zebra_nhg_uninstall_kernel(struct nhg_hash_entry *nhe);
extern void zebra_interface_nhg_reinstall(struct interface *ifp);

/* Forward ref of dplane update context type */
struct zebra_dplane_ctx;
extern void zebra_nhg_dplane_result(struct zebra_dplane_ctx *ctx);


/* Sweep the nhg hash tables for old entries on restart */
extern void zebra_nhg_sweep_table(struct hash *hash);

/*
 * We are shutting down but the nexthops should be kept
 * as that -r has been specified and we don't want to delete
 * the routes unintentionally
 */
extern void zebra_nhg_mark_keep(void);

/* Nexthop resolution processing */
struct route_entry; /* Forward ref to avoid circular includes */
extern int nexthop_active_update(struct route_node *rn, struct route_entry *re,
				 struct route_entry *old_re);

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pNG" (const struct nhg_hash_entry *)
#endif

#ifdef __cplusplus
}
#endif

#endif	/* __ZEBRA_NHG_H__ */
